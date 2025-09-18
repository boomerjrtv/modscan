#!/usr/bin/env python3
"""
Enhanced Vulnerability Scanner Integration
Integrates all new components: knowledge base, AI planner, deterministic verifiers, attack graph, telemetry
"""

import asyncio
import aiohttp
import logging
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
import json
from urllib.parse import urlparse, urljoin

# Import all new components
from knowledge_base import get_relevant_docs, KnowledgeDoc
from ai_planner import generate_test_plan, TestPlan, PlanAction
from deterministic_verifiers import verify_xss, verify_sqli, verify_ssrf, verify_open_redirect, Evidence
from attack_graph import find_exploit_chains, suggest_next_attacks, AttackPath
from telemetry import log_scan_attempt, store_artifact, track_operation, get_session_stats

# Import existing components
from asset_manager import VulnerabilityFinding

logger = logging.getLogger(__name__)

@dataclass
class EnhancedScanResult:
    """Enhanced scan result with chain analysis and evidence artifacts"""
    target_url: str
    vulnerabilities: List[VulnerabilityFinding]
    evidence_artifacts: List[str]  # Artifact IDs
    attack_chains: List[AttackPath]
    confidence_scores: Dict[str, float]
    scan_duration: float
    total_requests: int
    knowledge_docs_used: List[str]
    next_recommended_actions: List[Tuple[str, float]]

class EnhancedVulnerabilityScanner:
    """
    Next-generation vulnerability scanner that combines:
    - Deterministic verification for precision
    - AI planning for intelligent targeting  
    - Knowledge base for real-world payloads
    - Attack graph for exploit chaining
    - Comprehensive telemetry and artifacts
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.session_timeout = aiohttp.ClientTimeout(total=30)
        
        # Track current capabilities for chaining
        self.verified_capabilities: List[str] = []
        self.target_context: Dict[str, Any] = {}
        
        logger.info("Enhanced vulnerability scanner initialized")
    
    async def scan_target(self, target_url: str, tech_stack: List[str] = None,
                         vulnerability_classes: List[str] = None) -> EnhancedScanResult:
        """
        Perform comprehensive vulnerability scan with AI planning and chaining.
        
        Args:
            target_url: Target URL to scan
            tech_stack: Known technology stack ['php', 'mysql', etc.]
            vulnerability_classes: Specific vuln types to focus on
            
        Returns:
            EnhancedScanResult with findings and recommendations
        """
        scan_start_time = time.time()
        
        with track_operation("enhanced_vulnerability_scan", target_url) as tracker:
            try:
                # Phase 1: Build target fingerprint and generate test plan
                fingerprint = await self._build_target_fingerprint(target_url, tech_stack)
                test_plan = await self._generate_intelligent_plan(fingerprint, vulnerability_classes)
                
                if not test_plan:
                    tracker.set_error("Failed to generate test plan")
                    return self._empty_scan_result(target_url)
                
                # Phase 2: Execute test plan with deterministic verification
                vulnerabilities = []
                artifacts = []
                total_requests = 0
                
                async with aiohttp.ClientSession(timeout=self.session_timeout) as session:
                    for action in test_plan.actions:
                        vuln, artifact_ids, requests_made = await self._execute_plan_action(
                            action, session, fingerprint
                        )
                        
                        if vuln:
                            vulnerabilities.append(vuln)
                            self._update_verified_capabilities(action.vuln_class)
                        
                        artifacts.extend(artifact_ids)
                        total_requests += requests_made
                        
                        # Add small delay to avoid overwhelming target
                        await asyncio.sleep(0.1)
                
                # Phase 3: Analyze attack chains and suggest next actions
                attack_chains = self._analyze_attack_chains()
                next_actions = self._suggest_next_actions()
                
                # Phase 4: Build comprehensive result
                scan_duration = time.time() - scan_start_time
                
                result = EnhancedScanResult(
                    target_url=target_url,
                    vulnerabilities=vulnerabilities,
                    evidence_artifacts=artifacts,
                    attack_chains=attack_chains,
                    confidence_scores=self._calculate_confidence_scores(vulnerabilities),
                    scan_duration=scan_duration,
                    total_requests=total_requests,
                    knowledge_docs_used=[doc.id for doc in test_plan.actions[0].source_docs if hasattr(test_plan.actions[0], 'source_docs')],
                    next_recommended_actions=next_actions
                )
                
                tracker.set_result(f"Found {len(vulnerabilities)} vulnerabilities", success=len(vulnerabilities) > 0)
                tracker.add_evidence(*[v.vuln_type for v in vulnerabilities])
                
                return result
                
            except Exception as e:
                logger.error(f"Enhanced scan failed: {e}")
                tracker.set_error(str(e))
                return self._empty_scan_result(target_url)
    
    async def _build_target_fingerprint(self, target_url: str, tech_stack: List[str] = None) -> Dict[str, Any]:
        """Build comprehensive target fingerprint for AI planning"""
        
        fingerprint = {
            'base_url': target_url,
            'stack': tech_stack or [],
            'params': [],
            'headers': {},
            'forms': [],
            'endpoints': []
        }
        
        try:
            # Basic reconnaissance to discover parameters and forms
            async with aiohttp.ClientSession(timeout=self.session_timeout) as session:
                async with session.get(target_url) as response:
                    content = await response.text()
                    headers = dict(response.headers)
                    
                    fingerprint['headers'] = headers
                    
                    # Extract technology indicators from headers
                    tech_indicators = []
                    server_header = headers.get('Server', '').lower()
                    if 'apache' in server_header:
                        tech_indicators.append('apache')
                    if 'nginx' in server_header:
                        tech_indicators.append('nginx')
                    if 'php' in server_header or 'x-powered-by' in [k.lower() for k in headers.keys()]:
                        tech_indicators.append('php')
                    
                    fingerprint['stack'].extend(tech_indicators)
                    
                    # Basic parameter extraction from URL and forms
                    parsed_url = urlparse(target_url)
                    if parsed_url.query:
                        import urllib.parse
                        params = urllib.parse.parse_qs(parsed_url.query)
                        fingerprint['params'] = list(params.keys())
                    
                    # Store content for form analysis
                    if len(content) < 100000:  # Reasonable size limit
                        artifact = store_artifact(content, "html_response", {
                            "target": target_url,
                            "fingerprint_phase": True
                        })
                        if artifact:
                            fingerprint['content_artifact'] = artifact.id
        
        except Exception as e:
            logger.warning(f"Fingerprinting failed for {target_url}: {e}")
        
        # Update global target context
        self.target_context = fingerprint
        
        return fingerprint
    
    async def _generate_intelligent_plan(self, fingerprint: Dict[str, Any], 
                                       vulnerability_classes: List[str] = None) -> Optional[TestPlan]:
        """Generate AI-powered test plan using knowledge base"""
        
        try:
            # Use AI planner with fingerprint and knowledge base
            test_plan = await generate_test_plan(
                fingerprint=fingerprint,
                vuln_classes=vulnerability_classes,
                config=self.config
            )
            
            return test_plan
            
        except Exception as e:
            logger.error(f"Test plan generation failed: {e}")
            return None
    
    async def _execute_plan_action(self, action: PlanAction, session: aiohttp.ClientSession,
                                 fingerprint: Dict[str, Any]) -> Tuple[Optional[VulnerabilityFinding], List[str], int]:
        """
        Execute a single plan action with deterministic verification.
        
        Returns:
            (VulnerabilityFinding or None, artifact_ids, requests_made)
        """
        artifacts = []
        requests_made = 0
        
        # Build attempt logger
        attempt_logger = log_scan_attempt(
            target=action.endpoint,
            action_id=action.id,
            method=action.method,
            vulnerability_type=action.vuln_class
        ).with_source_docs(*action.source_docs)
        
        try:
            # Execute payloads with deterministic verification
            for payload in action.payloads[:5]:  # Limit to 5 payloads per action
                
                attempt_logger.with_payload(payload)
                evidence = None
                
                # Route to appropriate deterministic verifier
                if action.vuln_class.startswith('xss'):
                    evidence = await verify_xss(action.endpoint, action.param, payload, session)
                    
                elif action.vuln_class.startswith('sqli'):
                    evidence = await verify_sqli(action.endpoint, action.param, payload, session)
                    
                elif action.vuln_class == 'ssrf':
                    callback_url = self.config.get('callback_url')
                    evidence = await verify_ssrf(action.endpoint, action.param, callback_url, session)
                    
                elif action.vuln_class == 'open_redirect':
                    evidence = await verify_open_redirect(action.endpoint, action.param, session)
                
                requests_made += 1
                
                # If we found evidence, create vulnerability finding
                if evidence and evidence.confidence >= 0.7:  # High confidence threshold
                    
                    # Store evidence artifacts
                    if evidence.raw_data:
                        artifact = store_artifact(
                            evidence.raw_data,
                            f"{evidence.type}_evidence",
                            {
                                'action_id': action.id,
                                'payload': payload,
                                'confidence': evidence.confidence,
                                'vuln_type': action.vuln_class
                            }
                        )
                        if artifact:
                            artifacts.append(artifact.id)
                    
                    # Create vulnerability finding
                    vulnerability = VulnerabilityFinding(
                        url=action.endpoint,
                        vuln_type=action.vuln_class.upper().replace('.', '_'),
                        severity=self._map_confidence_to_severity(evidence.confidence),
                        confidence=evidence.confidence,
                        payload=payload,
                        evidence=evidence.details,
                        discovered_at=datetime.now(),
                        impact_description=f"{action.vuln_class} vulnerability confirmed with {evidence.confidence:.1%} confidence",
                        remediation=self._get_remediation_advice(action.vuln_class),
                        affected_parameter=action.param,
                        raw_request=f"{action.method} {action.endpoint}?{action.param}={payload}",
                        raw_response=evidence.raw_data[:1000] if evidence.raw_data else ""
                    )
                    
                    # Log successful attempt
                    attempt_logger.with_evidence(evidence.details) \
                        .with_response(confidence=evidence.confidence) \
                        .success(evidence.confidence) \
                        .commit()
                    
                    return vulnerability, artifacts, requests_made
                
                # Brief pause between payloads
                await asyncio.sleep(0.05)
            
            # No vulnerability found
            attempt_logger.failure("No evidence found with sufficient confidence").commit()
            return None, artifacts, requests_made
            
        except Exception as e:
            logger.error(f"Action execution failed for {action.id}: {e}")
            attempt_logger.failure(str(e)).commit()
            return None, artifacts, requests_made
    
    def _update_verified_capabilities(self, vuln_class: str):
        """Update verified capabilities for attack chaining"""
        capability_mapping = {
            'xss.reflected': 'xss_reflected',
            'xss.stored': 'xss_stored',
            'sqli.error_based': 'sqli_error_based',
            'sqli.boolean_blind': 'sqli_boolean_blind',
            'sqli.time_blind': 'sqli_time_blind',
            'ssrf': 'ssrf_external',
            'open_redirect': 'open_redirect',
            'idor': 'idor_horizontal'
        }
        
        capability = capability_mapping.get(vuln_class)
        if capability and capability not in self.verified_capabilities:
            self.verified_capabilities.append(capability)
            logger.info(f"Verified new capability: {capability}")
    
    def _analyze_attack_chains(self) -> List[AttackPath]:
        """Analyze possible attack chains from verified capabilities"""
        if not self.verified_capabilities:
            return []
        
        # Define high-value target capabilities
        target_capabilities = [
            'auth_bypass',
            'idor_vertical', 
            'sqli_error_based',
            'xss_stored',
            'ssrf_internal'
        ]
        
        # Find exploit chains
        attack_chains = find_exploit_chains(
            current_capabilities=self.verified_capabilities,
            target_capabilities=target_capabilities,
            context=self.target_context
        )
        
        return attack_chains[:5]  # Return top 5 chains
    
    def _suggest_next_actions(self) -> List[Tuple[str, float]]:
        """Suggest next actions based on current capabilities"""
        return suggest_next_attacks(
            current_capabilities=self.verified_capabilities,
            context=self.target_context
        )
    
    def _calculate_confidence_scores(self, vulnerabilities: List[VulnerabilityFinding]) -> Dict[str, float]:
        """Calculate confidence scores by vulnerability type"""
        scores = {}
        
        for vuln in vulnerabilities:
            vuln_type = vuln.vuln_type
            if vuln_type not in scores:
                scores[vuln_type] = []
            scores[vuln_type].append(vuln.confidence)
        
        # Return average confidence per type
        return {
            vuln_type: sum(confidences) / len(confidences)
            for vuln_type, confidences in scores.items()
        }
    
    def _map_confidence_to_severity(self, confidence: float) -> str:
        """Map confidence score to severity level"""
        if confidence >= 0.9:
            return "Critical"
        elif confidence >= 0.8:
            return "High"
        elif confidence >= 0.7:
            return "Medium"
        elif confidence >= 0.5:
            return "Low"
        else:
            return "Info"
    
    def _get_remediation_advice(self, vuln_class: str) -> str:
        """Get remediation advice for vulnerability type"""
        remediation_map = {
            'xss.reflected': 'Implement output encoding and input validation. Use Content Security Policy (CSP).',
            'xss.stored': 'Sanitize all user input before storage. Implement output encoding and CSP.',
            'sqli.error_based': 'Use parameterized queries or prepared statements. Validate input types.',
            'sqli.boolean_blind': 'Use parameterized queries. Implement proper error handling.',
            'sqli.time_blind': 'Use parameterized queries. Implement query timeouts.',
            'ssrf': 'Validate and whitelist allowed URLs. Use network segmentation.',
            'open_redirect': 'Validate redirect URLs against whitelist. Avoid user-controlled redirects.',
            'idor': 'Implement proper access controls and session management.'
        }
        
        return remediation_map.get(vuln_class, 'Implement proper input validation and security controls.')
    
    def _empty_scan_result(self, target_url: str) -> EnhancedScanResult:
        """Create empty scan result for error cases"""
        return EnhancedScanResult(
            target_url=target_url,
            vulnerabilities=[],
            evidence_artifacts=[],
            attack_chains=[],
            confidence_scores={},
            scan_duration=0.0,
            total_requests=0,
            knowledge_docs_used=[],
            next_recommended_actions=[]
        )
    
    async def scan_with_chaining(self, target_url: str, max_rounds: int = 3) -> EnhancedScanResult:
        """
        Perform multi-round scanning with attack chaining.
        Each round builds on the previous round's discoveries.
        """
        all_vulnerabilities = []
        all_artifacts = []
        all_chains = []
        total_requests = 0
        scan_start = time.time()
        
        for round_num in range(max_rounds):
            logger.info(f"Starting scan round {round_num + 1}/{max_rounds}")
            
            # Get suggestions for this round based on current capabilities
            if round_num == 0:
                # First round: comprehensive scan
                result = await self.scan_target(target_url)
            else:
                # Subsequent rounds: targeted based on attack graph
                next_actions = self._suggest_next_actions()
                if not next_actions:
                    logger.info("No more actions suggested, stopping scan")
                    break
                
                # Focus on top 3 suggested vulnerability classes
                focus_classes = [action[0] for action in next_actions[:3]]
                result = await self.scan_target(target_url, vulnerability_classes=focus_classes)
            
            # Accumulate results
            all_vulnerabilities.extend(result.vulnerabilities)
            all_artifacts.extend(result.evidence_artifacts)
            all_chains.extend(result.attack_chains)
            total_requests += result.total_requests
            
            # If no new vulnerabilities found, stop
            if not result.vulnerabilities:
                logger.info(f"No vulnerabilities found in round {round_num + 1}, stopping")
                break
        
        # Build final consolidated result
        return EnhancedScanResult(
            target_url=target_url,
            vulnerabilities=all_vulnerabilities,
            evidence_artifacts=all_artifacts,
            attack_chains=all_chains,
            confidence_scores=self._calculate_confidence_scores(all_vulnerabilities),
            scan_duration=time.time() - scan_start,
            total_requests=total_requests,
            knowledge_docs_used=[],
            next_recommended_actions=self._suggest_next_actions()
        )

# Enhanced scanner factory function
def create_enhanced_scanner(config: Dict[str, Any] = None) -> EnhancedVulnerabilityScanner:
    """Create an enhanced vulnerability scanner with full capabilities"""
    return EnhancedVulnerabilityScanner(config or {})

# Main API function for easy integration
async def enhanced_vulnerability_scan(target_url: str, 
                                    tech_stack: List[str] = None,
                                    vulnerability_classes: List[str] = None,
                                    config: Dict[str, Any] = None,
                                    enable_chaining: bool = True) -> EnhancedScanResult:
    """
    Perform enhanced vulnerability scan with all new capabilities.
    
    Args:
        target_url: Target URL to scan
        tech_stack: Known technology stack
        vulnerability_classes: Specific vulnerability types to focus on
        config: Configuration dict (API keys, etc.)
        enable_chaining: Whether to enable multi-round attack chaining
        
    Returns:
        EnhancedScanResult with comprehensive findings
    """
    scanner = create_enhanced_scanner(config)
    
    if enable_chaining:
        return await scanner.scan_with_chaining(target_url, max_rounds=3)
    else:
        return await scanner.scan_target(target_url, tech_stack, vulnerability_classes)

if __name__ == "__main__":
    # Test the enhanced scanner
    import asyncio
    logging.basicConfig(level=logging.INFO)
    
    async def test_enhanced_scanner():
        # Test configuration
        config = {
            'gemini_api_key': 'your_api_key_here',  # Would need real key
            'callback_url': 'https://webhook.site/unique-id'
        }
        
        # Run enhanced scan
        result = await enhanced_vulnerability_scan(
            target_url="http://192.168.1.42/dvwa/vulnerabilities/sqli/",
            tech_stack=["php", "mysql", "apache"],
            config=config,
            enable_chaining=True
        )
        
        # Print results
        print(f"\n=== Enhanced Scan Results for {result.target_url} ===")
        print(f"Scan Duration: {result.scan_duration:.2f} seconds")
        print(f"Total Requests: {result.total_requests}")
        print(f"Vulnerabilities Found: {len(result.vulnerabilities)}")
        
        for vuln in result.vulnerabilities:
            print(f"\n[{vuln.severity}] {vuln.vuln_type}")
            print(f"  Confidence: {vuln.confidence:.1%}")
            print(f"  Parameter: {vuln.affected_parameter}")
            print(f"  Payload: {vuln.payload}")
            print(f"  Evidence: {vuln.evidence}")
        
        print(f"\nAttack Chains Found: {len(result.attack_chains)}")
        for chain in result.attack_chains:
            print(f"  {' → '.join(chain.capabilities)} (success: {chain.success_probability:.1%})")
        
        print(f"\nNext Recommended Actions:")
        for action, priority in result.next_recommended_actions[:5]:
            print(f"  {action} (priority: {priority:.2f})")
        
        # Print session statistics
        stats = get_session_stats()
        print(f"\nSession Statistics:")
        print(f"  Success Rate: {stats['success_rate']:.1%}")
        print(f"  Average Response Time: {stats['average_response_time']:.1f}ms")
        print(f"  Artifacts Stored: {stats['artifacts_stored']}")
    
    # Uncomment to test (requires API key and target)
    # asyncio.run(test_enhanced_scanner())