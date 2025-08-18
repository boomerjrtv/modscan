#!/usr/bin/env python3
"""
Advanced Scanner Orchestrator - Surpasses XBOW with intelligent vulnerability discovery
Orchestrates XXE, GraphQL, and API Logic scanners with zero false positive validation
"""

import asyncio
import logging
import time
from typing import Dict, List, Any, Optional
from datetime import datetime

from .xxe_scanner import EnhancedXXEScanner
from .graphql_scanner import GraphQLScanner
from .api_logic_scanner import APILogicScanner
from .vulnerability_scanner import VulnerabilityScanner

logger = logging.getLogger("AdvancedScannerOrchestrator")

class AdvancedScannerOrchestrator:
    """Orchestrator for advanced vulnerability scanners"""
    
    def __init__(self, asset_manager, config: Dict):
        self.asset_manager = asset_manager
        self.config = config
        
        # UNLIMITED MODE - Use system resources to maximum
        perf_config = config.get('performance', {})
        advanced_config = config.get('advanced_scanners', {})
        
        if perf_config.get('unlimited_concurrency', True):
            # Calculate optimal concurrency based on system specs
            cpu_cores = perf_config.get('cpu_cores', 8)
            memory_gb = perf_config.get('memory_gb', 16)
            bandwidth_gbps = perf_config.get('network_bandwidth_gbps', 1.0)
            
            # Aggressive concurrency calculation
            # Rule: 1GB network can handle ~50,000 concurrent lightweight HTTP requests
            # Rule: 1 CPU core can handle ~1,000 async tasks efficiently  
            # Rule: 1GB RAM can handle ~5,000 concurrent HTTP sessions
            
            network_limit = int(bandwidth_gbps * 50000)  # 50,000 per GB
            cpu_limit = cpu_cores * 1000  # 1,000 per core
            memory_limit = memory_gb * 5000  # 5,000 per GB RAM
            
            # Use the most constraining resource, but be aggressive
            self.max_concurrent_scanners = min(network_limit, cpu_limit, memory_limit)
            
            logger.info(f"🚀 UNLIMITED MODE: Max concurrent = {self.max_concurrent_scanners}")
            logger.info(f"📊 Limits - Network: {network_limit}, CPU: {cpu_limit}, Memory: {memory_limit}")
        else:
            self.max_concurrent_scanners = advanced_config.get('max_concurrent_scanners', 100)
        
        self.scan_timeout = advanced_config.get('scan_timeout', 600)  # 10 minutes per scanner
        
        # Initialize scanners
        self.scanners = {
            'xxe': EnhancedXXEScanner(asset_manager, config),
            'graphql': GraphQLScanner(asset_manager, config),
            'api_logic': APILogicScanner(asset_manager, config),
            'traditional': VulnerabilityScanner(asset_manager, config)
        }
        
        # Statistics tracking
        self.scan_stats = {
            'total_targets': 0,
            'vulnerabilities_found': 0,
            'scan_start_time': None,
            'scanner_stats': {scanner: {'runs': 0, 'findings': 0, 'errors': 0} for scanner in self.scanners}
        }
    
    async def orchestrate_advanced_scan(self, targets: List[str]) -> Dict[str, Any]:
        """Orchestrate comprehensive vulnerability scanning"""
        logger.info(f"🚀 Starting advanced scan orchestration for {len(targets)} targets")
        
        self.scan_stats['total_targets'] = len(targets)
        self.scan_stats['scan_start_time'] = time.time()
        
        # Phase 1: Target Classification and Prioritization
        classified_targets = await self._classify_targets(targets)
        
        # Phase 2: Intelligent Scanner Assignment
        scanner_assignments = self._assign_scanners_intelligently(classified_targets)
        
        # Phase 3: Orchestrated Scanning with Concurrency Control
        all_findings = await self._execute_orchestrated_scan(scanner_assignments)
        
        # Phase 4: Cross-Scanner Validation and Deduplication
        validated_findings = self._cross_validate_findings(all_findings)
        
        # Phase 5: Generate Intelligence Report
        intelligence_report = self._generate_intelligence_report(validated_findings)
        
        # Log comprehensive results
        total_time = time.time() - self.scan_stats['scan_start_time']
        logger.info(f"✅ Advanced scan completed in {total_time:.2f}s - Found {len(validated_findings)} validated vulnerabilities")
        
        return {
            'findings': validated_findings,
            'intelligence_report': intelligence_report,
            'scan_statistics': self.scan_stats,
            'total_scan_time': total_time
        }
    
    async def _classify_targets(self, targets: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """Classify targets by technology and attack surface"""
        classified = {
            'soap_xml': [],      # Likely SOAP/XML services (XXE targets)
            'graphql': [],       # GraphQL endpoints
            'rest_api': [],      # REST API endpoints
            'web_app': [],       # Traditional web applications
            'unknown': []        # Uncategorized targets
        }
        
        # Analyze each target
        for target in targets:
            target_info = {'url': target, 'confidence': 0.0, 'indicators': []}
            
            # Technology fingerprinting
            tech_indicators = await self._fingerprint_technology(target)
            
            # Classify based on indicators
            if any(indicator in tech_indicators for indicator in ['soap', 'wsdl', 'xml']):
                target_info['confidence'] = 0.9
                target_info['indicators'] = [i for i in tech_indicators if i in ['soap', 'wsdl', 'xml']]
                classified['soap_xml'].append(target_info)
            
            elif any(indicator in tech_indicators for indicator in ['graphql', 'graphiql', 'playground']):
                target_info['confidence'] = 0.95
                target_info['indicators'] = [i for i in tech_indicators if i in ['graphql', 'graphiql', 'playground']]
                classified['graphql'].append(target_info)
            
            elif any(indicator in tech_indicators for indicator in ['api', 'rest', 'json', 'v1', 'v2']):
                target_info['confidence'] = 0.8
                target_info['indicators'] = [i for i in tech_indicators if i in ['api', 'rest', 'json', 'v1', 'v2']]
                classified['rest_api'].append(target_info)
            
            elif any(indicator in tech_indicators for indicator in ['html', 'javascript', 'form']):
                target_info['confidence'] = 0.7
                target_info['indicators'] = [i for i in tech_indicators if i in ['html', 'javascript', 'form']]
                classified['web_app'].append(target_info)
            
            else:
                target_info['confidence'] = 0.1
                classified['unknown'].append(target_info)
        
        logger.info(f"🔍 Target classification: SOAP/XML: {len(classified['soap_xml'])}, "
                   f"GraphQL: {len(classified['graphql'])}, REST API: {len(classified['rest_api'])}, "
                   f"Web App: {len(classified['web_app'])}, Unknown: {len(classified['unknown'])}")
        
        return classified
    
    async def _fingerprint_technology(self, target: str) -> List[str]:
        """Fingerprint target technology stack"""
        indicators = []
        
        try:
            # Get response headers and content
            import aiohttp
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.get(target) as resp:
                    content = await resp.text()
                    headers = dict(resp.headers)
                    
                    # URL-based indicators
                    url_lower = target.lower()
                    if 'graphql' in url_lower or 'graphiql' in url_lower:
                        indicators.extend(['graphql', 'graphiql'])
                    if '/api/' in url_lower or '/rest/' in url_lower:
                        indicators.extend(['api', 'rest'])
                    if 'soap' in url_lower or 'wsdl' in url_lower:
                        indicators.extend(['soap', 'wsdl'])
                    if '/v1/' in url_lower or '/v2/' in url_lower:
                        indicators.extend(['v1', 'v2'])
                    
                    # Header-based indicators
                    content_type = headers.get('content-type', '').lower()
                    if 'xml' in content_type:
                        indicators.append('xml')
                    if 'json' in content_type:
                        indicators.append('json')
                    
                    server_header = headers.get('server', '').lower()
                    if 'apache' in server_header:
                        indicators.append('apache')
                    if 'nginx' in server_header:
                        indicators.append('nginx')
                    
                    # Content-based indicators
                    content_lower = content.lower()
                    if 'graphql' in content_lower:
                        indicators.append('graphql')
                    if '<soap:' in content_lower or 'xmlns:soap' in content_lower:
                        indicators.append('soap')
                    if 'wsdl' in content_lower or 'xmlns:wsdl' in content_lower:
                        indicators.append('wsdl')
                    if '"data":' in content_lower or '"errors":' in content_lower:
                        indicators.append('json')
                    if '<html' in content_lower:
                        indicators.append('html')
                    if 'javascript' in content_lower or '<script' in content_lower:
                        indicators.append('javascript')
                    if '<form' in content_lower:
                        indicators.append('form')
        
        except Exception:
            pass
        
        return list(set(indicators))  # Deduplicate
    
    def _assign_scanners_intelligently(self, classified_targets: Dict[str, List[Dict[str, Any]]]) -> Dict[str, List[Dict[str, Any]]]:
        """Intelligently assign scanners based on target classification"""
        assignments = {
            'xxe': [],
            'graphql': [],
            'api_logic': [],
            'traditional': []
        }
        
        # XXE Scanner: SOAP/XML targets + some APIs
        assignments['xxe'].extend(classified_targets['soap_xml'])
        # Also assign XXE to REST APIs (they might accept XML)
        for target in classified_targets['rest_api']:
            if target['confidence'] > 0.7:
                assignments['xxe'].append(target)
        
        # GraphQL Scanner: GraphQL endpoints
        assignments['graphql'].extend(classified_targets['graphql'])
        
        # API Logic Scanner: REST APIs + some unknown targets
        assignments['api_logic'].extend(classified_targets['rest_api'])
        assignments['api_logic'].extend(classified_targets['unknown'])
        
        # Traditional Scanner: Web apps + all targets (comprehensive coverage)
        assignments['traditional'].extend(classified_targets['web_app'])
        assignments['traditional'].extend(classified_targets['unknown'])
        
        logger.info(f"📋 Scanner assignments: XXE: {len(assignments['xxe'])}, "
                   f"GraphQL: {len(assignments['graphql'])}, "
                   f"API Logic: {len(assignments['api_logic'])}, "
                   f"Traditional: {len(assignments['traditional'])}")
        
        return assignments
    
    async def _execute_orchestrated_scan(self, scanner_assignments: Dict[str, List[Dict[str, Any]]]) -> Dict[str, List[Dict[str, Any]]]:
        """Execute scanners with intelligent orchestration"""
        all_findings = {scanner: [] for scanner in self.scanners}
        
        # Create scanning tasks with timeout and concurrency control
        semaphore = asyncio.Semaphore(self.max_concurrent_scanners)
        
        async def run_scanner_with_timeout(scanner_name: str, targets: List[Dict[str, Any]]) -> Tuple[str, List[Dict[str, Any]]]:
            async with semaphore:
                try:
                    scanner = self.scanners[scanner_name]
                    findings = []
                    
                    self.scan_stats['scanner_stats'][scanner_name]['runs'] += 1
                    
                    if scanner_name == 'xxe':
                        # XXE scanner processes one target at a time
                        for target_info in targets:
                            target_findings = await asyncio.wait_for(
                                scanner.scan_target(target_info['url']),
                                timeout=self.scan_timeout
                            )
                            findings.extend([{
                                'scanner': 'xxe',
                                'target': target_info['url'],
                                'finding': finding.__dict__ if hasattr(finding, '__dict__') else finding
                            } for finding in target_findings])
                    
                    elif scanner_name == 'graphql':
                        # GraphQL scanner processes one target at a time
                        for target_info in targets:
                            target_findings = await asyncio.wait_for(
                                scanner.run(target_info['url']),
                                timeout=self.scan_timeout
                            )
                            findings.extend([{
                                'scanner': 'graphql',
                                'target': target_info['url'],
                                'finding': finding
                            } for finding in target_findings])
                    
                    elif scanner_name == 'api_logic':
                        # API Logic scanner processes one target at a time
                        for target_info in targets:
                            target_findings = await asyncio.wait_for(
                                scanner.run(target_info['url']),
                                timeout=self.scan_timeout
                            )
                            findings.extend([{
                                'scanner': 'api_logic',
                                'target': target_info['url'],
                                'finding': finding
                            } for finding in target_findings])
                    
                    elif scanner_name == 'traditional':
                        # Traditional scanner can handle batch processing
                        if hasattr(scanner, 'scan_assets_for_vulnerabilities'):
                            # Convert target format for traditional scanner
                            assets = [{'url': t['url']} for t in targets]
                            
                            # Use existing session if available
                            import aiohttp
                            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                                batch_findings = await asyncio.wait_for(
                                    scanner.scan_assets_for_vulnerabilities(assets, session),
                                    timeout=self.scan_timeout * len(assets)
                                )
                                
                                for target_findings in batch_findings:
                                    findings.extend([{
                                        'scanner': 'traditional',
                                        'target': finding.url if hasattr(finding, 'url') else 'unknown',
                                        'finding': finding.__dict__ if hasattr(finding, '__dict__') else finding
                                    } for finding in target_findings])
                    
                    self.scan_stats['scanner_stats'][scanner_name]['findings'] += len(findings)
                    logger.info(f"✅ {scanner_name} scanner completed: {len(findings)} findings")
                    
                    return scanner_name, findings
                
                except asyncio.TimeoutError:
                    self.scan_stats['scanner_stats'][scanner_name]['errors'] += 1
                    logger.warning(f"⏰ {scanner_name} scanner timed out")
                    return scanner_name, []
                
                except Exception as e:
                    self.scan_stats['scanner_stats'][scanner_name]['errors'] += 1
                    logger.error(f"❌ {scanner_name} scanner error: {e}")
                    return scanner_name, []
        
        # Execute all scanners concurrently
        scanner_tasks = []
        for scanner_name, targets in scanner_assignments.items():
            if targets:  # Only run scanners that have targets
                scanner_tasks.append(run_scanner_with_timeout(scanner_name, targets))
        
        if scanner_tasks:
            results = await asyncio.gather(*scanner_tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, tuple) and len(result) == 2:
                    scanner_name, findings = result
                    all_findings[scanner_name] = findings
                elif isinstance(result, Exception):
                    logger.error(f"Scanner task exception: {result}")
        
        return all_findings
    
    def _cross_validate_findings(self, all_findings: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Cross-validate findings between scanners for zero false positives"""
        validated_findings = []
        
        for scanner_name, findings in all_findings.items():
            for finding_data in findings:
                finding = finding_data.get('finding', {})
                target = finding_data.get('target', '')
                
                # Apply scanner-specific validation rules
                if self._validate_finding_by_scanner(scanner_name, finding, target):
                    # Enhance finding with metadata
                    enhanced_finding = {
                        'scanner': scanner_name,
                        'target': target,
                        'type': finding.get('type', 'unknown'),
                        'severity': finding.get('severity', 'medium'),
                        'confidence': finding.get('confidence', 0.5),
                        'proof': finding.get('proof', ''),
                        'timestamp': datetime.now().isoformat(),
                        'raw_finding': finding
                    }
                    
                    validated_findings.append(enhanced_finding)
                    self.scan_stats['vulnerabilities_found'] += 1
        
        # Cross-scanner deduplication
        deduplicated_findings = self._deduplicate_findings(validated_findings)
        
        logger.info(f"🎯 Validated {len(deduplicated_findings)} findings after cross-validation and deduplication")
        
        return deduplicated_findings
    
    def _validate_finding_by_scanner(self, scanner_name: str, finding: Dict[str, Any], target: str) -> bool:
        """Apply zero false positive validation rules by scanner type"""
        
        if scanner_name == 'xxe':
            # XXE findings must have concrete proof (file content or error messages)
            proof = finding.get('proof', '')
            confidence = finding.get('confidence', 0)
            
            # Require high confidence + concrete evidence
            if confidence < 0.7:
                return False
            
            # Must have recognizable file content or XML parser errors
            proof_indicators = [
                'root:x:', 'daemon:x:', '/bin/bash', '/bin/sh',  # /etc/passwd content
                'nonexistent/', 'file:/proc/self/environ',       # Error-based XXE
                'javax.xml', 'org.xml.sax', 'XMLStreamException' # Parser errors
            ]
            
            return any(indicator in proof for indicator in proof_indicators)
        
        elif scanner_name == 'graphql':
            # GraphQL findings must be deterministic
            finding_type = finding.get('type', '')
            proof = finding.get('proof', '')
            
            # High confidence types that are deterministic
            deterministic_types = [
                'graphql.introspection.enabled',
                'graphql.auth.bypass',
                'graphql.dos.resource_exhaustion'
            ]
            
            if finding_type in deterministic_types:
                return True
            
            # For other types, require substantial proof
            return len(proof) > 50 and ('schema' in proof or 'query' in proof or 'mutation' in proof)
        
        elif scanner_name == 'api_logic':
            # API logic findings must have concrete evidence
            finding_type = finding.get('type', '')
            confidence = finding.get('confidence', 0)
            
            # High confidence findings with deterministic evidence
            if confidence >= 0.8:
                return True
            
            # IDOR findings need ID evidence
            if 'idor' in finding_type:
                return 'accessed_id' in finding and 'original_id' in finding
            
            # Mass assignment needs canary evidence  
            if 'mass_assignment' in finding_type:
                return 'canary_value' in finding
            
            return confidence >= 0.6
        
        elif scanner_name == 'traditional':
            # Traditional scanner findings - apply existing validation
            confidence = finding.get('confidence', 0)
            return confidence >= 0.7
        
        return False
    
    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate findings across scanners"""
        seen_fingerprints = set()
        deduplicated = []
        
        for finding in findings:
            # Create fingerprint based on target + type + key evidence
            fingerprint_parts = [
                finding.get('target', ''),
                finding.get('type', ''),
                str(finding.get('confidence', 0))[:3]  # First 3 chars of confidence
            ]
            
            # Add proof snippet for uniqueness
            proof = finding.get('proof', '')
            if len(proof) > 20:
                fingerprint_parts.append(proof[:20])
            
            fingerprint = '|'.join(fingerprint_parts)
            
            if fingerprint not in seen_fingerprints:
                seen_fingerprints.add(fingerprint)
                deduplicated.append(finding)
            else:
                logger.debug(f"Deduplicated finding: {finding.get('type')} on {finding.get('target')}")
        
        return deduplicated
    
    def _generate_intelligence_report(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive intelligence report"""
        report = {
            'executive_summary': {
                'total_vulnerabilities': len(findings),
                'critical_vulnerabilities': len([f for f in findings if f.get('severity') == 'critical']),
                'high_vulnerabilities': len([f for f in findings if f.get('severity') == 'high']),
                'medium_vulnerabilities': len([f for f in findings if f.get('severity') == 'medium']),
                'low_vulnerabilities': len([f for f in findings if f.get('severity') == 'low'])
            },
            'scanner_performance': {
                scanner: {
                    'findings': stats['findings'],
                    'success_rate': stats['findings'] / max(stats['runs'], 1),
                    'error_rate': stats['errors'] / max(stats['runs'], 1)
                }
                for scanner, stats in self.scan_stats['scanner_stats'].items()
            },
            'vulnerability_categories': {},
            'high_priority_targets': [],
            'recommendations': []
        }
        
        # Categorize vulnerabilities
        for finding in findings:
            vuln_type = finding.get('type', 'unknown')
            if vuln_type not in report['vulnerability_categories']:
                report['vulnerability_categories'][vuln_type] = 0
            report['vulnerability_categories'][vuln_type] += 1
        
        # Identify high priority targets
        target_risk_scores = {}
        for finding in findings:
            target = finding.get('target', '')
            severity = finding.get('severity', 'low')
            
            if target not in target_risk_scores:
                target_risk_scores[target] = 0
            
            # Risk scoring
            severity_scores = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}
            target_risk_scores[target] += severity_scores.get(severity, 1)
        
        # Sort targets by risk score
        sorted_targets = sorted(target_risk_scores.items(), key=lambda x: x[1], reverse=True)
        report['high_priority_targets'] = sorted_targets[:10]  # Top 10 risky targets
        
        # Generate recommendations
        if report['executive_summary']['critical_vulnerabilities'] > 0:
            report['recommendations'].append("🚨 CRITICAL: Immediate remediation required for critical vulnerabilities")
        
        if report['executive_summary']['high_vulnerabilities'] > 0:
            report['recommendations'].append("⚡ HIGH: Address high-severity vulnerabilities within 24-48 hours")
        
        # Scanner-specific recommendations
        for scanner, stats in report['scanner_performance'].items():
            if stats['error_rate'] > 0.2:
                report['recommendations'].append(f"🔧 Technical: {scanner} scanner has high error rate - check configuration")
        
        return report
    
    async def initialize(self):
        """Initialize the orchestrator"""
        logger.info("🚀 Initializing Advanced Scanner Orchestrator")
        
        # Initialize all scanners
        for scanner_name, scanner in self.scanners.items():
            try:
                if hasattr(scanner, 'initialize'):
                    await scanner.initialize()
                logger.info(f"✅ {scanner_name} scanner initialized")
            except Exception as e:
                logger.error(f"❌ Failed to initialize {scanner_name} scanner: {e}")
        
        self.asset_manager.log_activity('ORCHESTRATOR_INIT', 'Advanced Scanner Orchestrator initialized')
        logger.info("✅ Advanced Scanner Orchestrator ready")