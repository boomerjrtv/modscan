#!/usr/bin/env python3
"""
Advanced Attack Orchestrator
Combines all our advanced features into a unified attack platform

Features:
- Evidence-based confidence scoring
- Turbo Intruder-style high-speed HTTP engine  
- Python attack scripting with templates
- Race condition detection
- Smart location-based deduplication
- Business logic vulnerability testing

This orchestrator demonstrates how to use all components together for maximum effectiveness.
"""

import asyncio
import logging
from typing import List, Dict, Any
from datetime import datetime

from .turbo_engine import TurboEngine, TurboRequest
from .attack_scripts import AttackScriptEngine, AttackResult
from .vulnerability_scanner import VulnerabilityScanner
from asset_manager import AssetManager, VulnerabilityFinding

logger = logging.getLogger("AdvancedAttackOrchestrator")

class AdvancedAttackOrchestrator:
    """Orchestrates advanced attack scenarios combining all our enhanced features"""
    
    def __init__(self, asset_manager: AssetManager, config: Dict[str, Any]):
        self.asset_manager = asset_manager
        self.config = config
        self.turbo_engine = None
        self.attack_script_engine = None
        self.vulnerability_scanner = None
        
        # Performance tracking
        self.attack_stats = {
            'total_vulnerabilities_found': 0,
            'high_confidence_findings': 0,
            'race_conditions_tested': 0,
            'scripts_executed': 0,
            'targets_processed': 0
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        # Initialize Turbo Engine with high performance settings
        self.turbo_engine = TurboEngine(
            max_connections=5000,  # Very high for bug bounty scale
            connection_pool_size=200
        )
        await self.turbo_engine.start()
        
        # Initialize attack script engine
        self.attack_script_engine = AttackScriptEngine(self.turbo_engine)
        
        # Initialize enhanced vulnerability scanner
        self.vulnerability_scanner = VulnerabilityScanner(self.asset_manager, self.config)
        
        # Add vulnerability callback to track findings
        self.attack_script_engine.add_vulnerability_callback(self._process_vulnerability_finding)
        
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.turbo_engine:
            await self.turbo_engine.stop()
        
        # Print final stats
        self._print_final_stats()
    
    async def _process_vulnerability_finding(self, finding: VulnerabilityFinding):
        """Process vulnerability findings from attack scripts"""
        self.attack_stats['total_vulnerabilities_found'] += 1
        
        # Check confidence tier
        confidence_tier = self.vulnerability_scanner.get_confidence_tier(finding.confidence)
        if confidence_tier == "HIGH":
            self.attack_stats['high_confidence_findings'] += 1
        
        # Store in database
        try:
            self.asset_manager.add_vulnerability_finding(finding, 0)  # Asset ID 0 for now
            logger.info(f"🔥 {confidence_tier} CONFIDENCE {finding.vuln_type}: {finding.payload}")
        except Exception as e:
            logger.error(f"Failed to store vulnerability: {e}")
    
    async def comprehensive_target_assessment(self, target_url: str) -> Dict[str, Any]:
        """Perform comprehensive assessment of a single target using all advanced features"""
        logger.info(f"🎯 Starting comprehensive assessment of: {target_url}")
        
        results = {
            'target_url': target_url,
            'vulnerabilities_found': [],
            'attack_results': [],
            'race_conditions_tested': 0,
            'confidence_distribution': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'PROBE': 0}
        }
        
        # Phase 1: Standard vulnerability scanning with smart deduplication
        logger.info("📊 Phase 1: Enhanced vulnerability scanning")
        asset = {'url': target_url, 'tech_stack': '', 'status_code': 200}
        
        async with aiohttp.ClientSession() as session:
            semaphore = asyncio.Semaphore(50)  # High concurrency
            standard_findings = await self.vulnerability_scanner._scan_single_asset_enhanced(
                asset, session, semaphore
            )
            
            results['vulnerabilities_found'].extend(standard_findings)
        
        # Phase 2: Attack script execution
        logger.info("⚡ Phase 2: Attack script execution")
        
        script_targets = [
            ('csrf_chain', {'form_data': {'username': 'test', 'password': 'test'}}),
            ('param_fuzzing', {'max_payloads': 50}),  # Limited for demo
            ('upload_bypass', {})
        ]
        
        for script_name, params in script_targets:
            try:
                result = await self.attack_script_engine.execute_script(script_name, target_url, params)
                results['attack_results'].append(result)
                results['vulnerabilities_found'].extend(result.vulnerabilities_found)
                self.attack_stats['scripts_executed'] += 1
                
                logger.info(f"✅ Script '{script_name}': {len(result.vulnerabilities_found)} vulnerabilities")
                
            except Exception as e:
                logger.error(f"Script '{script_name}' failed: {e}")
        
        # Phase 3: Race condition testing
        logger.info("🏁 Phase 3: Race condition testing")
        
        race_condition_targets = [
            # Test common race condition scenarios
            {'endpoint': f"{target_url}/login", 'method': 'POST', 'data': {'username': 'admin', 'password': 'admin'}},
            {'endpoint': f"{target_url}/register", 'method': 'POST', 'data': {'username': 'testuser', 'email': 'test@example.com'}},
            {'endpoint': f"{target_url}/transfer", 'method': 'POST', 'data': {'amount': '0.01', 'to_account': '12345'}}
        ]
        
        for race_target in race_condition_targets:
            try:
                race_result = await self._test_race_condition(race_target, concurrent_requests=20)
                if race_result.get('vulnerability_found'):
                    results['vulnerabilities_found'].append(race_result['vulnerability'])
                    
                results['race_conditions_tested'] += 1
                self.attack_stats['race_conditions_tested'] += 1
                
            except Exception as e:
                logger.debug(f"Race condition test failed: {e}")
        
        # Analyze confidence distribution
        for vuln in results['vulnerabilities_found']:
            tier = self.vulnerability_scanner.get_confidence_tier(vuln.confidence)
            results['confidence_distribution'][tier] += 1
        
        self.attack_stats['targets_processed'] += 1
        
        logger.info(f"🏁 Assessment complete: {len(results['vulnerabilities_found'])} total vulnerabilities")
        return results
    
    async def _test_race_condition(self, target_config: Dict[str, Any], concurrent_requests: int = 20) -> Dict[str, Any]:
        """Test for race conditions using Turbo Engine"""
        endpoint = target_config['endpoint']
        method = target_config['method']
        data = target_config.get('data', {})
        
        # Create gate for synchronized requests
        gate_name = f"race_{int(datetime.now().timestamp())}"
        gate = self.turbo_engine.create_gate(gate_name)
        
        # Queue concurrent requests
        for i in range(concurrent_requests):
            request = TurboRequest(
                method=method,
                url=endpoint,
                data=data,
                gate=gate_name,
                id=f"race_req_{i}"
            )
            self.turbo_engine.queue_request(request)
        
        # Execute race condition test
        responses = await self.turbo_engine.race_condition_test(gate_name, delay_before_release=0.05)
        
        # Analyze results
        analysis = self.turbo_engine.analyze_response_timing(responses)
        
        result = {
            'endpoint': endpoint,
            'requests_sent': concurrent_requests,
            'responses_received': len(responses),
            'analysis': analysis,
            'vulnerability_found': False
        }
        
        # Check for race condition indicators
        if analysis.get('potential_race_condition'):
            # Create vulnerability finding
            vulnerability = VulnerabilityFinding(
                url=endpoint,
                vuln_type="RACE_CONDITION",
                severity="High",
                confidence=0.80,
                payload=f"Concurrent {method} requests: {concurrent_requests}",
                evidence=f"Race condition detected: {analysis['race_indicator']}. Status distribution: {analysis['status_distribution']}",
                discovered_at=datetime.now(),
                impact_description="Race condition may allow bypassing business logic controls",
                remediation="Implement proper locking mechanisms and atomic operations"
            )
            
            result['vulnerability'] = vulnerability
            result['vulnerability_found'] = True
            
            logger.info(f"🏁 Race condition found: {endpoint}")
        
        return result
    
    async def mass_bug_bounty_scan(self, targets: List[str], max_concurrent: int = 10) -> List[Dict[str, Any]]:
        """Perform mass scanning optimized for bug bounty hunting"""
        logger.info(f"🚀 Starting mass bug bounty scan: {len(targets)} targets")
        
        # Limit concurrency to avoid overwhelming targets
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def limited_assessment(target):
            async with semaphore:
                return await self.comprehensive_target_assessment(target)
        
        # Execute assessments with concurrency limiting
        results = await asyncio.gather(
            *[limited_assessment(target) for target in targets],
            return_exceptions=True
        )
        
        # Filter successful results
        successful_results = [r for r in results if isinstance(r, dict)]
        
        # Aggregate statistics
        total_vulns = sum(len(r['vulnerabilities_found']) for r in successful_results)
        high_confidence_vulns = sum(
            r['confidence_distribution']['HIGH'] for r in successful_results
        )
        
        logger.info(f"🏆 Mass scan complete:")
        logger.info(f"   Targets scanned: {len(successful_results)}")
        logger.info(f"   Total vulnerabilities: {total_vulns}")
        logger.info(f"   High confidence: {high_confidence_vulns}")
        logger.info(f"   Race conditions tested: {sum(r['race_conditions_tested'] for r in successful_results)}")
        
        return successful_results
    
    def _print_final_stats(self):
        """Print final attack statistics"""
        logger.info("📊 Final Attack Statistics:")
        for key, value in self.attack_stats.items():
            logger.info(f"   {key.replace('_', ' ').title()}: {value}")

# Example usage and templates
class BugBountyAttackTemplates:
    """Pre-built attack templates for common bug bounty scenarios"""
    
    @staticmethod
    async def e_commerce_testing(orchestrator: AdvancedAttackOrchestrator, base_url: str):
        """E-commerce specific testing (price manipulation, cart bypass, etc.)"""
        
        e_commerce_targets = [
            f"{base_url}/cart",
            f"{base_url}/checkout", 
            f"{base_url}/payment",
            f"{base_url}/api/products",
            f"{base_url}/admin",
            f"{base_url}/user/profile"
        ]
        
        return await orchestrator.mass_bug_bounty_scan(e_commerce_targets, max_concurrent=5)
    
    @staticmethod
    async def social_media_testing(orchestrator: AdvancedAttackOrchestrator, base_url: str):
        """Social media specific testing (account takeover, privacy bypass, etc.)"""
        
        social_targets = [
            f"{base_url}/login",
            f"{base_url}/register",
            f"{base_url}/api/user",
            f"{base_url}/posts",
            f"{base_url}/messages",
            f"{base_url}/settings"
        ]
        
        return await orchestrator.mass_bug_bounty_scan(social_targets, max_concurrent=3)
    
    @staticmethod  
    async def banking_fintech_testing(orchestrator: AdvancedAttackOrchestrator, base_url: str):
        """Banking/fintech specific testing (race conditions, business logic bypass)"""
        
        fintech_targets = [
            f"{base_url}/transfer",
            f"{base_url}/api/balance", 
            f"{base_url}/transactions",
            f"{base_url}/api/withdraw",
            f"{base_url}/limits",
            f"{base_url}/api/account"
        ]
        
        # Use higher race condition testing for financial apps
        results = []
        for target in fintech_targets:
            result = await orchestrator.comprehensive_target_assessment(target)
            results.append(result)
            
            # Additional race condition testing for critical endpoints
            if any(keyword in target for keyword in ['transfer', 'withdraw', 'balance']):
                logger.info(f"💰 Enhanced race condition testing for: {target}")
                # Additional race tests would go here
        
        return results