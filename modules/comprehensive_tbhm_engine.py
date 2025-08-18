#!/usr/bin/env python3
"""
Comprehensive TBHM-Inspired Multi-Tiered Vulnerability Discovery Engine
Deep integration of ALL bug hunting methodologies with AI-driven adaptive scanning
"""

import asyncio
import aiohttp
import logging
import json
import re
import subprocess
import os
import tempfile
import random
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass
from pathlib import Path
import google.generativeai as genai
from .ai_pentester_agent import AIPentesterAgent

logger = logging.getLogger("ComprehensiveTBHM")

@dataclass
class ScanningMethod:
    """Individual scanning method tracking"""
    name: str
    tool: str
    category: str
    last_executed: datetime
    success_rate: float
    findings_count: int
    complexity: str  # LOW, MEDIUM, HIGH
    prerequisites: List[str]
    expected_findings: List[str]

@dataclass
class AdaptiveScanDecision:
    """AI-driven scanning decision"""
    method: str
    priority: int
    confidence: float
    reasoning: str
    expected_vulns: List[str]

class ComprehensiveTBHMEngine:
    def __init__(self, asset_manager, config: Dict):
        self.asset_manager = asset_manager
        self.config = config
        self.gemini_key = config.get('gemini_api_key', '')
        
        # Initialize AI Pentester Agent (XBOW-inspired)
        self.ai_pentester = AIPentesterAgent(asset_manager, config)
        
        # Initialize Gemini for adaptive decisions
        if self.gemini_key:
            genai.configure(api_key=self.gemini_key)
            self.gemini_model = genai.GenerativeModel('gemini-2.0-flash-exp')
            logger.info("🤖 Gemini initialized for adaptive scanning decisions")
        else:
            self.gemini_model = None
        
        # COMPREHENSIVE TBHM TOOL ARSENAL
        self.reconnaissance_tools = {
            # Subdomain Discovery
            'subfinder': {'cmd': 'subfinder', 'category': 'subdomain_enum'},
            'assetfinder': {'cmd': 'assetfinder', 'category': 'subdomain_enum'},
            'amass': {'cmd': 'amass', 'category': 'subdomain_enum'},
            'chaos': {'cmd': 'chaos', 'category': 'subdomain_enum'},
            'dnsrecon': {'cmd': 'dnsrecon', 'category': 'dns_enum'},
            'dnsenum': {'cmd': 'dnsenum', 'category': 'dns_enum'},
            'fierce': {'cmd': 'fierce', 'category': 'dns_enum'},
            
            # URL Discovery  
            'gau': {'cmd': 'gau', 'category': 'url_discovery'},
            'waybackurls': {'cmd': 'waybackurls', 'category': 'url_discovery'},
            'urlprobe': {'cmd': 'urlprobe', 'category': 'url_validation'},
            'httpx': {'cmd': 'httpx', 'category': 'url_validation'},
            'httprobe': {'cmd': 'httprobe', 'category': 'url_validation'},
            
            # Content Discovery
            'katana': {'cmd': 'katana', 'category': 'web_crawling'},
            'hakrawler': {'cmd': 'hakrawler', 'category': 'web_crawling'},
            'gospider': {'cmd': 'gospider', 'category': 'web_crawling'},
            'feroxbuster': {'cmd': 'feroxbuster', 'category': 'directory_bruteforce'},
            'dirsearch': {'cmd': 'dirsearch', 'category': 'directory_bruteforce'},
            'gobuster': {'cmd': 'gobuster', 'category': 'directory_bruteforce'},
            'dirb': {'cmd': 'dirb', 'category': 'directory_bruteforce'},
            'wfuzz': {'cmd': 'wfuzz', 'category': 'fuzzing'},
            'ffuf': {'cmd': 'ffuf', 'category': 'fuzzing'},
            
            # Parameter Discovery
            'arjun': {'cmd': 'arjun', 'category': 'parameter_discovery'},
            'paramspider': {'cmd': 'paramspider', 'category': 'parameter_discovery'},
            'x8': {'cmd': 'x8', 'category': 'parameter_discovery'},
            
            # Technology Detection
            'wappalyzer': {'cmd': 'wappalyzer', 'category': 'tech_detection'},
            'webanalyze': {'cmd': 'webanalyze', 'category': 'tech_detection'},
            'whatweb': {'cmd': 'whatweb', 'category': 'tech_detection'},
        }
        
        self.vulnerability_tools = {
            # AI-Powered Validation (XBOW-inspired)
            'ai_validated_scan': {'cmd': 'ai_pentester', 'category': 'ai_validation'},
            
            # Core Vulnerability Scanners
            'nuclei': {'cmd': 'nuclei', 'category': 'comprehensive_vuln'},
            'nmap': {'cmd': 'nmap', 'category': 'network_vuln'},
            'nikto': {'cmd': 'nikto', 'category': 'web_vuln'},
            'dirb': {'cmd': 'dirb', 'category': 'directory_vuln'},
            
            # Injection Testing
            'sqlmap': {'cmd': 'sqlmap', 'category': 'sql_injection'},
            'xsstrike': {'cmd': 'xsstrike', 'category': 'xss_testing'},
            'dalfox': {'cmd': 'dalfox', 'category': 'xss_testing'},
            'xsser': {'cmd': 'xsser', 'category': 'xss_testing'},
            'commix': {'cmd': 'commix', 'category': 'command_injection'},
            
            # Web Application Testing
            'burpsuite': {'cmd': 'burp', 'category': 'comprehensive_web'},
            'zaproxy': {'cmd': 'zap', 'category': 'comprehensive_web'},
            'wpscan': {'cmd': 'wpscan', 'category': 'cms_testing'},
            'joomscan': {'cmd': 'joomscan', 'category': 'cms_testing'},
            'droopescan': {'cmd': 'droopescan', 'category': 'cms_testing'},
            
            # API Testing
            'postman': {'cmd': 'newman', 'category': 'api_testing'},
            'kiterunner': {'cmd': 'kr', 'category': 'api_discovery'},
            'restler': {'cmd': 'restler', 'category': 'api_fuzzing'},
            
            # Specialized Testing
            'ssrfmap': {'cmd': 'ssrfmap', 'category': 'ssrf_testing'},
            'xxeinjector': {'cmd': 'xxeinjector', 'category': 'xxe_testing'},
            'corscanner': {'cmd': 'corscanner', 'category': 'cors_testing'},
            'testssl': {'cmd': 'testssl.sh', 'category': 'ssl_testing'},
            'sslscan': {'cmd': 'sslscan', 'category': 'ssl_testing'},
            
            # Mobile & Cloud
            'mobsf': {'cmd': 'mobsf', 'category': 'mobile_testing'},
            'prowler': {'cmd': 'prowler', 'category': 'cloud_testing'},
            'cloudsploit': {'cmd': 'cloudsploit', 'category': 'cloud_testing'},
        }
        
        # Method execution tracking (per asset)
        self.method_history = {}
        
        # TBHM Testing Categories with comprehensive approaches
        self.tbhm_categories = {
            'reconnaissance': {
                'subdomain_enumeration': ['subfinder', 'assetfinder', 'amass', 'chaos'],
                'dns_enumeration': ['dnsrecon', 'dnsenum', 'fierce'],
                'url_discovery': ['gau', 'waybackurls', 'katana', 'hakrawler'],
                'parameter_discovery': ['arjun', 'paramspider', 'x8'],
                'technology_detection': ['wappalyzer', 'webanalyze', 'whatweb'],
                'content_discovery': ['feroxbuster', 'dirsearch', 'gobuster', 'ffuf']
            },
            'vulnerability_discovery': {
                'injection_testing': ['sqlmap', 'xsstrike', 'dalfox', 'commix'],
                'authorization_testing': ['custom_auth_tests', 'session_analysis'],
                'transport_security': ['testssl', 'sslscan', 'cors_testing'],
                'web_services': ['kiterunner', 'restler', 'api_fuzzing'],
                'cms_testing': ['wpscan', 'joomscan', 'droopescan'],
                'comprehensive_scanning': ['nuclei', 'nikto', 'nmap']
            },
            'exploitation': {
                'privilege_escalation': ['custom_privesc', 'auth_bypass'],
                'logic_testing': ['business_logic', 'workflow_analysis'],
                'advanced_attacks': ['ssrfmap', 'xxeinjector', 'deserialization']
            }
        }
        
        logger.info(f"🚀 Comprehensive TBHM Engine initialized with {len(self.reconnaissance_tools)} recon tools and {len(self.vulnerability_tools)} vuln tools")

    async def adaptive_multi_tier_scan(self, assets: List[Dict], session: aiohttp.ClientSession) -> Dict:
        """AI-driven adaptive multi-tier scanning with comprehensive TBHM methodology"""
        results = {
            'assets_scanned': 0,
            'methods_executed': 0,
            'vulnerabilities_found': 0,
            'new_assets_discovered': 0,
            'scan_decisions': []
        }
        
        logger.info(f"🧠 ADAPTIVE MULTI-TIER SCAN: Starting comprehensive TBHM analysis on {len(assets)} assets")
        
        for asset in assets:
            try:
                asset_results = await self._comprehensive_asset_analysis(asset, session)
                
                results['assets_scanned'] += 1
                results['methods_executed'] += asset_results.get('methods_executed', 0)
                results['vulnerabilities_found'] += asset_results.get('vulnerabilities_found', 0)
                results['new_assets_discovered'] += asset_results.get('new_assets_discovered', 0)
                results['scan_decisions'].extend(asset_results.get('decisions', []))
                
            except Exception as e:
                logger.error(f"Comprehensive analysis failed for {asset.get('url', 'unknown')}: {e}")
        
        logger.info(f"🎯 ADAPTIVE SCAN COMPLETE: {results['vulnerabilities_found']} vulns, {results['new_assets_discovered']} new assets, {results['methods_executed']} methods")
        return results

    async def _comprehensive_asset_analysis(self, asset: Dict, session: aiohttp.ClientSession) -> Dict:
        """Comprehensive per-asset analysis using ALL TBHM methodologies"""
        url = asset['url']
        asset_id = asset['id']
        tech_stack = asset.get('tech_stack', '')
        
        results = {
            'methods_executed': 0,
            'vulnerabilities_found': 0,
            'new_assets_discovered': 0,
            'decisions': []
        }
        
        logger.info(f"🔍 COMPREHENSIVE ANALYSIS: {url} | Tech: {tech_stack}")
        
        # Phase 1: AI-Driven Method Selection
        scan_decisions = await self._ai_select_scanning_methods(asset)
        results['decisions'] = scan_decisions
        
        # Phase 2: Execute Selected Methods in Priority Order
        for decision in sorted(scan_decisions, key=lambda x: x.priority):
            try:
                method_results = await self._execute_scanning_method(decision.method, asset, session)
                results['methods_executed'] += 1
                results['vulnerabilities_found'] += method_results.get('vulnerabilities', 0)
                results['new_assets_discovered'] += method_results.get('new_assets', 0)
                
                # Update method history
                self._update_method_history(asset_id, decision.method, method_results)
                
            except Exception as e:
                logger.error(f"Method {decision.method} failed for {url}: {e}")
        
        return results

    async def _ai_select_scanning_methods(self, asset: Dict) -> List[AdaptiveScanDecision]:
        """Use AI to intelligently select scanning methods based on asset characteristics"""
        decisions = []
        
        if not self.gemini_model:
            # Fallback to rule-based selection
            return self._rule_based_method_selection(asset)
        
        try:
            # Prepare context for AI decision
            asset_context = {
                'url': asset['url'],
                'tech_stack': asset.get('tech_stack', ''),
                'status_code': asset.get('status_code', 0),
                'title': asset.get('title', ''),
                'response_body': asset.get('response_body', '')[:1000],  # Limited for API
                'previous_methods': self._get_previous_methods(asset['id']),
                'scan_history': self._get_scan_history(asset['id'])
            }
            
            prompt = f"""
            You are an expert bug bounty hunter using the TBHM methodology. Analyze this asset and recommend the most effective scanning methods.
            
            Asset: {json.dumps(asset_context, indent=2)}
            
            Available tool categories:
            1. Reconnaissance: subdomain_enumeration, dns_enumeration, url_discovery, parameter_discovery, technology_detection, content_discovery
            2. Vulnerability Discovery: injection_testing, authorization_testing, transport_security, web_services, cms_testing, comprehensive_scanning
            3. Exploitation: privilege_escalation, logic_testing, advanced_attacks
            
            Consider:
            - What methods haven't been tried yet?
            - What tech stack vulnerabilities should be prioritized?
            - What's the most likely attack surface?
            - What methods have highest success probability?
            
            Respond with JSON array of recommended methods:
            [{{
                "method": "category_name",
                "priority": 1-10,
                "confidence": 0.0-1.0,
                "reasoning": "why this method",
                "expected_vulns": ["vuln_type1", "vuln_type2"]
            }}]
            """
            
            response = await asyncio.get_event_loop().run_in_executor(
                None, self.gemini_model.generate_content, prompt
            )
            
            # Parse AI response
            ai_decisions = json.loads(response.text)
            
            for decision_data in ai_decisions:
                decision = AdaptiveScanDecision(
                    method=decision_data['method'],
                    priority=decision_data['priority'],
                    confidence=decision_data['confidence'],
                    reasoning=decision_data['reasoning'],
                    expected_vulns=decision_data.get('expected_vulns', [])
                )
                decisions.append(decision)
                
            logger.info(f"🤖 AI DECISIONS: {len(decisions)} methods recommended for {asset['url']}")
            
        except Exception as e:
            logger.error(f"AI method selection failed: {e}")
            decisions = self._rule_based_method_selection(asset)
        
        return decisions

    def _rule_based_method_selection(self, asset: Dict) -> List[AdaptiveScanDecision]:
        """Fallback rule-based method selection"""
        decisions = []
        url = asset['url']
        tech_stack = asset.get('tech_stack', '').lower()
        
        # Basic reconnaissance if not done
        if not self._method_executed(asset['id'], 'subdomain_enumeration'):
            decisions.append(AdaptiveScanDecision(
                method='subdomain_enumeration',
                priority=10,
                confidence=0.9,
                reasoning='Basic subdomain discovery needed',
                expected_vulns=['subdomain_takeover', 'additional_attack_surface']
            ))
        
        # Content discovery for web apps
        if asset.get('status_code') == 200:
            decisions.append(AdaptiveScanDecision(
                method='content_discovery',
                priority=8,
                confidence=0.8,
                reasoning='200 status indicates active web application',
                expected_vulns=['directory_traversal', 'file_exposure', 'backup_files']
            ))
        
        # Tech-specific testing
        if 'wordpress' in tech_stack or 'wp-' in url:
            decisions.append(AdaptiveScanDecision(
                method='cms_testing',
                priority=9,
                confidence=0.9,
                reasoning='WordPress detected - CMS-specific vulnerabilities likely',
                expected_vulns=['wp_plugins', 'wp_themes', 'wp_core']
            ))
        
        # API testing for API endpoints
        if any(keyword in url.lower() for keyword in ['api', 'graphql', 'rest']):
            decisions.append(AdaptiveScanDecision(
                method='web_services',
                priority=9,
                confidence=0.8,
                reasoning='API endpoint detected',
                expected_vulns=['api_auth_bypass', 'graphql_introspection', 'idor']
            ))
        
        # Injection testing for dynamic apps
        if '?' in url or 'php' in tech_stack or 'jsp' in tech_stack:
            decisions.append(AdaptiveScanDecision(
                method='injection_testing',
                priority=9,
                confidence=0.7,
                reasoning='Dynamic application with parameters',
                expected_vulns=['sql_injection', 'xss', 'command_injection']
            ))
        
        return decisions

    async def _execute_scanning_method(self, method: str, asset: Dict, session: aiohttp.ClientSession) -> Dict:
        """Execute a specific scanning method"""
        url = asset['url']
        results = {'vulnerabilities': 0, 'new_assets': 0, 'findings': []}
        
        logger.info(f"⚡ EXECUTING: {method} on {url}")
        
        # XBOW-inspired AI validation scanning
        if method == 'ai_validated_scan':
            return await self._run_ai_validated_scan(asset)
        
        # Continue with existing methods...
        
        try:
            if method == 'subdomain_enumeration':
                results = await self._run_subdomain_enumeration(asset, session)
            elif method == 'content_discovery':
                results = await self._run_content_discovery(asset, session)
            elif method == 'injection_testing':
                results = await self._run_injection_testing(asset, session)
            elif method == 'cms_testing':
                results = await self._run_cms_testing(asset, session)
            elif method == 'web_services':
                results = await self._run_web_services_testing(asset, session)
            elif method == 'authorization_testing':
                results = await self._run_authorization_testing(asset, session)
            elif method == 'transport_security':
                results = await self._run_transport_security_testing(asset, session)
            elif method == 'comprehensive_scanning':
                results = await self._run_comprehensive_nuclei_scan(asset, session)
            else:
                logger.warning(f"Unknown method: {method}")
                
        except Exception as e:
            logger.error(f"Method execution failed for {method}: {e}")
        
        return results

    async def _run_subdomain_enumeration(self, asset: Dict, session: aiohttp.ClientSession) -> Dict:
        """Run comprehensive subdomain enumeration"""
        domain = asset['url'].replace('https://', '').replace('http://', '').split('/')[0]
        results = {'vulnerabilities': 0, 'new_assets': 0, 'findings': []}
        
        try:
            # Run subfinder
            cmd = ['subfinder', '-d', domain, '-silent', '-o', '/dev/stdout']
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if stdout:
                subdomains = stdout.decode().strip().split('\\n')
                for subdomain in subdomains:
                    if subdomain and subdomain != domain:
                        # Add to asset database
                        self.asset_manager.add_asset(f"https://{subdomain}", subdomain, "subdomain_enumeration")
                        results['new_assets'] += 1
                        
            logger.info(f"🔍 SUBDOMAIN ENUM: Found {results['new_assets']} new subdomains for {domain}")
            
        except Exception as e:
            logger.error(f"Subdomain enumeration failed: {e}")
        
        return results

    async def _run_ai_validated_scan(self, asset: Dict) -> Dict:
        """Run AI-powered scan with deterministic validation (XBOW approach)"""
        results = {'vulnerabilities': 0, 'new_assets': 0, 'findings': []}
        
        try:
            url = asset['url']
            logger.info(f"🤖 AI-VALIDATED SCAN: {url}")
            
            # Use AI pentester agent with validation
            validated_vulns = await self.ai_pentester.run_ai_assisted_scan(url)
            
            # Store validated vulnerabilities  
            for vuln in validated_vulns:
                self.asset_manager.add_vulnerability(vuln)
                results['vulnerabilities'] += 1
                results['findings'].append(vuln)
                
                logger.info(f"✅ VALIDATED {vuln['type']}: {vuln['description']}")
            
            return results
            
        except Exception as e:
            logger.error(f"AI validated scan failed: {e}")
            return results

    async def _run_comprehensive_nuclei_scan(self, asset: Dict, session: aiohttp.ClientSession) -> Dict:
        """Run comprehensive Nuclei scan with ALL relevant templates"""
        url = asset['url']
        tech_stack = asset.get('tech_stack', '').lower()
        results = {'vulnerabilities': 0, 'new_assets': 0, 'findings': []}
        
        try:
            nuclei_path = self.config.get('nuclei', {}).get('path', 'nuclei')
            templates_path = self.config.get('nuclei', {}).get('templates_path', os.path.expanduser('~/nuclei-templates'))
            
            # COMPREHENSIVE template selection - ALL relevant paths
            template_args = []
            
            # Core vulnerability templates
            core_templates = [
                'http/cves/',
                'http/vulnerabilities/',
                'http/exposures/',
                'http/misconfiguration/',
                'http/takeovers/',
                'http/default-logins/',
                'http/fuzzing/',
                'http/file/',
                'http/iot/'
            ]
            
            for template in core_templates:
                template_path = Path(templates_path) / template
                if template_path.exists():
                    template_args.extend(['-t', str(template_path)])
            
            # Technology-specific templates
            if 'nginx' in tech_stack:
                template_args.extend(['-t', str(Path(templates_path) / 'http/technologies/nginx/')])
            if 'apache' in tech_stack:
                template_args.extend(['-t', str(Path(templates_path) / 'http/technologies/apache/')])
            if 'wordpress' in tech_stack:
                template_args.extend(['-t', str(Path(templates_path) / 'http/technologies/wordpress/')])
            
            if template_args:
                with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as tf:
                    tf.write(url + "\\n")
                    target_file = tf.name
                
                cmd = [
                    nuclei_path,
                    '-list', target_file,
                    '-jsonl',
                    '-silent',
                    '-rate-limit', '200',
                    '-concurrency', '50',
                    *template_args
                ]
                
                process = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                
                if stdout:
                    for line in stdout.decode().split('\\n'):
                        if line:
                            try:
                                result = json.loads(line)
                                # Store vulnerability
                                vuln_data = {
                                    'asset_id': asset['id'],
                                    'type': result.get('template-id', 'nuclei_finding'),
                                    'description': result.get('info', {}).get('name', 'Nuclei finding'),
                                    'severity': result.get('info', {}).get('severity', 'info').upper(),
                                    'evidence': str(result),
                                    'payload': result.get('curl-command', ''),
                                    'detected_at': datetime.now().isoformat(),
                                    'confidence': 0.8
                                }
                                self.asset_manager.add_vulnerability(vuln_data)
                                results['vulnerabilities'] += 1
                            except json.JSONDecodeError:
                                continue
                
                os.unlink(target_file)
                
        except Exception as e:
            logger.error(f"Comprehensive Nuclei scan failed: {e}")
        
        logger.info(f"🚀 NUCLEI COMPREHENSIVE: {results['vulnerabilities']} vulnerabilities found in {url}")
        return results

    def _method_executed(self, asset_id: int, method: str) -> bool:
        """Check if method was previously executed on asset"""
        asset_history = self.method_history.get(asset_id, {})
        return method in asset_history

    def _get_previous_methods(self, asset_id: int) -> List[str]:
        """Get list of previously executed methods"""
        return list(self.method_history.get(asset_id, {}).keys())

    def _get_scan_history(self, asset_id: int) -> Dict:
        """Get scan history for asset"""
        return self.method_history.get(asset_id, {})

    def _update_method_history(self, asset_id: int, method: str, results: Dict):
        """Update method execution history"""
        if asset_id not in self.method_history:
            self.method_history[asset_id] = {}
        
        self.method_history[asset_id][method] = {
            'executed_at': datetime.now(),
            'vulnerabilities_found': results.get('vulnerabilities', 0),
            'new_assets_found': results.get('new_assets', 0),
            'success': results.get('vulnerabilities', 0) > 0
        }

    # Placeholder methods for other testing categories
    async def _run_content_discovery(self, asset: Dict, session: aiohttp.ClientSession) -> Dict:
        """Content discovery implementation"""
        return {'vulnerabilities': 0, 'new_assets': 0, 'findings': []}
    
    async def _run_injection_testing(self, asset: Dict, session: aiohttp.ClientSession) -> Dict:
        """Injection testing implementation"""
        return {'vulnerabilities': 0, 'new_assets': 0, 'findings': []}
    
    async def _run_cms_testing(self, asset: Dict, session: aiohttp.ClientSession) -> Dict:
        """CMS testing implementation"""
        return {'vulnerabilities': 0, 'new_assets': 0, 'findings': []}
    
    async def _run_web_services_testing(self, asset: Dict, session: aiohttp.ClientSession) -> Dict:
        """Web services testing implementation"""
        return {'vulnerabilities': 0, 'new_assets': 0, 'findings': []}
    
    async def _run_authorization_testing(self, asset: Dict, session: aiohttp.ClientSession) -> Dict:
        """Authorization testing implementation"""
        return {'vulnerabilities': 0, 'new_assets': 0, 'findings': []}
    
    async def _run_transport_security_testing(self, asset: Dict, session: aiohttp.ClientSession) -> Dict:
        """Transport security testing implementation"""
        return {'vulnerabilities': 0, 'new_assets': 0, 'findings': []}