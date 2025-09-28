#!/usr/bin/env python3
"""
Intelligent Vulnerability Testing - WAF-Aware & Context-Driven

Instead of brute force payload spraying, this module:
1. Analyzes the target context and technology stack
2. Selects targeted, low-noise payloads based on the specific app
3. Uses timing, WAF detection, and behavioral analysis
4. Focuses on quality over quantity to avoid detection
"""

import asyncio
import logging
import time
import random
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse, parse_qs, urljoin
import aiohttp
import re

from .stealth_headers import get_stealth_headers, get_api_headers


logger = logging.getLogger(__name__)

class VulnerabilityFinding:
    """Local VulnerabilityFinding class to avoid circular imports"""
    def __init__(self, vulnerability_type, url, description, confidence, severity):
        self.vulnerability_type = vulnerability_type
        self.url = url
        self.description = description
        self.confidence = confidence
        self.severity = severity

class IntelligentVulnTester:
    """Smart, context-aware vulnerability testing that avoids WAF detection"""
    
    def __init__(self):
        self.waf_detected = False
        self.baseline_response_time = None
        self.target_tech_stack = {}
        self.tested_patterns = set()
        
    async def analyze_target_context(self, url: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """
        Analyze target to determine optimal testing strategy
        
        Returns context including:
        - Technology stack (PHP, ASP.NET, Java, etc.)
        - WAF presence and type
        - Input validation patterns
        - Error handling behavior
        """
        context = {
            'tech_stack': [],
            'waf_type': None,
            'error_patterns': [],
            'input_validation': 'unknown',
            'baseline_timing': None
        }
        
        try:
            # 1. Technology detection via subtle probes
            tech_probes = {
                'php': '?debug=1',
                'asp': '?aspxerrorpath=/test',
                'java': '?jsessionid=test',
                'nodejs': '?__proto__=test',
                'python': '?__class__=test'
            }
            
            headers = get_stealth_headers(url)
            
            for tech, probe in tech_probes.items():
                test_url = url + probe
                start_time = time.time()
                
                try:
                    async with session.get(test_url, headers=headers) as response:
                        response_time = time.time() - start_time
                        text = await response.text()
                        
                        # Look for technology-specific indicators
                        if self._detect_technology(tech, response, text):
                            context['tech_stack'].append(tech)
                            logger.info(f"🎯 Detected technology: {tech}")
                        
                        # Establish baseline timing
                        if context['baseline_timing'] is None:
                            context['baseline_timing'] = response_time
                            
                except Exception as e:
                    logger.debug(f"Tech probe {tech} failed: {e}")
                
                # Add jitter to avoid pattern detection
                await asyncio.sleep(random.uniform(0.3, 1.0))
            
            # 2. WAF detection via careful probing
            context['waf_type'] = await self._detect_waf(url, session)
            
            # 3. Input validation analysis
            context['input_validation'] = await self._analyze_input_validation(url, session)
            
        except Exception as e:
            logger.debug(f"Context analysis failed: {e}")
        
        return context
    
    def _detect_technology(self, tech: str, response: aiohttp.ClientResponse, text: str) -> bool:
        """Detect technology stack from response patterns"""
        
        indicators = {
            'php': [
                'X-Powered-By: PHP',
                'Set-Cookie: PHPSESSID',
                'php_errors',
                'Fatal error:',
                'Parse error:'
            ],
            'asp': [
                'X-AspNet-Version',
                'X-Powered-By: ASP.NET',
                'Set-Cookie: ASP.NET_SessionId', 
                'Server Error in',
                '__VIEWSTATE'
            ],
            'java': [
                'X-Powered-By: Servlet',
                'Set-Cookie: JSESSIONID',
                'java.lang.',
                'javax.servlet',
                'Tomcat'
            ],
            'nodejs': [
                'X-Powered-By: Express',
                'connect.sid',
                'node.js',
                'npm'
            ],
            'python': [
                'Server: gunicorn',
                'X-Powered-By: Django',
                'werkzeug',
                'flask'
            ]
        }
        
        tech_indicators = indicators.get(tech, [])
        headers_str = str(dict(response.headers)).lower()
        
        return any(indicator.lower() in headers_str or indicator.lower() in text.lower() 
                  for indicator in tech_indicators)
    
    async def _detect_waf(self, url: str, session: aiohttp.ClientSession) -> Optional[str]:
        """Detect WAF presence using minimal, targeted probes"""
        
        # Ultra-minimal WAF detection payloads (less likely to trigger blocks)
        subtle_probes = [
            "?test=<script>",  # Basic XSS probe
            "?id=1'",         # Basic SQLi probe  
            "?file=../etc",   # Basic path traversal
        ]
        
        headers = get_stealth_headers(url)
        
        for probe in subtle_probes:
            try:
                test_url = url + probe
                async with session.get(test_url, headers=headers) as response:
                    
                    # Check for WAF indicators in headers
                    waf_headers = {
                        'cloudflare': ['cf-ray', 'cf-cache-status'],
                        'akamai': ['akamai-request-id', 'akamai-cache-status'],
                        'aws': ['x-amzn-requestid', 'x-amzn-trace-id'],
                        'fortinet': ['fortigate', 'fortiweb'],
                        'imperva': ['x-iinfo', 'incap-ses']
                    }
                    
                    response_headers = dict(response.headers)
                    for waf_name, header_indicators in waf_headers.items():
                        if any(indicator.lower() in k.lower() for k in response_headers.keys() 
                              for indicator in header_indicators):
                            logger.info(f"🛡️ WAF detected: {waf_name}")
                            return waf_name
                    
                    # Check response content for WAF blocks
                    if response.status in [403, 406, 429]:
                        text = await response.text()
                        waf_content_indicators = [
                            'blocked by cloudflare',
                            'access denied',
                            'web application firewall',
                            'security policy',
                            'request blocked'
                        ]
                        
                        if any(indicator in text.lower() for indicator in waf_content_indicators):
                            logger.info("🛡️ WAF detected via content analysis")
                            return 'generic'
                
                # Jitter between probes
                await asyncio.sleep(random.uniform(0.5, 1.5))
                
            except Exception as e:
                logger.debug(f"WAF detection probe failed: {e}")
        
        return None
    
    async def _analyze_input_validation(self, url: str, session: aiohttp.ClientSession) -> str:
        """Analyze input validation patterns to optimize payload selection"""
        
        # Test with safe, non-malicious inputs to understand validation
        test_inputs = [
            "test123",      # Alphanumeric
            "test@test.com", # Email format
            "123",          # Numeric
            "test space",   # Space handling
            "test-dash"     # Special chars
        ]
        
        validation_patterns = []
        headers = get_stealth_headers(url)
        
        try:
            for test_input in test_inputs:
                test_url = f"{url}?test={test_input}"
                async with session.get(test_url, headers=headers) as response:
                    if response.status == 400:
                        text = await response.text()
                        if 'validation' in text.lower() or 'invalid' in text.lower():
                            validation_patterns.append(f"rejects_{test_input}")
                
                await asyncio.sleep(random.uniform(0.2, 0.8))
                
        except Exception as e:
            logger.debug(f"Input validation analysis failed: {e}")
        
        if len(validation_patterns) > 2:
            return 'strict'
        elif len(validation_patterns) > 0:
            return 'moderate'
        else:
            return 'permissive'
    
    async def test_intelligently(self, url: str, session: aiohttp.ClientSession) -> List[VulnerabilityFinding]:
        """
        Main intelligent testing method that adapts based on target analysis
        """
        findings = []
        
        # Step 1: Analyze target context
        logger.info(f"🧠 Analyzing target context: {url}")
        context = await self.analyze_target_context(url, session)
        
        # Step 2: Select optimal testing strategy based on context
        if context['waf_type']:
            logger.info(f"🛡️ WAF detected ({context['waf_type']}), switching to stealth mode")
            findings.extend(await self._stealth_testing(url, session, context))
        else:
            logger.info("�� No WAF detected, using targeted testing")
            findings.extend(await self._targeted_testing(url, session, context))
        
        return findings
    
    async def _stealth_testing(self, url: str, session: aiohttp.ClientSession, context: Dict) -> List[VulnerabilityFinding]:
        """Ultra-careful testing when WAF is present"""
        findings = []
        
        # Use only the most subtle, context-specific payloads
        if 'php' in context['tech_stack']:
            findings.extend(await self._test_php_specific_stealth(url, session))
        elif 'java' in context['tech_stack']:
            findings.extend(await self._test_java_specific_stealth(url, session))
        elif 'asp' in context['tech_stack']:
            findings.extend(await self._test_asp_specific_stealth(url, session))
        
        # Add longer delays between requests
        await asyncio.sleep(random.uniform(2.0, 4.0))
        
        return findings
    
    async def _targeted_testing(self, url: str, session: aiohttp.ClientSession, context: Dict) -> List[VulnerabilityFinding]:
        """Focused testing when no WAF is detected"""
        findings = []
        
        # Test based on technology stack with more aggressive payloads
        for tech in context['tech_stack']:
            if tech == 'php':
                findings.extend(await self._test_php_vulnerabilities(url, session))
            elif tech == 'java':
                findings.extend(await self._test_java_vulnerabilities(url, session))
            elif tech == 'asp':
                findings.extend(await self._test_asp_vulnerabilities(url, session))
            
            # Moderate delays
            await asyncio.sleep(random.uniform(0.5, 1.5))
            
        return findings
    
    async def _test_php_specific_stealth(self, url: str, session: aiohttp.ClientSession) -> List[VulnerabilityFinding]:
        """PHP-specific stealth testing"""
        findings = []
        
        # Very subtle PHP-specific tests
        subtle_payloads = [
            "?debug=1",           # Debug mode
            "?source=1",          # Source viewing
            "?phpinfo=1",         # Info disclosure
        ]
        
        headers = get_stealth_headers(url)
        
        for payload in subtle_payloads:
            try:
                test_url = url + payload
                async with session.get(test_url, headers=headers) as response:
                    text = await response.text()
                    
                    # Look for PHP-specific information disclosure
                    if 'phpinfo()' in text or 'PHP Version' in text:
                        finding = VulnerabilityFinding(
                            vulnerability_type='info_disclosure',
                            url=test_url,
                            description='PHP information disclosure detected',
                            confidence='high',
                            severity='medium'
                        )
                        findings.append(finding)
                        logger.info(f"🔍 PHP info disclosure found: {test_url}")
                
                # Long delay for stealth
                await asyncio.sleep(random.uniform(3.0, 6.0))
                
            except Exception as e:
                logger.debug(f"PHP stealth test failed: {e}")
        
        return findings
    
    async def _test_java_vulnerabilities(self, url: str, session: aiohttp.ClientSession) -> List[VulnerabilityFinding]:
        """Java-specific targeted testing"""
        findings = []
        
        # Java-specific payloads
        java_payloads = [
            "?jsessionid=123'",          # Session injection
            "?class.classLoader=test",   # Class loader manipulation
            "?java.lang.Runtime=test",   # Runtime access
        ]
        
        headers = get_stealth_headers(url)
        
        for payload in java_payloads:
            try:
                test_url = url + payload
                async with session.get(test_url, headers=headers) as response:
                    text = await response.text()
                    
                    # Look for Java-specific error patterns
                    java_errors = [
                        'java.lang.',
                        'javax.servlet',
                        'ClassNotFoundException',
                        'NoSuchMethodException'
                    ]
                    
                    if any(error in text for error in java_errors):
                        finding = VulnerabilityFinding(
                            vulnerability_type='java_injection',
                            url=test_url, 
                            description='Java injection or information disclosure detected',
                            confidence='medium',
                            severity='medium'
                        )
                        findings.append(finding)
                        logger.info(f"🔍 Java vulnerability found: {test_url}")
                
                await asyncio.sleep(random.uniform(1.0, 2.0))
                
            except Exception as e:
                logger.debug(f"Java test failed: {e}")
        
        return findings

    # Additional technology-specific methods...
    async def _test_php_vulnerabilities(self, url: str, session: aiohttp.ClientSession) -> List[VulnerabilityFinding]:
        """PHP vulnerability testing when no WAF detected"""
        # Implementation for more aggressive PHP testing
        return []
    
    async def _test_asp_specific_stealth(self, url: str, session: aiohttp.ClientSession) -> List[VulnerabilityFinding]:
        """ASP.NET stealth testing"""
        return []
    
    async def _test_asp_vulnerabilities(self, url: str, session: aiohttp.ClientSession) -> List[VulnerabilityFinding]:
        """ASP.NET vulnerability testing"""
        return []


# Global instance
intelligent_tester = IntelligentVulnTester()

async def test_url_intelligently(url: str, session: aiohttp.ClientSession) -> List[VulnerabilityFinding]:
    """Convenience function for intelligent testing"""
    return await intelligent_tester.test_intelligently(url, session)
