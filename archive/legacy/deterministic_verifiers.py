#!/usr/bin/env python3
"""
Deterministic Vulnerability Verifiers
Fast, precise evidence collection without AI inference
"""

import re
import json
import hashlib
import time
import logging
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs, urlencode, quote, unquote
import asyncio
import aiohttp

logger = logging.getLogger(__name__)

@dataclass
class Evidence:
    """Deterministic evidence structure"""
    type: str  # 'reflection', 'error', 'timing', 'status', 'header', 'oob'
    confidence: float  # 0.0 to 1.0
    details: str
    raw_data: str
    markers: List[str]
    context: Dict[str, Any]

class DeterministicVerifiers:
    """
    Collection of deterministic vulnerability verifiers.
    No AI inference - only precise pattern matching and evidence collection.
    """
    
    def __init__(self):
        self.session_timeout = aiohttp.ClientTimeout(total=15)
        self._error_patterns = self._load_error_patterns()
        self._timing_baseline = {}  # URL -> baseline response time
    
    def _load_error_patterns(self) -> Dict[str, List[str]]:
        """Load database error patterns for SQLi detection"""
        return {
            'mysql': [
                r"You have an error in your SQL syntax",
                r"mysql_fetch_array\(\)",
                r"mysql_fetch_assoc\(\)",
                r"mysql_fetch_row\(\)",
                r"mysql_num_rows\(\)",
                r"mysql_query\(\)",
                r"Warning.*mysql_.*",
                r"MySQL server version",
                r"MySQLSyntaxErrorException",
                r"com\.mysql\.jdbc\.exceptions"
            ],
            'postgresql': [
                r"PostgreSQL.*ERROR",
                r"Warning.*\Wpg_.*",
                r"valid PostgreSQL result",
                r"Npgsql\.",
                r"PG::Error",
                r"org\.postgresql\.util\.PSQLException",
                r"ERROR:\s+syntax error at or near"
            ],
            'mssql': [
                r"Microsoft.*ODBC.*SQL Server",
                r"OLE DB.*SQL Server",
                r"Microsoft OLE DB Provider for SQL Server",
                r"\[SQL Server\]",
                r"ADODB\.Field.*error",
                r"Microsoft VBScript runtime error",
                r"Unclosed quotation mark after",
                r"System\.Data\.SqlClient\.SqlException"
            ],
            'oracle': [
                r"ORA-[0-9]{5}",
                r"Oracle.*Driver",
                r"Warning.*\Woci_.*",
                r"Warning.*\Wora_.*",
                r"oracle\.jdbc\.driver"
            ],
            'sqlite': [
                r"SQLite.*error",
                r"sqlite3\.OperationalError",
                r"SQLiteException",
                r"System\.Data\.SQLite\.SQLiteException"
            ],
            'generic': [
                r"SQL syntax.*error",
                r"Warning.*mysql_.*",
                r"MySQLSyntaxErrorException",
                r"valid MySQL result",
                r"check the manual that corresponds to your.*server version",
                r"ORA-[0-9]{4,5}",
                r"Microsoft.*ODBC.*Driver",
                r"SQLSTATE\[.*?\]",
                r"Syntax error.*query",
                r"Query failed",
                r"quoted string not properly terminated"
            ]
        }
    
    async def verify_xss_reflected(self, url: str, param: str, payload: str, 
                                 session: aiohttp.ClientSession) -> Optional[Evidence]:
        """
        Deterministic reflected XSS verification.
        Tests for exact payload reflection and context analysis.
        """
        try:
            # Generate unique marker
            marker = f"MODSCAN_XSS_{int(time.time())}"
            test_payload = payload.replace("__MARKER__", marker)
            
            # Test the payload
            test_url = self._inject_parameter(url, param, test_payload)
            
            async with session.get(test_url, timeout=self.session_timeout) as response:
                content = await response.text()
                headers = dict(response.headers)
                
                # Check for marker reflection
                if marker not in content:
                    return None
                
                # Analyze reflection context
                context = self._analyze_xss_context(content, marker)
                confidence = self._calculate_xss_confidence(context, headers)
                
                if confidence < 0.3:  # Minimum confidence threshold
                    return None
                
                return Evidence(
                    type='reflection',
                    confidence=confidence,
                    details=f"Marker '{marker}' reflected in {context['location']} context",
                    raw_data=content[:2000],
                    markers=[marker],
                    context=context
                )
                
        except Exception as e:
            logger.debug(f"XSS verification error for {url}: {e}")
            return None
    
    async def verify_xss_dom(self, url: str, payload: str, 
                           session: aiohttp.ClientSession) -> Optional[Evidence]:
        """
        Deterministic DOM XSS verification using fragment/hash injection.
        """
        try:
            marker = f"MODSCAN_DOM_{int(time.time())}"
            test_payload = payload.replace("__MARKER__", marker)
            
            # Test with hash/fragment
            test_url = f"{url}#{test_payload}"
            
            async with session.get(test_url, timeout=self.session_timeout) as response:
                content = await response.text()
                
                # Look for JavaScript that processes location.hash or fragment
                js_patterns = [
                    r'location\.hash',
                    r'window\.location\.hash',
                    r'document\.location\.hash',
                    r'location\.fragment',
                    r'innerHTML.*location',
                    r'eval.*location',
                    r'document\.write.*location'
                ]
                
                js_found = any(re.search(pattern, content, re.IGNORECASE) for pattern in js_patterns)
                
                if not js_found:
                    return None
                
                # Check if the payload would be dangerous in this context
                dangerous_patterns = [
                    r'<script.*?>' + re.escape(marker),
                    r'javascript:.*?' + re.escape(marker),
                    r'on\w+\s*=.*?' + re.escape(marker)
                ]
                
                dangerous = any(re.search(pattern, test_payload, re.IGNORECASE) for pattern in dangerous_patterns)
                
                confidence = 0.7 if dangerous else 0.4
                
                return Evidence(
                    type='dom_reflection',
                    confidence=confidence,
                    details=f"DOM XSS sink detected with hash processing",
                    raw_data=content[:2000],
                    markers=[marker],
                    context={'js_sinks': js_found, 'payload_dangerous': dangerous}
                )
                
        except Exception as e:
            logger.debug(f"DOM XSS verification error for {url}: {e}")
            return None
    
    async def verify_sqli_error(self, url: str, param: str, payload: str,
                              session: aiohttp.ClientSession) -> Optional[Evidence]:
        """
        Deterministic SQL injection verification using error patterns.
        """
        try:
            test_url = self._inject_parameter(url, param, payload)
            
            async with session.get(test_url, timeout=self.session_timeout) as response:
                content = await response.text()
                
                # Check for database error patterns
                detected_db = None
                matched_patterns = []
                
                for db_type, patterns in self._error_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                            detected_db = db_type
                            matched_patterns.append(pattern)
                            break
                    if detected_db:
                        break
                
                if not detected_db or not matched_patterns:
                    return None
                
                confidence = 0.95 if len(matched_patterns) > 1 else 0.85
                
                return Evidence(
                    type='error',
                    confidence=confidence,
                    details=f"SQL error detected: {detected_db} database",
                    raw_data=content[:2000],
                    markers=[],
                    context={
                        'database_type': detected_db,
                        'error_patterns': matched_patterns[:3],
                        'payload': payload
                    }
                )
                
        except Exception as e:
            logger.debug(f"SQLi error verification error for {url}: {e}")
            return None
    
    async def verify_sqli_boolean(self, url: str, param: str, 
                                session: aiohttp.ClientSession) -> Optional[Evidence]:
        """
        Deterministic boolean-based SQL injection verification.
        """
        try:
            # Get baseline response
            baseline_response = await self._get_baseline_response(url, session)
            if not baseline_response:
                return None
            
            baseline_content, baseline_length = baseline_response
            
            # Test true condition
            true_payload = f"' OR 1=1--"
            true_url = self._inject_parameter(url, param, true_payload)
            
            async with session.get(true_url, timeout=self.session_timeout) as response:
                true_content = await response.text()
                true_length = len(true_content)
            
            # Test false condition
            false_payload = f"' OR 1=2--"
            false_url = self._inject_parameter(url, param, false_payload)
            
            async with session.get(false_url, timeout=self.session_timeout) as response:
                false_content = await response.text()
                false_length = len(false_content)
            
            # Analyze differences
            baseline_similarity = self._content_similarity(baseline_content, true_content)
            false_similarity = self._content_similarity(baseline_content, false_content)
            
            # Boolean SQLi detected if true condition behaves differently from false
            if abs(true_length - false_length) > 100 or abs(baseline_similarity - false_similarity) > 0.3:
                confidence = 0.8
                
                return Evidence(
                    type='boolean_differential',
                    confidence=confidence,
                    details=f"Boolean SQLi: TRUE/FALSE responses differ significantly",
                    raw_data=f"Baseline: {baseline_length}b, True: {true_length}b, False: {false_length}b",
                    markers=[],
                    context={
                        'baseline_length': baseline_length,
                        'true_length': true_length,
                        'false_length': false_length,
                        'similarity_diff': abs(baseline_similarity - false_similarity)
                    }
                )
            
            return None
            
        except Exception as e:
            logger.debug(f"Boolean SQLi verification error for {url}: {e}")
            return None
    
    async def verify_sqli_timing(self, url: str, param: str,
                               session: aiohttp.ClientSession) -> Optional[Evidence]:
        """
        Deterministic time-based SQL injection verification.
        """
        try:
            # Get baseline timing
            baseline_time = await self._measure_response_time(url, session)
            if baseline_time is None:
                return None
            
            # Test time delay payloads
            delay_seconds = 5
            payloads = [
                f"' AND (SELECT SLEEP({delay_seconds}))--",  # MySQL
                f"'; SELECT pg_sleep({delay_seconds})--",    # PostgreSQL
                f"'; WAITFOR DELAY '00:00:0{delay_seconds}'--",  # MSSQL
            ]
            
            for payload in payloads:
                test_url = self._inject_parameter(url, param, payload)
                response_time = await self._measure_response_time(test_url, session)
                
                if response_time and response_time > (baseline_time + delay_seconds - 1):
                    confidence = min(0.9, 0.5 + (response_time - baseline_time) / 10)
                    
                    return Evidence(
                        type='timing',
                        confidence=confidence,
                        details=f"Time-based SQLi: {response_time:.2f}s delay (baseline: {baseline_time:.2f}s)",
                        raw_data=f"Payload: {payload}",
                        markers=[],
                        context={
                            'baseline_time': baseline_time,
                            'delayed_time': response_time,
                            'delay_seconds': delay_seconds,
                            'payload': payload
                        }
                    )
            
            return None
            
        except Exception as e:
            logger.debug(f"Timing SQLi verification error for {url}: {e}")
            return None
    
    async def verify_ssrf(self, url: str, param: str, callback_url: str,
                        session: aiohttp.ClientSession) -> Optional[Evidence]:
        """
        Deterministic SSRF verification using callback validation.
        """
        try:
            # Test internal/metadata URLs
            internal_urls = [
                "http://127.0.0.1/",
                "http://localhost/",
                "http://169.254.169.254/latest/meta-data/",  # AWS
                "http://metadata.google.internal/computeMetadata/v1/",  # GCP
            ]
            
            for internal_url in internal_urls:
                test_url = self._inject_parameter(url, param, internal_url)
                
                async with session.get(test_url, timeout=self.session_timeout) as response:
                    content = await response.text()
                    
                    # Check for internal service responses
                    internal_indicators = [
                        'ami-id',  # AWS metadata
                        'instance-id',  # AWS metadata  
                        'computeMetadata',  # GCP metadata
                        'X-Forwarded-For',  # Internal service headers
                        'Private-Token',  # Internal APIs
                        'localhost',
                        '127.0.0.1'
                    ]
                    
                    matches = sum(1 for indicator in internal_indicators 
                                if indicator.lower() in content.lower())
                    
                    if matches > 0:
                        confidence = min(0.9, 0.4 + matches * 0.2)
                        
                        return Evidence(
                            type='ssrf_internal',
                            confidence=confidence,
                            details=f"SSRF to internal service: {matches} indicators found",
                            raw_data=content[:1000],
                            markers=[],
                            context={
                                'target_url': internal_url,
                                'indicators_found': matches,
                                'response_length': len(content)
                            }
                        )
            
            # Test callback URL if provided
            if callback_url:
                test_url = self._inject_parameter(url, param, callback_url)
                
                async with session.get(test_url, timeout=self.session_timeout) as response:
                    # The actual callback verification would be done externally
                    # This just confirms the request was made
                    return Evidence(
                        type='ssrf_callback',
                        confidence=0.6,  # Pending external verification
                        details=f"SSRF callback request initiated",
                        raw_data=f"Target: {callback_url}",
                        markers=[],
                        context={'callback_url': callback_url, 'pending_verification': True}
                    )
            
            return None
            
        except Exception as e:
            logger.debug(f"SSRF verification error for {url}: {e}")
            return None
    
    async def verify_open_redirect(self, url: str, param: str, 
                                 session: aiohttp.ClientSession) -> Optional[Evidence]:
        """
        Deterministic open redirect verification.
        """
        try:
            # Test redirect payloads
            redirect_targets = [
                "http://evil.example.com",
                "//evil.example.com",
                "https://evil.example.com",
                "javascript:alert('redirect')",
            ]
            
            for target in redirect_targets:
                test_url = self._inject_parameter(url, param, target)
                
                async with session.get(test_url, allow_redirects=False, 
                                     timeout=self.session_timeout) as response:
                    
                    # Check for redirect status codes
                    if response.status in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        
                        # Validate if redirect goes to our target
                        if self._is_dangerous_redirect(location, target):
                            confidence = 0.9 if location == target else 0.7
                            
                            return Evidence(
                                type='redirect',
                                confidence=confidence,
                                details=f"Open redirect to: {location}",
                                raw_data=f"Status: {response.status}, Location: {location}",
                                markers=[],
                                context={
                                    'redirect_status': response.status,
                                    'redirect_location': location,
                                    'target_payload': target
                                }
                            )
            
            return None
            
        except Exception as e:
            logger.debug(f"Open redirect verification error for {url}: {e}")
            return None
    
    async def verify_idor(self, url: str, param: str, session1: aiohttp.ClientSession,
                        session2: aiohttp.ClientSession, user1_value: str, 
                        user2_value: str) -> Optional[Evidence]:
        """
        Deterministic IDOR verification using two-session differential analysis.
        """
        try:
            # Get user1's resource with session1
            user1_url = self._inject_parameter(url, param, user1_value)
            async with session1.get(user1_url, timeout=self.session_timeout) as response:
                user1_content = await response.text()
                user1_status = response.status
            
            # Try to access user1's resource with session2
            async with session2.get(user1_url, timeout=self.session_timeout) as response:
                cross_access_content = await response.text()
                cross_access_status = response.status
            
            # Get user2's resource with session2 for comparison
            user2_url = self._inject_parameter(url, param, user2_value)
            async with session2.get(user2_url, timeout=self.session_timeout) as response:
                user2_content = await response.text()
                user2_status = response.status
            
            # Analyze access patterns
            if (cross_access_status == 200 and user1_status == 200 and
                len(cross_access_content) > 100 and  # Not empty/error page
                self._content_similarity(user1_content, cross_access_content) > 0.8):
                
                confidence = 0.85
                
                return Evidence(
                    type='idor_access',
                    confidence=confidence,
                    details=f"IDOR: Session2 accessed User1 resource",
                    raw_data=f"Cross-access response length: {len(cross_access_content)}",
                    markers=[],
                    context={
                        'user1_value': user1_value,
                        'user2_value': user2_value,
                        'cross_access_status': cross_access_status,
                        'content_similarity': self._content_similarity(user1_content, cross_access_content),
                        'response_lengths': {
                            'user1': len(user1_content),
                            'user2': len(user2_content),
                            'cross_access': len(cross_access_content)
                        }
                    }
                )
            
            return None
            
        except Exception as e:
            logger.debug(f"IDOR verification error for {url}: {e}")
            return None
    
    # Helper methods
    
    def _inject_parameter(self, url: str, param: str, value: str) -> str:
        """Inject parameter value into URL while preserving existing parameters"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        
        # Inject/replace the target parameter
        query_params[param] = [value]
        
        # For DVWA and similar apps, ensure Submit parameter exists
        if 'Submit' not in query_params and 'submit' not in query_params:
            query_params['Submit'] = ['Submit']
        
        new_query = urlencode(query_params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
    
    def _analyze_xss_context(self, content: str, marker: str) -> Dict[str, Any]:
        """Analyze XSS reflection context"""
        context = {'location': 'unknown', 'dangerous': False}
        
        # Find marker in content
        marker_pos = content.find(marker)
        if marker_pos == -1:
            return context
        
        # Get surrounding context (50 chars before/after)
        start = max(0, marker_pos - 50)
        end = min(len(content), marker_pos + len(marker) + 50)
        surrounding = content[start:end]
        
        # Analyze context
        if re.search(r'<script[^>]*>' + re.escape(marker), content, re.IGNORECASE):
            context = {'location': 'script_tag', 'dangerous': True}
        elif re.search(r'on\w+\s*=\s*["\']?[^"\']*' + re.escape(marker), content, re.IGNORECASE):
            context = {'location': 'event_handler', 'dangerous': True}
        elif re.search(r'javascript:[^"\']*' + re.escape(marker), content, re.IGNORECASE):
            context = {'location': 'javascript_url', 'dangerous': True}
        elif re.search(r'<[^>]*\s+[^>]*' + re.escape(marker), content, re.IGNORECASE):
            context = {'location': 'html_attribute', 'dangerous': False}
        elif re.search(r'>[^<]*' + re.escape(marker) + '[^<]*<', content, re.IGNORECASE):
            context = {'location': 'html_content', 'dangerous': True}
        else:
            context = {'location': 'other', 'dangerous': False}
        
        context['surrounding'] = surrounding
        return context
    
    def _calculate_xss_confidence(self, context: Dict[str, Any], headers: Dict[str, str]) -> float:
        """Calculate XSS confidence based on context and headers"""
        base_confidence = 0.8 if context.get('dangerous', False) else 0.4
        
        # CSP header reduces confidence
        csp = headers.get('Content-Security-Policy', '').lower()
        if csp and ("'unsafe-inline'" not in csp or "'none'" in csp):
            base_confidence *= 0.6  # CSP protection present
        
        # X-XSS-Protection header
        xss_protection = headers.get('X-XSS-Protection', '').lower()
        if xss_protection and '0' not in xss_protection:
            base_confidence *= 0.8  # XSS filter enabled
        
        return min(1.0, base_confidence)
    
    async def _get_baseline_response(self, url: str, session: aiohttp.ClientSession) -> Optional[Tuple[str, int]]:
        """Get baseline response for comparison"""
        try:
            async with session.get(url, timeout=self.session_timeout) as response:
                content = await response.text()
                return content, len(content)
        except:
            return None
    
    def _content_similarity(self, content1: str, content2: str) -> float:
        """Calculate content similarity using simple ratio"""
        if not content1 or not content2:
            return 0.0
        
        # Simple character-based similarity
        len1, len2 = len(content1), len(content2)
        max_len = max(len1, len2)
        if max_len == 0:
            return 1.0
        
        # Count common characters (simple approach)
        common = sum(1 for c1, c2 in zip(content1[:1000], content2[:1000]) if c1 == c2)
        return common / min(len1, len2, 1000)
    
    async def _measure_response_time(self, url: str, session: aiohttp.ClientSession) -> Optional[float]:
        """Measure response time for timing attacks"""
        try:
            start_time = time.time()
            async with session.get(url, timeout=self.session_timeout) as response:
                await response.text()  # Ensure full response is received
            end_time = time.time()
            return end_time - start_time
        except:
            return None
    
    def _is_dangerous_redirect(self, location: str, target: str) -> bool:
        """Check if redirect is dangerous/external"""
        if not location:
            return False
        
        # Check for exact match
        if location == target:
            return True
        
        # Check for dangerous schemes
        dangerous_schemes = ['javascript:', 'data:', 'vbscript:']
        if any(location.lower().startswith(scheme) for scheme in dangerous_schemes):
            return True
        
        # Check for external domains
        try:
            from urllib.parse import urlparse
            parsed = urlparse(location)
            if parsed.netloc and parsed.netloc not in ['localhost', '127.0.0.1']:
                return True
        except:
            pass
        
        return False

# Global instance
verifiers = DeterministicVerifiers()

# Export main verification functions
async def verify_xss(url: str, param: str, payload: str, session: aiohttp.ClientSession) -> Optional[Evidence]:
    """Verify XSS vulnerability deterministically"""
    return await verifiers.verify_xss_reflected(url, param, payload, session)

async def verify_sqli(url: str, param: str, payload: str, session: aiohttp.ClientSession) -> Optional[Evidence]:
    """Verify SQL injection deterministically"""
    # Try error-based first (fastest)
    evidence = await verifiers.verify_sqli_error(url, param, payload, session)
    if evidence:
        return evidence
    
    # Try boolean-based
    evidence = await verifiers.verify_sqli_boolean(url, param, session)
    if evidence:
        return evidence
    
    # Try timing-based (slowest)
    return await verifiers.verify_sqli_timing(url, param, session)

async def verify_ssrf(url: str, param: str, callback_url: str, session: aiohttp.ClientSession) -> Optional[Evidence]:
    """Verify SSRF vulnerability deterministically"""
    return await verifiers.verify_ssrf(url, param, callback_url, session)

async def verify_open_redirect(url: str, param: str, session: aiohttp.ClientSession) -> Optional[Evidence]:
    """Verify open redirect vulnerability deterministically"""
    return await verifiers.verify_open_redirect(url, param, session)

async def verify_idor(url: str, param: str, session1: aiohttp.ClientSession, 
                     session2: aiohttp.ClientSession, user1_value: str, 
                     user2_value: str) -> Optional[Evidence]:
    """Verify IDOR vulnerability deterministically"""
    return await verifiers.verify_idor(url, param, session1, session2, user1_value, user2_value)