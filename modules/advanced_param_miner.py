#!/usr/bin/env python3
"""
Advanced Parameter Mining Module
Based on PortSwigger param-miner techniques for comprehensive parameter discovery.
"""

import asyncio
import logging
import time
import re
from typing import List, Dict, Set, Tuple, Optional
from urllib.parse import urlparse, urlencode, parse_qs
import aiohttp

logger = logging.getLogger(__name__)

class AdvancedParamMiner:
    def __init__(self, asset_manager, config):
        self.asset_manager = asset_manager
        self.config = config
        
        # Comprehensive parameter wordlists
        self.param_wordlist = self._load_comprehensive_params()
        
        # Detection thresholds
        self.response_time_threshold = 0.5  # seconds
        self.content_length_threshold = 100  # bytes
        self.reflection_confidence = 0.8
        
    def _load_comprehensive_params(self) -> List[str]:
        """Load comprehensive parameter wordlist based on param-miner techniques."""
        
        # Core web parameters
        web_params = [
            'id', 'page', 'search', 'query', 'q', 'name', 'user', 'username', 'email',
            'password', 'pass', 'token', 'key', 'api_key', 'auth', 'authorization',
            'session', 'sessionid', 'sid', 'csrf', 'xsrf', 'nonce', 'state',
            'callback', 'jsonp', 'format', 'type', 'action', 'method', 'cmd', 'exec'
        ]
        
        # HTTP method override parameters
        method_params = [
            '_method', 'method', 'X-HTTP-Method-Override', 'X-HTTP-Method',
            'X-Method-Override', '_httpmethod'
        ]
        
        # JavaScript/AJAX parameters
        js_params = [
            'data', 'json', 'ajax', 'xhr', 'async', 'sync', 'post', 'get',
            'message', 'msg', 'text', 'content', 'body', 'payload', 'input',
            'value', 'param', 'parameter', 'arg', 'argument', 'var', 'variable'
        ]
        
        # Framework-specific parameters
        framework_params = [
            # Laravel/Symfony
            '_token', '_method', 'csrf_token', 'authenticity_token',
            # ASP.NET
            '__VIEWSTATE', '__VIEWSTATEGENERATOR', '__EVENTVALIDATION', '__DOPOSTBACK',
            # JSF
            'javax.faces.ViewState', 'javax.faces.source',
            # Spring
            'spring-security-redirect', '_csrf',
            # WordPress
            'action', 'nonce', 'wp_nonce', '_wpnonce',
            # Drupal
            'form_id', 'form_token', 'form_build_id'
        ]
        
        # Cache busting and debugging
        cache_params = [
            'cache', 'nocache', 'timestamp', 'ts', 'time', 'debug', 'dev',
            'test', 'version', 'v', 'rev', 'build', 'hash', 'checksum'
        ]
        
        # Redirect and URL parameters
        url_params = [
            'redirect', 'return', 'returnUrl', 'url', 'link', 'href', 'src',
            'next', 'continue', 'goto', 'target', 'destination', 'forward',
            'back', 'ref', 'referer', 'referrer', 'origin'
        ]
        
        # File and path parameters
        file_params = [
            'file', 'path', 'dir', 'directory', 'folder', 'filename', 'filepath',
            'include', 'require', 'template', 'view', 'page', 'module', 'plugin',
            'component', 'widget', 'resource', 'asset', 'upload', 'download'
        ]
        
        all_params = (web_params + method_params + js_params + framework_params + 
                     cache_params + url_params + file_params)
        
        return list(set(all_params))  # Remove duplicates
    
    async def mine_parameters(self, url: str, session: aiohttp.ClientSession) -> Dict[str, List[str]]:
        """
        Comprehensive parameter mining using multiple techniques.
        Returns dict with parameter types as keys and lists of found parameters.
        """
        results = {
            'query_params': [],
            'body_params': [],  
            'header_params': [],
            'js_params': [],
            'fragment_params': [],
            'cache_params': []
        }
        
        # Run all mining techniques concurrently
        tasks = [
            self._mine_query_parameters(url, session),
            self._mine_body_parameters(url, session), 
            self._mine_header_parameters(url, session),
            self._mine_javascript_parameters(url, session),
            self._mine_fragment_parameters(url, session),
            self._mine_cache_parameters(url, session)
        ]
        
        mining_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Combine results
        param_types = ['query_params', 'body_params', 'header_params', 
                      'js_params', 'fragment_params', 'cache_params']
        
        for i, result in enumerate(mining_results):
            if isinstance(result, Exception):
                logger.debug(f"Parameter mining task {i} failed: {result}")
                continue
            if result and isinstance(result, list):
                results[param_types[i]] = result
                
        return results
    
    async def _mine_query_parameters(self, url: str, session: aiohttp.ClientSession) -> List[str]:
        """Mine GET/query parameters using response differential analysis."""
        found_params = []
        
        try:
            # Get baseline response
            baseline_response = await self._get_response_fingerprint(url, session)
            if not baseline_response:
                return found_params
                
            # Test parameters with various techniques
            for param in self.param_wordlist[:100]:  # Limit for performance
                test_url = f"{url}{'&' if '?' in url else '?'}{param}=test_value_123"
                
                test_response = await self._get_response_fingerprint(test_url, session)
                if not test_response:
                    continue
                    
                # Check for significant differences
                if self._is_significant_difference(baseline_response, test_response):
                    found_params.append(param)
                    logger.info(f"🔍 Found query parameter: {param}")
                    
        except Exception as e:
            logger.debug(f"Query parameter mining failed: {e}")
            
        return found_params
    
    async def _mine_body_parameters(self, url: str, session: aiohttp.ClientSession) -> List[str]:
        """Mine POST/body parameters."""
        found_params = []
        
        try:
            # Get baseline POST response
            baseline_response = await self._get_response_fingerprint(url, session, method='POST')
            if not baseline_response:
                return found_params
                
            for param in self.param_wordlist[:50]:  # Smaller set for POST
                post_data = {param: 'test_value_123'}
                
                test_response = await self._get_response_fingerprint(
                    url, session, method='POST', data=post_data
                )
                if not test_response:
                    continue
                    
                if self._is_significant_difference(baseline_response, test_response):
                    found_params.append(param)
                    logger.info(f"🔍 Found body parameter: {param}")
                    
        except Exception as e:
            logger.debug(f"Body parameter mining failed: {e}")
            
        return found_params
    
    async def _mine_header_parameters(self, url: str, session: aiohttp.ClientSession) -> List[str]:
        """Mine header-based parameters (common in APIs)."""
        found_params = []
        
        header_params = [
            'X-Custom-Param', 'X-API-Key', 'X-Token', 'X-Auth-Token',
            'X-Request-ID', 'X-Session-ID', 'X-User-ID', 'X-Client-ID',
            'Authorization', 'Authentication', 'Bearer', 'Token'
        ]
        
        try:
            baseline_response = await self._get_response_fingerprint(url, session)
            if not baseline_response:
                return found_params
                
            for param in header_params:
                headers = {param: 'test_value_123'}
                
                test_response = await self._get_response_fingerprint(
                    url, session, extra_headers=headers
                )
                if not test_response:
                    continue
                    
                if self._is_significant_difference(baseline_response, test_response):
                    found_params.append(param)
                    logger.info(f"🔍 Found header parameter: {param}")
                    
        except Exception as e:
            logger.debug(f"Header parameter mining failed: {e}")
            
        return found_params
    
    async def _mine_javascript_parameters(self, url: str, session: aiohttp.ClientSession) -> List[str]:
        """Extract parameters from JavaScript code analysis."""
        found_params = []
        
        try:
            async with session.get(url, timeout=10) as response:
                html = await response.text()
                
            # Enhanced JavaScript parameter extraction patterns
            patterns = [
                # URL parameter parsing
                r'getParameter[s]?\([\'"](\w+)[\'"]',
                r'searchParams\.get\([\'"](\w+)[\'"]',
                r'URLSearchParams.*[\'"](\w+)[\'"]',
                
                # Form and input processing
                r'name\s*=\s*[\'"](\w+)[\'"]',
                r'getElementById\([\'"](\w+)[\'"]',
                r'querySelector.*[\'"](\w+)[\'"]',
                
                # AJAX and API calls
                r'data\s*:\s*{[^}]*[\'"](\w+)[\'"]',
                r'post\s*\([^,]*,\s*{[^}]*[\'"](\w+)[\'"]',
                r'ajax.*data.*[\'"](\w+)[\'"]',
                
                # Variable assignments that might be parameters
                r'var\s+(\w+)\s*=.*(?:query|param|search|input)',
                r'let\s+(\w+)\s*=.*(?:query|param|search|input)',
                r'const\s+(\w+)\s*=.*(?:query|param|search|input)',
                
                # Hash/fragment processing
                r'location\.hash.*[\'"](\w+)[\'"]',
                r'window\.location\.hash.*[\'"](\w+)[\'"]',
                
                # Common JavaScript frameworks
                r'this\.(\w+)\s*=.*(?:params|query|search)',
                r'props\.(\w+)',
                r'state\.(\w+)',
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, html, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    if (match.isalpha() and len(match) <= 30 and 
                        match not in ['var', 'let', 'const', 'function', 'class']):
                        found_params.append(match)
                        
            # Remove duplicates and filter
            found_params = list(set(found_params))
            if found_params:
                logger.info(f"🔍 Found {len(found_params)} JavaScript parameters")
                
        except Exception as e:
            logger.debug(f"JavaScript parameter mining failed: {e}")
            
        return found_params
    
    async def _mine_fragment_parameters(self, url: str, session: aiohttp.ClientSession) -> List[str]:
        """Mine parameters that might be processed in URL fragments."""
        # URL fragments are client-side only, so extract from JS analysis
        return await self._extract_fragment_params_from_js(url, session)
    
    async def _mine_cache_parameters(self, url: str, session: aiohttp.ClientSession) -> List[str]:
        """Mine parameters using cache poisoning techniques."""
        found_params = []
        
        cache_test_params = ['utm_source', 'utm_medium', 'fbclid', 'gclid', 'cb', 'cache_bust']
        
        try:
            for param in cache_test_params:
                # Test with cache-busting parameter
                test_url = f"{url}{'&' if '?' in url else '?'}{param}={int(time.time())}"
                
                # Make multiple requests to check for caching behavior
                responses = []
                for _ in range(3):
                    try:
                        async with session.get(test_url, timeout=5) as resp:
                            responses.append({
                                'status': resp.status,
                                'headers': dict(resp.headers),
                                'length': len(await resp.text())
                            })
                    except:
                        continue
                        
                # Check for cache-related differences
                if self._has_cache_behavior(responses):
                    found_params.append(param)
                    logger.info(f"🔍 Found cache parameter: {param}")
                    
        except Exception as e:
            logger.debug(f"Cache parameter mining failed: {e}")
            
        return found_params
    
    async def _get_response_fingerprint(self, url: str, session: aiohttp.ClientSession, 
                                      method: str = 'GET', data: Dict = None, 
                                      extra_headers: Dict = None) -> Optional[Dict]:
        """Get a comprehensive response fingerprint for comparison."""
        try:
            headers = {'User-Agent': 'ModScan/1.0'}
            if extra_headers:
                headers.update(extra_headers)
                
            start_time = time.time()
            
            if method == 'POST':
                async with session.post(url, data=data, headers=headers, timeout=10) as resp:
                    content = await resp.text()
                    response_time = time.time() - start_time
                    
                    return {
                        'status_code': resp.status,
                        'content_length': len(content),
                        'response_time': response_time,
                        'headers': dict(resp.headers),
                        'content_hash': hash(content[:1000]),  # First 1K chars
                        'title': self._extract_title(content),
                        'forms': self._count_forms(content),
                        'scripts': content.count('<script'),
                        'errors': self._detect_errors(content)
                    }
            else:
                async with session.get(url, headers=headers, timeout=10) as resp:
                    content = await resp.text()
                    response_time = time.time() - start_time
                    
                    return {
                        'status_code': resp.status,
                        'content_length': len(content),
                        'response_time': response_time,
                        'headers': dict(resp.headers),
                        'content_hash': hash(content[:1000]),
                        'title': self._extract_title(content),
                        'forms': self._count_forms(content),
                        'scripts': content.count('<script'),
                        'errors': self._detect_errors(content)
                    }
                    
        except Exception as e:
            logger.debug(f"Failed to get response fingerprint: {e}")
            return None
    
    def _is_significant_difference(self, baseline: Dict, test: Dict) -> bool:
        """Determine if response differences indicate parameter recognition."""
        if not baseline or not test:
            return False
            
        # Status code changes
        if baseline['status_code'] != test['status_code']:
            return True
            
        # Significant content length differences
        length_diff = abs(baseline['content_length'] - test['content_length'])
        if length_diff > self.content_length_threshold:
            return True
            
        # Response time differences (possible backend processing)
        time_diff = abs(baseline['response_time'] - test['response_time'])
        if time_diff > self.response_time_threshold:
            return True
            
        # Content hash differences (content changes)
        if baseline['content_hash'] != test['content_hash']:
            return True
            
        # Form count changes (dynamic form generation)
        if baseline['forms'] != test['forms']:
            return True
            
        # Error detection differences
        if baseline['errors'] != test['errors']:
            return True
            
        return False
    
    def _extract_title(self, content: str) -> str:
        """Extract page title for comparison."""
        try:
            match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
            return match.group(1).strip() if match else ''
        except:
            return ''
    
    def _count_forms(self, content: str) -> int:
        """Count forms in content."""
        return content.lower().count('<form')
    
    def _detect_errors(self, content: str) -> int:
        """Detect error messages that might indicate parameter processing."""
        error_patterns = [
            'error', 'exception', 'warning', 'invalid', 'missing', 'required',
            'not found', '404', '500', 'syntax error', 'parse error'
        ]
        
        content_lower = content.lower()
        return sum(1 for pattern in error_patterns if pattern in content_lower)
    
    def _has_cache_behavior(self, responses: List[Dict]) -> bool:
        """Check if responses show caching behavior."""
        if len(responses) < 2:
            return False
            
        # Check for cache-related headers
        cache_headers = ['cache-control', 'expires', 'etag', 'last-modified']
        for resp in responses:
            headers = resp.get('headers', {})
            if any(header in headers for header in cache_headers):
                return True
                
        return False
    
    async def _extract_fragment_params_from_js(self, url: str, session: aiohttp.ClientSession) -> List[str]:
        """Extract parameters from JavaScript hash/fragment processing."""
        found_params = []
        
        try:
            async with session.get(url, timeout=10) as response:
                html = await response.text()
                
            # Fragment-specific patterns
            fragment_patterns = [
                r'location\.hash\.substring\(1\)',
                r'window\.location\.hash',
                r'#(\w+)=',
                r'fragment.*[\'"](\w+)[\'"]',
                r'hash.*[\'"](\w+)[\'"]',
            ]
            
            for pattern in fragment_patterns:
                matches = re.findall(pattern, html, re.IGNORECASE)
                found_params.extend(matches)
                
        except Exception as e:
            logger.debug(f"Fragment parameter extraction failed: {e}")
            
        return list(set(found_params))