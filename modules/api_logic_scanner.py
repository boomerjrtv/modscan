from pathlib import Path
import random
import requests
#!/usr/bin/env python3
"""
Enhanced API Logic Scanner - Surpasses XBOW with advanced IDOR, BOLA, and business logic testing
Implements canary-based validation and deterministic evidence collection
"""

import asyncio
import time
import uuid
import hashlib
import json
import re
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
import aiohttp
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

class APILogicScanner:
    
    # --- WAF-aware HTTP helper ---
    def _safe_get(self, url: str, timeout: int = 15, attempts: int = 6, allow_headless: bool = True):
        """Browser-like GET with proxy rotation + headless fallback.
        Returns (status, final_url, headers, text, via). Uses proxy_list in config.json."""
        import json, time, random, re
        import requests
        from pathlib import Path

        # load proxies list from your existing config.json
        try:
            cfg = json.loads(Path("config.json").read_text())
            proxies = cfg.get("proxy_list", [])
        except Exception:
            proxies = []

        block_pats = [r"Sorry,\s+you have been blocked", r"/cdn-cgi/trace", r"/cdn-cgi/challenge",
                      r"Access Denied", r"PerimeterX", r"Attention Required! \| Cloudflare"]

        def looks_blocked(resp, text):
            if resp is not None and resp.status_code in (403, 429, 503):
                return True
            if resp is not None:
                svr = (resp.headers.get("server") or "").lower()
                if "cloudflare" in svr or "akamai" in svr:
                    return True
                if "cf-ray" in resp.headers or "cf-cache-status" in resp.headers:
                    return True
            text = (text or "")[:10000]
            return any(re.search(p, text, re.I) for p in block_pats)

        def pick_proxy(i):
            if not proxies:
                return {}, None
            p = proxies[i % len(proxies)]
            return {"http": p, "https": p}, p

        def random_headers():
            uas = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
            ]
            return {
                "User-Agent": random.choice(uas),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "Connection": "keep-alive",
            }

        sess = requests.Session()
        sess.headers.update(random_headers())
        last_exc = None

        for i in range(attempts):
            pmap, pname = pick_proxy(i)
            try:
                resp = sess.get(url, timeout=timeout, proxies=pmap, allow_redirects=True)
                txt = resp.text or ""
                if not looks_blocked(resp, txt) and resp.status_code < 500:
                    return resp.status_code, resp.url, dict(resp.headers), txt, f"requests:{pname or 'direct'}"
            except Exception as e:
                last_exc = e
            time.sleep(0.6 + random.random())
            sess.headers.update(random_headers())

        if allow_headless:
            try:
                from selenium import webdriver
                from selenium.webdriver.chrome.options import Options
                opts = Options()
                opts.add_argument("--headless=new"); opts.add_argument("--disable-gpu")
                opts.add_argument("--no-sandbox"); opts.add_argument("--disable-dev-shm-usage")
                opts.add_argument("--window-size=1366,1024")
                # use first proxy for headless if available
                if proxies:
                    opts.add_argument(f"--proxy-server={proxies[0]}")
                drv = webdriver.Chrome(options=opts)
                drv.set_page_load_timeout(25)
                drv.get(url)
                time.sleep(2.5)
                html = drv.page_source or ""
                drv.quit()
                if html:
                    return 200, url, {}, html, "headless"
            except Exception:
                pass

        raise RuntimeError(f"WAF blocked and headless failed for {url}; last={last_exc}")

class APILogicScanner:
    def __init__(self, asset_manager, config: Dict):
        self.asset_manager = asset_manager
        self.config = config
        self.allow_write_tests = config.get('allow_write_tests', False)
        self.timeout_s = config.get('timeout', 15.0)
        self.rate_limit = config.get('api_rate_limit', 8.0)
        self.auth_headers = config.get('auth_headers', {})
        self.max_concurrent = config.get('max_concurrent', 12)
        self._last_req_ts = 0.0

    async def run(self, target: str) -> List[Dict[str, Any]]:
        """Main API logic scanning entry point"""
        endpoints = await self._discover_api_endpoints(target)
        findings = []
        
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        # Scan each endpoint with multiple techniques
        tasks = []
        for endpoint in endpoints:
            tasks.append(self._comprehensive_api_scan(endpoint, semaphore))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                findings.extend(result)
        
        # Store findings and return
        self._store_findings(findings)
        return findings

    async def _discover_api_endpoints(self, target: str) -> List[Dict[str, Any]]:
        """Enhanced API endpoint discovery beyond XBOW"""
        endpoints = []
        base_url = target.rstrip('/')
        
        # Discovery methods
        discovery_sources = [
            self._discover_from_content(target),
            self._discover_openapi_specs(base_url),
            self._discover_common_patterns(base_url),
            self._discover_from_assets(target)
        ]
        
        # Execute discovery methods concurrently
        results = await asyncio.gather(*discovery_sources, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                endpoints.extend(result)
        
        # Deduplicate and validate
        unique_endpoints = []
        seen_urls = set()
        
        for endpoint in endpoints:
            url = endpoint.get('url', '')
            if url not in seen_urls and await self._is_valid_api_endpoint(url):
                seen_urls.add(url)
                unique_endpoints.append(endpoint)
        
        return unique_endpoints[:100]  # Limit to prevent overwhelming

    async def _discover_from_content(self, target: str) -> List[Dict[str, Any]]:
        """Discover API endpoints from page content"""
        endpoints = []
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                await self._throttle()
                async with session.get(target) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        
                        # API endpoint patterns
                        api_patterns = [
                            r'["\']([^"\']*api[^"\']*\/[^"\']*)["\']',
                            r'["\']([^"\']*\/v\d+\/[^"\']*)["\']',
                            r'["\']([^"\']*\/rest\/[^"\']*)["\']',
                            r'["\']([^"\']*\/json\/[^"\']*)["\']',
                            r'endpoint["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                            r'url["\']?\s*[:=]\s*["\']([^"\']*api[^"\']*)["\']'
                        ]
                        
                        for pattern in api_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            for match in matches:
                                if self._is_api_like_path(match):
                                    full_url = self._resolve_url(target, match)
                                    endpoints.append({
                                        'url': full_url,
                                        'method': 'GET',
                                        'source': 'content_discovery',
                                        'confidence': 0.7
                                    })
        except Exception:
            pass
        
        return endpoints

    async def _discover_openapi_specs(self, base_url: str) -> List[Dict[str, Any]]:
        """Discover endpoints from OpenAPI/Swagger specifications"""
        endpoints = []
        
        spec_paths = [
            '/swagger.json', '/swagger.yaml', '/swagger.yml',
            '/openapi.json', '/openapi.yaml', '/openapi.yml',
            '/api/swagger.json', '/api/openapi.json',
            '/docs/swagger.json', '/docs/openapi.json',
            '/v1/swagger.json', '/v2/swagger.json',
            '/api-docs', '/swagger-ui.html'
        ]
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            for spec_path in spec_paths:
                try:
                    spec_url = f"{base_url}{spec_path}"
                    await self._throttle()
                    
                    async with session.get(spec_url) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            
                            # Parse OpenAPI/Swagger spec
                            try:
                                spec_data = json.loads(content)
                                parsed_endpoints = self._parse_openapi_spec(spec_data, base_url)
                                endpoints.extend(parsed_endpoints)
                                break  # Found a spec, don't need to check others
                            except json.JSONDecodeError:
                                # Try YAML parsing if available
                                continue
                
                except Exception:
                    continue
        
        return endpoints

    async def _discover_common_patterns(self, base_url: str) -> List[Dict[str, Any]]:
        """Discover endpoints using common API patterns"""
        endpoints = []
        
        # Common API paths and patterns
        common_paths = [
            '/api/v1/users', '/api/v1/user', '/api/users', '/api/user',
            '/api/v1/admin', '/api/admin', '/api/v1/config', '/api/config',
            '/api/v1/status', '/api/status', '/api/health', '/api/info',
            '/api/v1/data', '/api/data', '/api/v1/items', '/api/items',
            '/rest/users', '/rest/user', '/rest/admin', '/rest/config',
            '/json/users', '/json/user', '/json/admin', '/json/config',
            '/v1/users', '/v2/users', '/users', '/user',
            '/admin/api/users', '/internal/api/users'
        ]
        
        # Test each path for existence and API characteristics
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            for path in common_paths:
                try:
                    test_url = f"{base_url}{path}"
                    if await self._test_endpoint_exists(session, test_url):
                        endpoints.append({
                            'url': test_url,
                            'method': 'GET',
                            'source': 'pattern_discovery',
                            'confidence': 0.8
                        })
                        
                        # Generate related endpoints
                        related = self._generate_related_endpoints(test_url)
                        endpoints.extend(related)
                
                except Exception:
                    continue
        
        return endpoints

    async def _discover_from_assets(self, target: str) -> List[Dict[str, Any]]:
        """Discover API endpoints from existing asset database"""
        endpoints = []
        
        try:
            # Get URLs from asset database that look like APIs
            with self.asset_manager._get_db() as db:
                cursor = db.execute("""
                    SELECT url, status_code FROM assets 
                    WHERE url LIKE '%api%' OR url LIKE '%rest%' OR url LIKE '%json%' 
                    OR url LIKE '%v1%' OR url LIKE '%v2%'
                    ORDER BY discovered_at DESC
                    LIMIT 50
                """)
                
                for row in cursor.fetchall():
                    url, status_code = row
                    if self._is_api_like_path(url) and status_code in [200, 201, 400, 401, 403]:
                        endpoints.append({
                            'url': url,
                            'method': 'GET',
                            'source': 'asset_database',
                            'confidence': 0.9
                        })
        
        except Exception:
            pass
        
        return endpoints

    async def _comprehensive_api_scan(self, endpoint: Dict[str, Any], semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """Comprehensive API logic testing beyond XBOW"""
        findings = []
        
        async with semaphore:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout_s)) as session:
                url = endpoint['url']
                
                # 1. IDOR Testing (Enhanced)
                idor_findings = await self._advanced_idor_testing(session, url)
                findings.extend(idor_findings)
                
                # 2. BOLA Testing (Broken Object Level Authorization)
                bola_findings = await self._bola_testing(session, url)
                findings.extend(bola_findings)
                
                # 3. HTTP Method Testing
                method_findings = await self._http_method_testing(session, url)
                findings.extend(method_findings)
                
                # 4. Parameter Pollution Testing
                pollution_findings = await self._parameter_pollution_testing(session, url)
                findings.extend(pollution_findings)
                
                # 5. Mass Assignment Testing (if write operations allowed)
                if self.allow_write_tests:
                    mass_assign_findings = await self._mass_assignment_testing(session, url)
                    findings.extend(mass_assign_findings)
                
                # 6. Business Logic Testing
                logic_findings = await self._business_logic_testing(session, url)
                findings.extend(logic_findings)
                
                # 7. Information Disclosure Testing
                info_findings = await self._information_disclosure_testing(session, url)
                findings.extend(info_findings)
        
        return findings

    async def _advanced_idor_testing(self, session: aiohttp.ClientSession, url: str) -> List[Dict[str, Any]]:
        """Advanced IDOR testing with multiple techniques"""
        findings = []
        
        # Extract numeric IDs from URL path and parameters
        id_locations = self._extract_id_locations(url)
        
        for location in id_locations:
            try:
                # Test sequential ID access
                sequential_finding = await self._test_sequential_idor(session, url, location)
                if sequential_finding:
                    findings.append(sequential_finding)
                
                # Test predictable ID patterns
                pattern_finding = await self._test_predictable_idor(session, url, location)
                if pattern_finding:
                    findings.append(pattern_finding)
                
                # Test UUID manipulation
                if self._looks_like_uuid(location['value']):
                    uuid_finding = await self._test_uuid_idor(session, url, location)
                    if uuid_finding:
                        findings.append(uuid_finding)
            
            except Exception:
                continue
        
        return findings

    async def _test_sequential_idor(self, session: aiohttp.ClientSession, url: str, id_location: Dict) -> Optional[Dict[str, Any]]:
        """Test for sequential IDOR vulnerabilities"""
        try:
            original_id = id_location['value']
            if not original_id.isdigit():
                return None
            
            # Get baseline response
            await self._throttle()
            async with session.get(url, headers=self.auth_headers) as baseline_resp:
                if baseline_resp.status != 200:
                    return None
                
                baseline_content = await baseline_resp.text()
                baseline_hash = hashlib.md5(baseline_content.encode()).hexdigest()
            
            # Test adjacent IDs
            test_ids = [str(int(original_id) + i) for i in [-2, -1, 1, 2]]
            
            for test_id in test_ids:
                test_url = url.replace(original_id, test_id, 1)
                
                await self._throttle()
                async with session.get(test_url, headers=self.auth_headers) as test_resp:
                    if test_resp.status == 200:
                        test_content = await test_resp.text()
                        test_hash = hashlib.md5(test_content.encode()).hexdigest()
                        
                        # Check if content is different (indicates different resource)
                        if test_hash != baseline_hash and len(test_content) > 100:
                            # Test without authentication to confirm IDOR
                            await self._throttle()
                            async with session.get(test_url, headers={}) as unauth_resp:
                                if unauth_resp.status == 200:
                                    return {
                                        "type": "api.idor.sequential",
                                        "endpoint": test_url,
                                        "severity": "high",
                                        "proof": f"Sequential IDOR: Accessed ID {test_id} (original: {original_id})",
                                        "original_id": original_id,
                                        "accessed_id": test_id,
                                        "auth_bypass": True,
                                        "confidence": 0.9
                                    }
                                else:
                                    return {
                                        "type": "api.idor.sequential",
                                        "endpoint": test_url,
                                        "severity": "medium",
                                        "proof": f"Sequential IDOR: Accessed ID {test_id} (original: {original_id}) with auth",
                                        "original_id": original_id,
                                        "accessed_id": test_id,
                                        "auth_bypass": False,
                                        "confidence": 0.7
                                    }
        
        except Exception:
            pass
        
        return None

    async def _bola_testing(self, session: aiohttp.ClientSession, url: str) -> List[Dict[str, Any]]:
        """Test for Broken Object Level Authorization (BOLA)"""
        findings = []
        
        # BOLA is essentially the same as IDOR but focuses on authorization context
        # Test with different user contexts if available
        
        if not self.auth_headers:
            return findings
        
        try:
            # Test the endpoint with authentication
            await self._throttle()
            async with session.get(url, headers=self.auth_headers) as auth_resp:
                if auth_resp.status != 200:
                    return findings
                
                auth_content = await auth_resp.text()
                
                # Test same endpoint without authentication
                await self._throttle()
                async with session.get(url, headers={}) as unauth_resp:
                    if unauth_resp.status == 200:
                        unauth_content = await unauth_resp.text()
                        
                        # If we get different but valid content, it might be BOLA
                        if (len(unauth_content) > 100 and 
                            abs(len(auth_content) - len(unauth_content)) / len(auth_content) < 0.5):
                            
                            findings.append({
                                "type": "api.bola.auth_bypass",
                                "endpoint": url,
                                "severity": "high",
                                "proof": "Endpoint accessible without authentication",
                                "auth_status": auth_resp.status,
                                "unauth_status": unauth_resp.status,
                                "confidence": 0.85
                            })
                
                # Test with modified/invalid authentication
                invalid_headers = dict(self.auth_headers)
                if 'Authorization' in invalid_headers:
                    invalid_headers['Authorization'] = invalid_headers['Authorization'] + 'invalid'
                elif 'X-API-Key' in invalid_headers:
                    invalid_headers['X-API-Key'] = invalid_headers['X-API-Key'] + 'invalid'
                
                if invalid_headers != self.auth_headers:
                    await self._throttle()
                    async with session.get(url, headers=invalid_headers) as invalid_resp:
                        if invalid_resp.status == 200:
                            findings.append({
                                "type": "api.bola.weak_auth",
                                "endpoint": url,
                                "severity": "medium",
                                "proof": "Endpoint accepts invalid/modified authentication",
                                "confidence": 0.7
                            })
        
        except Exception:
            pass
        
        return findings

    async def _http_method_testing(self, session: aiohttp.ClientSession, url: str) -> List[Dict[str, Any]]:
        """Test for HTTP method vulnerabilities"""
        findings = []
        
        methods_to_test = ['POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE']
        
        # Get baseline GET response
        try:
            await self._throttle()
            async with session.get(url, headers=self.auth_headers) as get_resp:
                get_status = get_resp.status
                get_content = await get_resp.text()
        except Exception:
            return findings
        
        for method in methods_to_test:
            try:
                await self._throttle()
                
                # Test each HTTP method
                async with session.request(method, url, headers=self.auth_headers) as resp:
                    if resp.status == 200 and method in ['PUT', 'DELETE', 'PATCH']:
                        # Dangerous methods should not return 200 on GET endpoints
                        findings.append({
                            "type": "api.method.dangerous_allowed",
                            "endpoint": url,
                            "severity": "medium",
                            "proof": f"Dangerous HTTP method {method} allowed on GET endpoint",
                            "method": method,
                            "status": resp.status,
                            "confidence": 0.8
                        })
                    
                    elif method == 'OPTIONS' and resp.status == 200:
                        # Check Allow header for dangerous methods
                        allow_header = resp.headers.get('Allow', '')
                        dangerous_methods = ['PUT', 'DELETE', 'PATCH']
                        
                        for dangerous in dangerous_methods:
                            if dangerous in allow_header:
                                findings.append({
                                    "type": "api.method.options_disclosure",
                                    "endpoint": url,
                                    "severity": "low",
                                    "proof": f"OPTIONS reveals dangerous method: {dangerous}",
                                    "allow_header": allow_header,
                                    "confidence": 0.6
                                })
                    
                    elif method == 'TRACE' and resp.status == 200:
                        # TRACE method can be used for XST attacks
                        findings.append({
                            "type": "api.method.trace_enabled",
                            "endpoint": url,
                            "severity": "low",
                            "proof": "TRACE method enabled (XST risk)",
                            "confidence": 0.7
                        })
            
            except Exception:
                continue
        
        return findings

    async def _mass_assignment_testing(self, session: aiohttp.ClientSession, url: str) -> List[Dict[str, Any]]:
        """Test for mass assignment vulnerabilities (requires write permission)"""
        findings = []
        
        if not self.allow_write_tests:
            return findings
        
        # Only test on POST/PUT endpoints or if we can identify create/update patterns
        if not any(pattern in url.lower() for pattern in ['create', 'update', 'edit', 'new']):
            return findings
        
        try:
            # Generate a unique canary value
            canary_field = f"test_canary_{uuid.uuid4().hex[:8]}"
            canary_value = f"canary_{uuid.uuid4().hex[:12]}"
            
            # Test POST with extra field
            test_data = {
                "name": "test",
                "value": "test",
                canary_field: canary_value
            }
            
            await self._throttle()
            async with session.post(
                url, 
                json=test_data,
                headers={**self.auth_headers, "Content-Type": "application/json"}
            ) as post_resp:
                
                if post_resp.status in [200, 201]:
                    # Try to retrieve the created object to see if canary was stored
                    response_data = await post_resp.json()
                    
                    # Check if canary appears in response
                    response_str = json.dumps(response_data).lower()
                    if canary_value.lower() in response_str:
                        findings.append({
                            "type": "api.mass_assignment.direct_reflection",
                            "endpoint": url,
                            "severity": "high",
                            "proof": f"Mass assignment: Canary field {canary_field} reflected in response",
                            "canary_field": canary_field,
                            "canary_value": canary_value,
                            "confidence": 0.95
                        })
                    
                    # Try to find a GET endpoint to check persistence
                    get_url = self._infer_get_endpoint(url, response_data)
                    if get_url:
                        await self._throttle()
                        async with session.get(get_url, headers=self.auth_headers) as get_resp:
                            if get_resp.status == 200:
                                get_data = await get_resp.text()
                                if canary_value.lower() in get_data.lower():
                                    findings.append({
                                        "type": "api.mass_assignment.persistent",
                                        "endpoint": url,
                                        "severity": "critical",
                                        "proof": f"Mass assignment: Canary persisted and retrievable via {get_url}",
                                        "canary_field": canary_field,
                                        "canary_value": canary_value,
                                        "get_endpoint": get_url,
                                        "confidence": 0.98
                                    })
        
        except Exception:
            pass
        
        return findings

    def _extract_id_locations(self, url: str) -> List[Dict[str, str]]:
        """Extract potential ID locations from URL"""
        locations = []
        
        # Check URL path for IDs
        path_parts = url.split('/')
        for i, part in enumerate(path_parts):
            if part.isdigit() or self._looks_like_uuid(part) or self._looks_like_hash(part):
                locations.append({
                    'type': 'path',
                    'position': i,
                    'value': part
                })
        
        # Check URL parameters for IDs
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param_name, param_values in params.items():
                for value in param_values:
                    if (value.isdigit() or self._looks_like_uuid(value) or 
                        param_name.lower() in ['id', 'user_id', 'userid', 'item_id']):
                        locations.append({
                            'type': 'parameter',
                            'name': param_name,
                            'value': value
                        })
        
        return locations

    def _looks_like_uuid(self, value: str) -> bool:
        """Check if string looks like a UUID"""
        uuid_pattern = r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        return bool(re.match(uuid_pattern, value))

    def _looks_like_hash(self, value: str) -> bool:
        """Check if string looks like a hash"""
        return len(value) >= 32 and all(c in '0123456789abcdefABCDEF' for c in value)

    def _is_api_like_path(self, path: str) -> bool:
        """Check if path looks like an API endpoint"""
        api_indicators = [
            '/api/', '/rest/', '/json/', '/v1/', '/v2/', '/v3/',
            'api.', '.json', 'graphql', 'admin/api'
        ]
        return any(indicator in path.lower() for indicator in api_indicators)

    def _resolve_url(self, base_url: str, path: str) -> str:
        """Resolve relative URL to absolute URL"""
        if path.startswith('http'):
            return path
        elif path.startswith('/'):
            parsed = urlparse(base_url)
            return f"{parsed.scheme}://{parsed.netloc}{path}"
        else:
            return f"{base_url.rstrip('/')}/{path}"

    async def _throttle(self):
        """Rate limiting mechanism"""
        delay = 1.0 / self.rate_limit
        now = time.time()
        since = now - self._last_req_ts
        if since < delay:
            await asyncio.sleep(delay - since)
        self._last_req_ts = time.time()

    def _store_findings(self, findings: List[Dict[str, Any]]):
        """Store API logic findings in database"""
        for finding in findings:
            try:
                with self.asset_manager._get_db() as db:
                    # Map severity to database format
                    severity_map = {"low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}
                    severity = severity_map.get(finding.get("severity", "medium"), "MEDIUM")
                    
                    # Find asset_id for the endpoint
                    cursor = db.execute("SELECT id FROM assets WHERE url = ? LIMIT 1", (finding.get("endpoint", ""),))
                    result = cursor.fetchone()
                    asset_id = result[0] if result else None
                    
                    db.execute('''
                        INSERT INTO vulnerabilities 
                        (asset_id, type, description, severity, evidence, payload, detected_at, confidence)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        asset_id,
                        finding.get("type", "API Logic Vulnerability"),
                        f"API Logic finding: {finding.get('type', 'Unknown')}",
                        severity,
                        finding.get("proof", ""),
                        json.dumps(finding, indent=2),
                        datetime.now().isoformat(),
                        finding.get("confidence", 0.8)
                    ))
                
                self.asset_manager.log_activity('API_LOGIC_FINDING', f"API Logic finding: {finding.get('type', 'Unknown')}")
                
            except Exception as e:
                print(f"Error storing API logic finding: {e}")

    # Additional helper methods for completeness
    async def _parameter_pollution_testing(self, session: aiohttp.ClientSession, url: str) -> List[Dict[str, Any]]:
        """Test for HTTP parameter pollution"""
        findings = []
        
        parsed = urlparse(url)
        if not parsed.query:
            return findings
        
        # Test parameter duplication
        params = parse_qs(parsed.query)
        for param_name, param_values in params.items():
            if len(param_values) == 1:
                # Create polluted URL
                polluted_params = dict(params)
                polluted_params[param_name] = [param_values[0], 'polluted_value']
                
                polluted_query = urlencode(polluted_params, doseq=True)
                polluted_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, polluted_query, parsed.fragment))
                
                try:
                    await self._throttle()
                    async with session.get(polluted_url, headers=self.auth_headers) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            if 'polluted_value' in content:
                                findings.append({
                                    "type": "api.parameter_pollution",
                                    "endpoint": polluted_url,
                                    "severity": "medium",
                                    "proof": f"Parameter {param_name} accepts multiple values",
                                    "parameter": param_name,
                                    "confidence": 0.7
                                })
                except Exception:
                    continue
        
        return findings

    async def _business_logic_testing(self, session: aiohttp.ClientSession, url: str) -> List[Dict[str, Any]]:
        """Test for business logic vulnerabilities"""
        findings = []
        
        # Test for rate limiting
        try:
            request_times = []
            for _ in range(5):
                start_time = time.time()
                await self._throttle()
                async with session.get(url, headers=self.auth_headers) as resp:
                    request_times.append(time.time() - start_time)
                    if resp.status != 200:
                        break
            
            if len(request_times) == 5 and all(t < 1.0 for t in request_times):
                findings.append({
                    "type": "api.business_logic.no_rate_limit",
                    "endpoint": url,
                    "severity": "low",
                    "proof": f"No rate limiting detected - 5 requests in {sum(request_times):.2f} seconds",
                    "confidence": 0.6
                })
        
        except Exception:
            pass
        
        return findings

    async def _information_disclosure_testing(self, session: aiohttp.ClientSession, url: str) -> List[Dict[str, Any]]:
        """Test for information disclosure in API responses"""
        findings = []
        
        try:
            await self._throttle()
            async with session.get(url, headers=self.auth_headers) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    
                    # Check for sensitive information patterns
                    sensitive_patterns = {
                        'password': r'password["\']?\s*[:=]\s*["\'][^"\']{3,}["\']',
                        'api_key': r'api[_-]?key["\']?\s*[:=]\s*["\'][^"\']{10,}["\']',
                        'secret': r'secret["\']?\s*[:=]\s*["\'][^"\']{10,}["\']',
                        'token': r'token["\']?\s*[:=]\s*["\'][^"\']{10,}["\']',
                        'private_key': r'private[_-]?key["\']?\s*[:=]\s*["\'][^"\']{20,}["\']',
                        'database': r'database["\']?\s*[:=]\s*["\'][^"\']+["\']',
                        'internal_ip': r'\b(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.)\d{1,3}\.\d{1,3}\.\d{1,3}\b'
                    }
                    
                    for info_type, pattern in sensitive_patterns.items():
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            findings.append({
                                "type": "api.information_disclosure",
                                "endpoint": url,
                                "severity": "medium" if info_type in ['password', 'api_key', 'secret'] else "low",
                                "proof": f"Sensitive {info_type} disclosed in response: {matches[0][:50]}...",
                                "info_type": info_type,
                                "confidence": 0.8
                            })
                            break  # Don't spam with multiple disclosure types
        
        except Exception:
            pass
        
        return findings

    # Placeholder methods for additional functionality
    async def _test_predictable_idor(self, session: aiohttp.ClientSession, url: str, location: Dict) -> Optional[Dict[str, Any]]:
        """Test for predictable IDOR patterns"""
        # Implementation would test common ID patterns like timestamps, encoded values, etc.
        return None
    
    async def _test_uuid_idor(self, session: aiohttp.ClientSession, url: str, location: Dict) -> Optional[Dict[str, Any]]:
        """Test for UUID-based IDOR"""
        # Implementation would test UUID manipulation techniques
        return None
    
    async def _is_valid_api_endpoint(self, url: str) -> bool:
        """Validate if URL is a valid API endpoint"""
        # Basic validation - could be enhanced with actual requests
        return self._is_api_like_path(url)
    
    def _parse_openapi_spec(self, spec_data: Dict, base_url: str) -> List[Dict[str, Any]]:
        """Parse OpenAPI specification for endpoints"""
        endpoints = []
        
        try:
            paths = spec_data.get('paths', {})
            for path, methods in paths.items():
                for method, details in methods.items():
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                        endpoints.append({
                            'url': f"{base_url}{path}",
                            'method': method.upper(),
                            'source': 'openapi_spec',
                            'confidence': 0.95,
                            'spec_details': details
                        })
        except Exception:
            pass
        
        return endpoints
    
    async def _test_endpoint_exists(self, session: aiohttp.ClientSession, url: str) -> bool:
        """Test if endpoint exists and responds"""
        try:
            await self._throttle()
            async with session.head(url, headers=self.auth_headers) as resp:
                return resp.status < 500
        except Exception:
            return False
    
    def _generate_related_endpoints(self, url: str) -> List[Dict[str, Any]]:
        """Generate related endpoints based on discovered endpoint"""
        related = []
        
        # Generate plural/singular variations
        if url.endswith('/user'):
            related.append({'url': url + 's', 'method': 'GET', 'source': 'variation', 'confidence': 0.6})
        elif url.endswith('/users'):
            related.append({'url': url[:-1], 'method': 'GET', 'source': 'variation', 'confidence': 0.6})
        
        return related
    
    def _infer_get_endpoint(self, post_url: str, response_data: Dict) -> Optional[str]:
        """Infer GET endpoint from POST response"""
        try:
            # Look for ID in response to construct GET URL
            if 'id' in response_data:
                return f"{post_url}/{response_data['id']}"
            elif 'Id' in response_data:
                return f"{post_url}/{response_data['Id']}"
            elif 'ID' in response_data:
                return f"{post_url}/{response_data['ID']}"
        except Exception:
            pass
        
        return None