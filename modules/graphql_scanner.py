from pathlib import Path
import random
import requests
#!/usr/bin/env python3
"""
Enhanced GraphQL Scanner - Surpasses XBOW with advanced introspection and injection detection
Implements business logic testing, auth bypasses, and deep query analysis
"""

import asyncio
import json
import hashlib
import time
import re
from typing import Dict, Any, List, Optional, Tuple
import aiohttp
from datetime import datetime

DEFAULT_GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/graphiql", "/playground", "/_graphql", "/console",
    "/gql", "/api/gql", "/query", "/api/query",
    "/admin/graphql", "/internal/graphql", "/dev/graphql"
]

INTROSPECTION_QUERIES = {
    "basic": {"query": "query IntrospectionQuery{__schema{types{name}}}"},
    "full": {"query": "query IntrospectionQuery{__schema{queryType{name},mutationType{name},subscriptionType{name},types{...FullType}}}fragment FullType on __Type{kind,name,description,fields(includeDeprecated:true){name,description,args{...InputValue},type{...TypeRef},isDeprecated,deprecationReason},inputFields{...InputValue},interfaces{...TypeRef},enumValues(includeDeprecated:true){name,description,isDeprecated,deprecationReason},possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name,description,type{...TypeRef},defaultValue}fragment TypeRef on __Type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}}"},
    "types": {"query": "query{__schema{types{name,fields{name,type{name}}}}}"},
    "mutations": {"query": "query{__schema{mutationType{fields{name,args{name,type{name}}}}}}"},
    "directives": {"query": "query{__schema{directives{name,description,args{name,type{name}}}}}"}
}

INJECTION_PAYLOADS = {
    "query_depth": {"query": "query NestedQuery{__schema{types{fields{type{ofType{ofType{ofType{ofType{ofType{name}}}}}}}}}}"},
    "alias_overload": {"query": "query AliasOverload{" + ",".join([f"alias{i}:__schema{{types{{name}}}}" for i in range(100)]) + "}"},
    "field_duplication": {"query": "query{__schema{types{name name name name name name name name name name}}}"},
    "directive_injection": {"query": "query @deprecated{__schema{types{name @deprecated}}}"}
}

class GraphQLScanner:
    
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

class GraphQLScanner:
    def __init__(self, asset_manager, config: Dict):
        self.asset_manager = asset_manager
        self.config = config
        self.timeout_s = config.get('timeout', 20.0)
        self.rate_limit_per_host = config.get('rate_limit', 5.0)
        self.max_concurrent = config.get('max_concurrent', 15)
        self.auth_headers = config.get('auth_headers', {})
        self._last_req_ts = 0.0

    async def run(self, target: str) -> List[Dict[str, Any]]:
        """Main scanning entry point"""
        endpoints = await self._enhanced_discovery(target)
        findings = []
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        # Scan all discovered endpoints
        tasks = []
        for endpoint in endpoints:
            tasks.append(self._comprehensive_graphql_scan(endpoint, semaphore))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, Exception):
                findings.append({
                    "type": "scan_error",
                    "severity": "info", 
                    "error": str(result)
                })
        
        # Store findings
        self._store_findings(findings)
        return findings

    async def _enhanced_discovery(self, target: str) -> List[str]:
        """Enhanced GraphQL endpoint discovery beyond XBOW"""
        endpoints = set()
        base_url = target.rstrip('/')
        
        # Standard paths
        for path in DEFAULT_GRAPHQL_PATHS:
            endpoints.add(f"{base_url}{path}")
        
        # Content-based discovery
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                await self._throttle()
                async with session.get(target) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        
                        # Look for GraphQL-specific patterns
                        patterns = [
                            r'["\']([^"\']*graphql[^"\']*)["\']',
                            r'endpoint["\']?\s*:\s*["\']([^"\']*gql[^"\']*)["\']',
                            r'api["\']?\s*:\s*["\']([^"\']*query[^"\']*)["\']',
                            r'url["\']?\s*:\s*["\']([^"\']*graphql[^"\']*)["\']'
                        ]
                        
                        for pattern in patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            for match in matches:
                                if match.startswith('/'):
                                    endpoints.add(f"{base_url}{match}")
                                elif match.startswith('http'):
                                    endpoints.add(match)
                
                # Check common framework patterns
                framework_paths = [
                    "/.well-known/graphql",
                    "/admin/api/graphql",
                    "/api/admin/graphql", 
                    "/internal/api/graphql",
                    "/dev/api/graphql",
                    "/test/graphql",
                    "/debug/graphql"
                ]
                
                for path in framework_paths:
                    test_url = f"{base_url}{path}"
                    if await self._check_graphql_endpoint(session, test_url):
                        endpoints.add(test_url)
        
        except Exception:
            pass
        
        # Validate endpoints
        validated_endpoints = []
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout_s)) as session:
            for endpoint in endpoints:
                if await self._is_graphql_endpoint(session, endpoint):
                    validated_endpoints.append(endpoint)
        
        return validated_endpoints

    async def _comprehensive_graphql_scan(self, endpoint: str, semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """Comprehensive GraphQL scanning beyond XBOW capabilities"""
        findings = []
        
        async with semaphore:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout_s)) as session:
                # 1. Introspection Analysis (Enhanced)
                introspection_findings = await self._advanced_introspection_scan(session, endpoint)
                findings.extend(introspection_findings)
                
                # 2. Authentication Bypass Tests
                auth_findings = await self._auth_bypass_tests(session, endpoint)
                findings.extend(auth_findings)
                
                # 3. Injection and DoS Tests
                injection_findings = await self._injection_vulnerability_tests(session, endpoint)
                findings.extend(injection_findings)
                
                # 4. Business Logic Tests
                logic_findings = await self._business_logic_tests(session, endpoint)
                findings.extend(logic_findings)
                
                # 5. Information Disclosure Tests
                info_findings = await self._information_disclosure_tests(session, endpoint)
                findings.extend(info_findings)
        
        return findings

    async def _advanced_introspection_scan(self, session: aiohttp.ClientSession, endpoint: str) -> List[Dict[str, Any]]:
        """Advanced introspection analysis beyond basic XBOW checks"""
        findings = []
        
        # Test different introspection queries
        for query_name, query in INTROSPECTION_QUERIES.items():
            try:
                await self._throttle()
                async with session.post(
                    endpoint, 
                    json=query,
                    headers={"Content-Type": "application/json", **self.auth_headers}
                ) as resp:
                    
                    if resp.status == 200:
                        data = await resp.json()
                        
                        if self._has_introspection_data(data):
                            findings.append({
                                "type": "graphql.introspection.enabled",
                                "endpoint": endpoint,
                                "severity": "medium",
                                "proof": f"Introspection query '{query_name}' successful",
                                "query_type": query_name,
                                "response_size": len(str(data))
                            })
                            
                            # Analyze schema for sensitive information
                            sensitive_findings = self._analyze_schema_for_sensitive_data(data, endpoint)
                            findings.extend(sensitive_findings)
                            
                            # Check for admin-only fields
                            admin_findings = self._check_admin_only_fields(data, endpoint)
                            findings.extend(admin_findings)
                            
                            break  # Don't spam with multiple introspection reports
                    
                    elif resp.status == 403:
                        findings.append({
                            "type": "graphql.introspection.blocked",
                            "endpoint": endpoint,
                            "severity": "info",
                            "proof": f"Introspection blocked for query '{query_name}'"
                        })
            
            except Exception as e:
                continue
        
        return findings

    async def _auth_bypass_tests(self, session: aiohttp.ClientSession, endpoint: str) -> List[Dict[str, Any]]:
        """Test for authentication bypass vulnerabilities"""
        findings = []
        
        if not self.auth_headers:
            return findings
        
        # Test introspection without auth
        test_query = INTROSPECTION_QUERIES["basic"]
        
        try:
            # With auth
            await self._throttle()
            async with session.post(endpoint, json=test_query, headers={"Content-Type": "application/json", **self.auth_headers}) as auth_resp:
                auth_data = await auth_resp.json() if auth_resp.status == 200 else {}
            
            # Without auth  
            await self._throttle()
            async with session.post(endpoint, json=test_query, headers={"Content-Type": "application/json"}) as unauth_resp:
                unauth_data = await unauth_resp.json() if unauth_resp.status == 200 else {}
            
            # Compare responses
            if (auth_resp.status == 200 and unauth_resp.status == 200 and 
                self._has_introspection_data(auth_data) and self._has_introspection_data(unauth_data)):
                
                findings.append({
                    "type": "graphql.auth.bypass",
                    "endpoint": endpoint,
                    "severity": "high",
                    "proof": "Introspection accessible without authentication",
                    "auth_status": auth_resp.status,
                    "unauth_status": unauth_resp.status
                })
        
        except Exception:
            pass
        
        return findings

    async def _injection_vulnerability_tests(self, session: aiohttp.ClientSession, endpoint: str) -> List[Dict[str, Any]]:
        """Test for injection vulnerabilities and DoS conditions"""
        findings = []
        
        for injection_name, payload in INJECTION_PAYLOADS.items():
            try:
                await self._throttle()
                start_time = time.time()
                
                async with session.post(
                    endpoint,
                    json=payload,
                    headers={"Content-Type": "application/json", **self.auth_headers}
                ) as resp:
                    
                    response_time = time.time() - start_time
                    response_text = await resp.text()
                    
                    # Check for DoS conditions
                    if response_time > 10 or len(response_text) > 1000000:  # 10 seconds or 1MB response
                        findings.append({
                            "type": "graphql.dos.resource_exhaustion",
                            "endpoint": endpoint,
                            "severity": "high",
                            "proof": f"Injection '{injection_name}' caused resource exhaustion",
                            "response_time": response_time,
                            "response_size": len(response_text),
                            "injection_type": injection_name
                        })
                    
                    # Check for error-based information disclosure
                    if resp.status >= 400:
                        error_patterns = [
                            "stack trace", "exception", "database", "internal error",
                            "sql", "query", "field", "resolver", "schema"
                        ]
                        
                        for pattern in error_patterns:
                            if pattern.lower() in response_text.lower():
                                findings.append({
                                    "type": "graphql.error.information_disclosure",
                                    "endpoint": endpoint,
                                    "severity": "medium",
                                    "proof": f"Error message contains '{pattern}': {response_text[:500]}",
                                    "injection_type": injection_name
                                })
                                break
            
            except asyncio.TimeoutError:
                findings.append({
                    "type": "graphql.dos.timeout",
                    "endpoint": endpoint,
                    "severity": "high",
                    "proof": f"Injection '{injection_name}' caused timeout",
                    "injection_type": injection_name
                })
            except Exception:
                continue
        
        return findings

    async def _business_logic_tests(self, session: aiohttp.ClientSession, endpoint: str) -> List[Dict[str, Any]]:
        """Test for business logic vulnerabilities"""
        findings = []
        
        # Test for query depth limits
        deep_query = {"query": "query DeepQuery{" + "__schema{types{fields{type{" * 20 + "name" + "}}}}" * 20 + "}"}
        
        try:
            await self._throttle()
            start_time = time.time()
            
            async with session.post(
                endpoint,
                json=deep_query,
                headers={"Content-Type": "application/json", **self.auth_headers}
            ) as resp:
                response_time = time.time() - start_time
                
                if response_time > 5:  # Took more than 5 seconds
                    findings.append({
                        "type": "graphql.business_logic.no_depth_limit",
                        "endpoint": endpoint,
                        "severity": "medium",
                        "proof": f"Deep nested query processed in {response_time:.2f} seconds",
                        "response_time": response_time
                    })
        
        except Exception:
            pass
        
        # Test for rate limiting
        try:
            simple_query = {"query": "query{__typename}"}
            request_times = []
            
            for _ in range(10):  # Send 10 quick requests
                start_time = time.time()
                async with session.post(
                    endpoint,
                    json=simple_query,
                    headers={"Content-Type": "application/json", **self.auth_headers}
                ) as resp:
                    request_times.append(time.time() - start_time)
            
            avg_response_time = sum(request_times) / len(request_times)
            
            if all(t < 1.0 for t in request_times) and avg_response_time < 0.5:
                findings.append({
                    "type": "graphql.business_logic.no_rate_limit",
                    "endpoint": endpoint,
                    "severity": "low",
                    "proof": f"No rate limiting detected - 10 requests processed in {sum(request_times):.2f} seconds",
                    "avg_response_time": avg_response_time
                })
        
        except Exception:
            pass
        
        return findings

    async def _information_disclosure_tests(self, session: aiohttp.ClientSession, endpoint: str) -> List[Dict[str, Any]]:
        """Test for information disclosure vulnerabilities"""
        findings = []
        
        # Test for verbose error messages
        malformed_queries = [
            {"query": "query{nonExistentField}"},
            {"query": "mutation{nonExistentMutation}"},
            {"query": "subscription{nonExistentSubscription}"},
            {"query": "query{__schema{invalidField}}"},
            {"query": "query($var: String!){__typename}"},  # Missing variable
        ]
        
        for malformed in malformed_queries:
            try:
                await self._throttle()
                async with session.post(
                    endpoint,
                    json=malformed,
                    headers={"Content-Type": "application/json", **self.auth_headers}
                ) as resp:
                    
                    if resp.status >= 400:
                        response_text = await resp.text()
                        
                        # Check for sensitive information in error messages
                        sensitive_patterns = [
                            r"file://[^\s]+",
                            r"[A-Za-z]:\\[^\s]+",
                            r"/[a-z]+/[a-z]+/[a-z]+/[^\s]+",
                            r"database|sql|query|table|column",
                            r"internal|debug|stack|trace",
                            r"secret|password|key|token",
                            r"localhost|127\.0\.0\.1|0\.0\.0\.0"
                        ]
                        
                        for pattern in sensitive_patterns:
                            matches = re.findall(pattern, response_text, re.IGNORECASE)
                            if matches:
                                findings.append({
                                    "type": "graphql.information_disclosure.error_messages",
                                    "endpoint": endpoint,
                                    "severity": "low",
                                    "proof": f"Sensitive information in error: {matches[0]}",
                                    "pattern": pattern,
                                    "query": malformed["query"]
                                })
                                break
            
            except Exception:
                continue
        
        return findings

    def _analyze_schema_for_sensitive_data(self, schema_data: Dict, endpoint: str) -> List[Dict[str, Any]]:
        """Analyze GraphQL schema for sensitive field names and types"""
        findings = []
        
        try:
            types = schema_data.get("data", {}).get("__schema", {}).get("types", [])
            
            sensitive_field_patterns = [
                r"password", r"secret", r"key", r"token", r"auth", r"login",
                r"admin", r"root", r"internal", r"debug", r"test",
                r"email", r"phone", r"ssn", r"credit", r"payment",
                r"api_key", r"private", r"confidential"
            ]
            
            for type_info in types:
                if isinstance(type_info, dict) and type_info.get("fields"):
                    for field in type_info["fields"]:
                        if isinstance(field, dict):
                            field_name = field.get("name", "").lower()
                            
                            for pattern in sensitive_field_patterns:
                                if re.search(pattern, field_name, re.IGNORECASE):
                                    findings.append({
                                        "type": "graphql.schema.sensitive_field",
                                        "endpoint": endpoint,
                                        "severity": "low",
                                        "proof": f"Potentially sensitive field exposed: {field.get('name')} in type {type_info.get('name')}",
                                        "field_name": field.get("name"),
                                        "type_name": type_info.get("name"),
                                        "field_type": str(field.get("type", {}))
                                    })
                                    break
        
        except Exception:
            pass
        
        return findings

    def _check_admin_only_fields(self, schema_data: Dict, endpoint: str) -> List[Dict[str, Any]]:
        """Check for admin-only or privileged fields that shouldn't be exposed"""
        findings = []
        
        try:
            types = schema_data.get("data", {}).get("__schema", {}).get("types", [])
            
            admin_patterns = [
                r"admin", r"root", r"superuser", r"privilege", r"permission",
                r"role", r"access", r"internal", r"system", r"debug"
            ]
            
            for type_info in types:
                if isinstance(type_info, dict):
                    type_name = type_info.get("name", "").lower()
                    
                    for pattern in admin_patterns:
                        if re.search(pattern, type_name, re.IGNORECASE):
                            findings.append({
                                "type": "graphql.schema.admin_type",
                                "endpoint": endpoint,
                                "severity": "medium",
                                "proof": f"Administrative type exposed: {type_info.get('name')}",
                                "type_name": type_info.get("name"),
                                "pattern_matched": pattern
                            })
                            break
        
        except Exception:
            pass
        
        return findings

    async def _check_graphql_endpoint(self, session: aiohttp.ClientSession, url: str) -> bool:
        """Check if URL is a GraphQL endpoint"""
        try:
            await self._throttle()
            async with session.post(url, json={"query": "query{__typename}"}, headers={"Content-Type": "application/json"}) as resp:
                if resp.status in [200, 400]:
                    content = await resp.text()
                    return any(indicator in content.lower() for indicator in ["graphql", "__typename", "query", "mutation"])
        except Exception:
            pass
        return False

    async def _is_graphql_endpoint(self, session: aiohttp.ClientSession, endpoint: str) -> bool:
        """Verify if endpoint is actually GraphQL"""
        try:
            await self._throttle()
            async with session.post(
                endpoint, 
                json={"query": "query{__typename}"},
                headers={"Content-Type": "application/json"}
            ) as resp:
                
                if resp.status in [200, 400, 405]:
                    text = await resp.text()
                    # GraphQL-specific response patterns
                    graphql_patterns = [
                        "graphql", "__typename", "data", "errors", "extensions",
                        "query", "mutation", "subscription", "schema"
                    ]
                    return any(pattern in text.lower() for pattern in graphql_patterns)
        except Exception:
            pass
        return False

    def _has_introspection_data(self, data: Dict) -> bool:
        """Check if response contains introspection data"""
        try:
            return bool(data.get("data", {}).get("__schema"))
        except Exception:
            return False

    async def _throttle(self):
        """Rate limiting mechanism"""
        delay = 1.0 / self.rate_limit_per_host
        now = time.time()
        since = now - self._last_req_ts
        if since < delay:
            await asyncio.sleep(delay - since)
        self._last_req_ts = time.time()

    def _store_findings(self, findings: List[Dict[str, Any]]):
        """Store GraphQL findings in database"""
        for finding in findings:
            try:
                with self.asset_manager._get_db() as db:
                    # Map severity to database format
                    severity_map = {"low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}
                    severity = severity_map.get(finding.get("severity", "low"), "LOW")
                    
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
                        finding.get("type", "GraphQL Vulnerability"),
                        f"GraphQL finding: {finding.get('type', 'Unknown')}",
                        severity,
                        finding.get("proof", ""),
                        json.dumps(finding, indent=2),
                        datetime.now().isoformat(),
                        0.85  # High confidence for GraphQL findings
                    ))
                
                self.asset_manager.log_activity('GRAPHQL_FINDING', f"GraphQL finding: {finding.get('type', 'Unknown')}")
                
            except Exception as e:
                print(f"Error storing GraphQL finding: {e}")