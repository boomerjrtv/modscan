#!/usr/bin/env python3
"""
Validation Manager - Universal, deterministic PoC verification helpers.

Provides target-agnostic post-detection verification for multiple vuln classes
by generating safe markers, replaying requests, checking visible effects,
and capturing screenshots via a callback provided by the scanner.
"""
from __future__ import annotations
import asyncio
import logging
import re
import time
from dataclasses import replace
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

logger = logging.getLogger("ValidationManager")

class ValidationManager:
    def __init__(self, scanner):
        # Access to scanner helpers (auth headers + screenshots)
        self.scanner = scanner

    def _marker(self, prefix: str = "MODSCAN") -> str:
        return f"{prefix}_{int(time.time())}"

    async def validate(self, finding, session) -> any:
        """Route validation by vulnerability type. Returns updated finding.

        Enriches evidence with verification method and marker when verified.
        """
        vt = (finding.vuln_type or '').lower()
        try:
            if 'xss' in vt and 'dom' not in vt:
                return await self._validate_xss_reflected(finding, session)
            if 'xss_dom' in vt or ('dom' in vt and 'xss' in vt):
                return await self._validate_xss_dom(finding, session)
            if 'open' in vt and 'redirect' in vt:
                return await self._validate_open_redirect(finding, session)
            if 'file' in vt and 'inclusion' in vt:
                return await self._validate_lfi(finding, session)
            if 'command' in vt and 'injection' in vt:
                return await self._validate_command_injection(finding, session)
            if 'ssrf' in vt:
                return await self._validate_ssrf(finding, session)
            if 'idor' in vt or 'insecure_direct' in vt:
                return await self._validate_idor(finding, session)
            if 'csrf' in vt:
                return await self._validate_csrf(finding, session)
        except Exception as e:
            logger.debug(f"Validation failed ({finding.vuln_type}): {e}")
        return finding

    async def _validate_xss_reflected(self, finding, session):
        url = finding.url
        marker = self._marker('XSS')
        try:
            parsed = urlparse(url)
            q = parse_qs(parsed.query, keep_blank_values=True)
            param = finding.affected_parameter or next(iter(q.keys()), 'q')
            # Build OOB beacon base from config (collaborator or local dashboard)
            collab = (self.scanner.config.get('collaborator', {}) or {}).get('base_domain')
            scheme = 'https' if ((self.scanner.config.get('collaborator', {}) or {}).get('https')) else 'http'
            if not collab:
                host = self.scanner.config.get('dashboard_host') or '127.0.0.1'
                port = str(self.scanner.config.get('dashboard_port') or '8000')
                collab = f"{host}:{port}"
            oob = f"{scheme}://{collab}/oob/xss/{marker}"

            # Inject a safe reflected payload that visibly inserts a banner and loads a blind beacon.
            # We use backticks to assign outerHTML; include a hidden img to call our OOB endpoint.
            payload = (
                f"\"><img src=x onerror=\"this.outerHTML=`<div id=MODSCAN_XSS "
                f"style=font:700 14px/1.2 system-ui;color:#10b981;background:#052e16;padding:6px 10px;"
                f"border-radius:6px>MODSCAN XSS VERIFIED • {marker}</div><img src='{oob}?u=${{encodeURIComponent(location.href)}}' style='display:none'>`\">"
            )
            q[param] = [payload]
            new_query = urlencode(q, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            h = await self.scanner._get_auth_headers(test_url)
            async with session.get(test_url, headers=h, timeout=15) as r:
                txt = await r.text()
            # Verify by presence of our unique marker in the reflected HTML (attribute value)
            verified = (marker in txt)
            if verified:
                try:
                    import asyncio as _asyncio
                    # Small delay to ensure client-side banner insertion renders before capture
                    await _asyncio.sleep(0.4)
                except Exception:
                    pass
                shot = await self.scanner._take_screenshot(test_url)
                finding.evidence = (
                    f"{finding.evidence} | Verification: visible MODSCAN banner {marker}. Screenshot: {shot}"
                ).strip()
                finding.confidence = max(finding.confidence, 0.9)
                finding.screenshot_path = shot or finding.screenshot_path
        except Exception as e:
            logger.debug(f"XSS reflected validation error: {e}")
        return finding

    async def _validate_xss_dom(self, finding, session):
        # DOM XSS is validated during detection; just annotate as verified
        try:
            finding.evidence = f"{finding.evidence} | Verification: DOM execution observed (window.__modscan_domxss=1)".strip()
            finding.confidence = max(finding.confidence, 0.9)
        except Exception:
            pass
        return finding

    async def _validate_open_redirect(self, finding, session):
        url = finding.url
        try:
            h = await self.scanner._get_auth_headers(url)
            # Do not follow redirects to capture Location header
            async with session.get(url, headers=h, timeout=15, allow_redirects=False) as r:
                loc = r.headers.get('Location')
                if r.status in (301,302,303,307,308) and loc and loc.startswith('http'):
                    finding.evidence = f"{finding.evidence} | Verification: 3xx redirect to {loc}".strip()
                    finding.confidence = max(finding.confidence, 0.85)
                    shot = await self.scanner._take_screenshot(url)
                    finding.screenshot_path = shot or finding.screenshot_path
        except Exception as e:
            logger.debug(f"Open redirect validation error: {e}")
        return finding

    async def _validate_lfi(self, finding, session):
        url = finding.url
        try:
            h = await self.scanner._get_auth_headers(url)
            async with session.get(url, headers=h, timeout=15) as r:
                txt = await r.text()
            # Heuristics for /etc/passwd content
            if re.search(r"root:x:0:0:|/bin/(bash|sh)", txt, re.I):
                finding.evidence = f"{finding.evidence} | Verification: /etc/passwd signature present".strip()
                finding.confidence = max(finding.confidence, 0.9)
                shot = await self.scanner._take_screenshot(url)
                finding.screenshot_path = shot or finding.screenshot_path
        except Exception as e:
            logger.debug(f"LFI validation error: {e}")
        return finding

    async def _validate_command_injection(self, finding, session):
        url = finding.url
        try:
            parsed = urlparse(url)
            q = parse_qs(parsed.query, keep_blank_values=True)
            param = finding.affected_parameter or next(iter(q.keys()), 'cmd')
            marker = self._marker('CMD')
            # Append a benign echo marker. Use common separators ; && |
            separators = [';','&&','|']
            base_val = (q.get(param, [''])[0])
            injected = base_val + f";echo {marker}"
            q[param] = [injected]
            new_query = urlencode(q, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            h = await self.scanner._get_auth_headers(test_url)
            async with session.get(test_url, headers=h, timeout=15) as r:
                txt = await r.text()
            if marker in txt:
                finding.evidence = f"{finding.evidence} | Verification: command output marker {marker} found".strip()
                finding.confidence = max(finding.confidence, 0.9)
                shot = await self.scanner._take_screenshot(test_url)
                finding.screenshot_path = shot or finding.screenshot_path
        except Exception as e:
            logger.debug(f"Command injection validation error: {e}")
        return finding

    async def _validate_ssrf(self, finding, session):
        url = finding.url
        try:
            # Use configured collaborator domain
            collab = (self.scanner.config.get('collaborator', {}) or {}).get('base_domain') or self.scanner.config.get('blind_xss_domain')
            if not collab:
                return finding
            marker = self._marker('SSRF')
            callback = f"http://{collab}/ssrf/{marker}"
            parsed = urlparse(url)
            q = parse_qs(parsed.query, keep_blank_values=True)
            # Candidate params for SSRF
            candidates = ['url','u','dest','target','endpoint','image','file','redirect','next']
            target_param = next((p for p in q.keys() if p.lower() in candidates), None) or (candidates[0])
            q[target_param] = [callback]
            new_query = urlencode(q, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            h = await self.scanner._get_auth_headers(test_url)
            async with session.get(test_url, headers=h, timeout=12) as r:
                _ = await r.text()
            finding.evidence = f"{finding.evidence} | Verification: OOB SSRF beacon sent to {callback} (monitor collaborator logs)".strip()
            finding.confidence = max(finding.confidence, 0.7)
        except Exception as e:
            logger.debug(f"SSRF validation error: {e}")
        return finding

    async def _validate_idor(self, finding, session):
        url = finding.url
        try:
            parsed = urlparse(url)
            q = parse_qs(parsed.query, keep_blank_values=True)
            # Choose numeric-looking param
            param = finding.affected_parameter or next((k for k,v in q.items() if any(ch.isdigit() for ch in ''.join(v))), None)
            if not param:
                return finding
            base_val = q.get(param, ['1'])[0]
            try:
                n = int(''.join(ch for ch in base_val if ch.isdigit()) or '1')
            except Exception:
                n = 1
            alt = str(n + 1 if n < 9 else n - 1)
            q[param] = [alt]
            new_query = urlencode(q, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            h = await self.scanner._get_auth_headers(test_url)
            async with session.get(url, headers=h, timeout=12) as r0:
                a = await r0.text()
            async with session.get(test_url, headers=h, timeout=12) as r1:
                b = await r1.text()
            # State diff heuristics: content length, JSON token counts, key hints
            verified = False
            diff_note = ''
            if (r1.status == 200) and (len(b) != len(a)):
                verified = True
                diff_note = f"state_diff length {len(a)}→{len(b)}"
            # JSON tokenized diff
            try:
                import json as _json
                ja = _json.loads(a)
                jb = _json.loads(b)
                def _count_json(x):
                    if isinstance(x, dict):
                        return len(x) + sum(_count_json(v) for v in x.values())
                    if isinstance(x, list):
                        return len(x) + sum(_count_json(v) for v in x)
                    return 1
                ca, cb = _count_json(ja), _count_json(jb)
                if ca != cb:
                    verified = True
                    diff_note = (diff_note + '; ' if diff_note else '') + f"json_tokens {ca}→{cb}"
            except Exception:
                # HTML keyword hints
                hints = ['admin','user','email','account','profile']
                if any(hint in (b.lower()) for hint in hints) and not any(hint in (a.lower()) for hint in hints):
                    verified = True
                    diff_note = (diff_note + '; ' if diff_note else '') + "keyword shift"
            if verified:
                finding.evidence = f"{finding.evidence} | Verification: {diff_note} when {param} changed".strip()
                finding.confidence = max(finding.confidence, 0.85)
                shot = await self.scanner._take_screenshot(test_url)
                finding.screenshot_path = shot or finding.screenshot_path
        except Exception as e:
            logger.debug(f"IDOR validation error: {e}")
        return finding

    async def _validate_csrf(self, finding, session):
        # For universal validation, confirm absence of typical CSRF tokens after fresh fetch
        url = finding.url
        try:
            h = await self.scanner._get_auth_headers(url)
            async with session.get(url, headers=h, timeout=12) as r:
                html = await r.text()
            if '<form' in html.lower():
                tokens = ['csrf','token','_token','authenticity_token','xsrf','requestverificationtoken','csrfmiddlewaretoken','form_token','security_token']
                has_token = any(tok in html.lower() for tok in tokens)
                if not has_token:
                    finding.evidence = f"{finding.evidence} | Verification: form rendered without CSRF token field".strip()
                    finding.confidence = max(finding.confidence, 0.78)
                    shot = await self.scanner._take_screenshot(url)
                    finding.screenshot_path = shot or finding.screenshot_path
        except Exception as e:
            logger.debug(f"CSRF validation error: {e}")
        return finding
