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
            if 'sql' in vt:
                return await self._validate_sqli(finding, session)
            if 'ssrf' in vt:
                return await self._validate_ssrf(finding, session)
            if 'idor' in vt or 'insecure_direct' in vt:
                return await self._validate_idor(finding, session)
            if 'csrf' in vt:
                return await self._validate_csrf(finding, session)
        except Exception as e:
            logger.debug(f"Validation failed ({finding.vuln_type}): {e}")
        return finding

    async def _validate_sqli(self, finding, session):
        """Deterministic SQLi validation with control requests.

        Strategy:
        - Reissue baseline (benign) request and then the payload request.
        - Compare error signatures and/or content length changes.
        - For time-based, measure delta vs. benign request.
        """
        try:
            from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
            url = finding.url
            parsed = urlparse(url)
            q = parse_qs(parsed.query, keep_blank_values=True)
            if not q:
                return finding
            target_param = finding.affected_parameter or next(iter(q.keys()))
            payload_val = q.get(target_param, [''])[0]

            # Build benign control value
            benign = '1'
            q_b = q.copy(); q_b[target_param] = [benign]
            ctrl_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(q_b, doseq=True), parsed.fragment))
            q_t = q.copy(); q_t[target_param] = [payload_val]
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(q_t, doseq=True), parsed.fragment))

            h = await self.scanner._get_auth_headers(test_url)
            # Control
            import time as _t
            t0 = _t.time()
            try:
                from modules.http_bypass import smart_request as _smart_request
                rc, ctrl_txt = await _smart_request(session, 'GET', ctrl_url, headers=h, timeout=15)
            except Exception:
                async with session.get(ctrl_url, headers=h, timeout=12) as rc:
                    ctrl_txt = await rc.text()
            t1 = _t.time()
            # Test
            try:
                from modules.http_bypass import smart_request as _smart_request
                rt, test_txt = await _smart_request(session, 'GET', test_url, headers=h, timeout=15)
            except Exception:
                async with session.get(test_url, headers=h, timeout=12) as rt:
                    test_txt = await rt.text()
            t2 = _t.time()

            ctrl_len, test_len = len(ctrl_txt or ''), len(test_txt or '')
            sql_errors = ['sql syntax', 'mysql', 'ora-', 'postgres', 'sqlite', 'unclosed quotation', 'odbc']
            errors_ctrl = any(e in (ctrl_txt or '').lower() for e in sql_errors)
            errors_test = any(e in (test_txt or '').lower() for e in sql_errors)

            verified = False
            note = []
            if errors_test and not errors_ctrl:
                verified = True
                note.append('error signature only on payload request')
            if abs(test_len - ctrl_len) > 250 and not errors_ctrl:
                verified = True
                note.append(f'content length diff {ctrl_len}->{test_len}')
            # Time-based hint
            if (t2 - t1) - (t1 - t0) > 3.5:
                verified = True
                note.append(f'timing delta {(t2 - t1) - (t1 - t0):.2f}s')

            if verified:
                finding.evidence = f"{finding.evidence} | Verification: SQLi confirmed ({'; '.join(note)})".strip()
                finding.confidence = max(finding.confidence, 0.88)
                shot = await self.scanner._take_screenshot(test_url)
                finding.screenshot_path = shot or finding.screenshot_path
        except Exception as e:
            logger.debug(f"SQLi validation error: {e}")
        return finding

    async def _validate_xss_reflected(self, finding, session):
        """Reflected XSS validation that requires actual JS execution in a browser.

        We do NOT consider mere reflection as verified. We confirm execution by:
        - Detecting a dialog event, OR
        - Detecting a window sentinel set by an event handler (onerror)
        """
        url = finding.url
        marker = self._marker('XSS')
        try:
            parsed = urlparse(url)
            q = parse_qs(parsed.query, keep_blank_values=True)
            param = finding.affected_parameter or next(iter(q.keys()), 'q')
            # Minimal safe payload that sets a global sentinel if JS executes
            payload = f"\"><img src=x onerror=\"window.__modscan_xss_marker='{marker}'\">"
            q[param] = [payload]
            new_query = urlencode(q, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

            # Try browser-based confirmation
            try:
                from playwright.async_api import async_playwright  # type: ignore
                try:
                    # Use shared runtime if available
                    from .browser_runtime import get_launch_options, extend_args
                    opts = get_launch_options()
                    launch_args = extend_args(["--headless=new"], opts['args'])
                    headless = bool(opts['headless'])
                except Exception:
                    launch_args = ["--headless=new"]
                    headless = True

                dialog_detected = False
                async with async_playwright() as pw:
                    browser = await pw.chromium.launch(headless=headless, args=launch_args)
                    page = await browser.new_page()
                    # Capture dialog events
                    async def _on_dialog(d):
                        nonlocal dialog_detected
                        dialog_detected = True
                        try:
                            await d.accept()
                        except Exception:
                            pass
                    page.on("dialog", _on_dialog)
                    try:
                        await page.goto(test_url, timeout=15000, wait_until='domcontentloaded')
                        # Light event fuzzing to trigger common handlers
                        try:
                            await page.mouse.move(10, 10)
                            await page.mouse.click(20, 20)
                            await page.keyboard.press('Tab')
                            await page.keyboard.type('modscan')
                        except Exception:
                            pass
                        # Check sentinel for execution
                        executed = await page.evaluate(f"() => window.__modscan_xss_marker === '{marker}'")
                    except Exception:
                        executed = False
                    try:
                        await browser.close()
                    except Exception:
                        pass

                if executed or dialog_detected:
                    shot = await self.scanner._take_screenshot(test_url)
                    finding.evidence = (
                        f"{finding.evidence} | Verification: browser execution ({'dialog' if dialog_detected else 'sentinel'}). Screenshot: {shot}"
                    ).strip()
                    finding.confidence = max(finding.confidence, 0.9)
                    finding.screenshot_path = shot or finding.screenshot_path
                else:
                    # Downgrade to reflection-only
                    finding.vuln_type = 'xss_reflection'
                    finding.severity = 'LOW'
                    finding.confidence = min(finding.confidence, 0.4)
                    finding.evidence = f"{finding.evidence} | Not verified (reflected only)".strip()
            except Exception as bex:
                logger.debug(f"Browser validation unavailable or failed: {bex}")
                # As a fallback, DO NOT mark verified on reflection alone
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
            try:
                from modules.http_bypass import smart_request as _smart_request
                r, _ = await _smart_request(session, 'GET', test_url, headers=h, timeout=15)
            except Exception:
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
            try:
                from modules.http_bypass import smart_request as _smart_request
                r0, a = await _smart_request(session, 'GET', url, headers=h, timeout=15)
            except Exception:
                async with session.get(url, headers=h, timeout=12) as r0:
                    a = await r0.text()
            try:
                from modules.http_bypass import smart_request as _smart_request
                r1, b = await _smart_request(session, 'GET', test_url, headers=h, timeout=15)
            except Exception:
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
            try:
                from modules.http_bypass import smart_request as _smart_request
                r, html = await _smart_request(session, 'GET', url, headers=h, timeout=15)
            except Exception:
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
