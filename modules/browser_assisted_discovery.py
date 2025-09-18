#!/usr/bin/env python3
"""
🔍 BROWSER-ASSISTED VULNERABILITY DISCOVERY

Simple but effective browser automation to find vulnerabilities that traditional
scanners miss. Focuses on practical discovery rather than complex AI interactions.
"""

import asyncio
import logging
import json
import re
from typing import Dict, List, Set, Optional
from urllib.parse import urljoin, urlparse
import time

try:
    from playwright.async_api import async_playwright, Page, Browser
except ImportError:
    pass

logger = logging.getLogger(__name__)

class BrowserAssistedDiscovery:
    """Browser automation for vulnerability discovery - practical and effective."""

    def __init__(self, asset_manager):
        self.asset_manager = asset_manager
        self.browser = None
        self.discoveries = []

    async def discover_dynamic_content(self, url: str) -> List[Dict]:
        """
        Use browser to discover dynamic content, AJAX endpoints, and hidden functionality.
        Much simpler than full AI interaction - just smart observation.
        """
        discoveries = []

        try:
            playwright = await async_playwright().start()
            browser = await playwright.chromium.launch(headless=True)
            page = await browser.new_page()

            # Monitor network requests to capture AJAX/API calls
            api_calls = []

            async def capture_requests(request):
                url_lower = request.url.lower()
                if any(indicator in url_lower for indicator in ['/api/', '.json', '/ajax/', '/rest/', 'graphql']):
                    api_calls.append({
                        'url': request.url,
                        'method': request.method,
                        'headers': dict(request.headers),
                        'post_data': request.post_data
                    })

            page.on('request', capture_requests)

            logger.info(f"🔍 Browser analyzing: {url}")
            await page.goto(url, timeout=30000)

            # Wait for dynamic content to load
            await page.wait_for_timeout(3000)

            # Try common interactions that reveal functionality
            await self._trigger_common_interactions(page)

            # Discover forms with detailed analysis
            forms = await self._analyze_forms_detailed(page, url)
            discoveries.extend(forms)

            # Capture discovered API endpoints
            for api_call in api_calls:
                discoveries.append({
                    'type': 'api_endpoint',
                    'url': api_call['url'],
                    'method': api_call['method'],
                    'vulnerability_potential': 'high'  # APIs often have good vuln potential
                })

            # Look for admin/hidden functionality hints
            admin_hints = await self._find_admin_hints(page)
            discoveries.extend(admin_hints)

            # Check for file upload capabilities
            upload_forms = await self._find_upload_forms(page)
            discoveries.extend(upload_forms)

            await browser.close()
            await playwright.stop()

            logger.info(f"🔍 Browser discovery found {len(discoveries)} items for {url}")

        except Exception as e:
            logger.error(f"Browser discovery failed for {url}: {e}")

        return discoveries

    async def _trigger_common_interactions(self, page: Page):
        """Trigger common user interactions to reveal hidden functionality."""
        try:
            # Click common navigation elements
            nav_selectors = [
                'button:has-text("menu")', 'button:has-text("Menu")',
                '[aria-label="menu"]', '.navbar-toggle', '.menu-toggle'
            ]

            for selector in nav_selectors:
                try:
                    await page.click(selector, timeout=2000)
                    await page.wait_for_timeout(1000)
                except:
                    pass

            # Hover over navigation items to reveal dropdowns
            nav_items = await page.query_selector_all('nav a, .navigation a, .menu a')
            for item in nav_items[:5]:  # Limit to prevent timeout
                try:
                    await item.hover()
                    await page.wait_for_timeout(500)
                except:
                    pass

            # Try to reveal search functionality
            search_triggers = ['input[type="search"]', '[placeholder*="search"]', '.search-toggle']
            for selector in search_triggers:
                try:
                    await page.click(selector, timeout=1000)
                    await page.wait_for_timeout(500)
                except:
                    pass

        except Exception as e:
            logger.debug(f"Error triggering interactions: {e}")

    async def _analyze_forms_detailed(self, page: Page, base_url: str) -> List[Dict]:
        """Detailed form analysis for vulnerability testing."""
        forms = []

        try:
            form_elements = await page.query_selector_all('form')

            for i, form in enumerate(form_elements):
                try:
                    action = await form.get_attribute('action') or base_url
                    method = await form.get_attribute('method') or 'GET'

                    # Get all input fields with details
                    inputs = await form.query_selector_all('input, textarea, select')
                    fields = {}

                    for input_elem in inputs:
                        name = await input_elem.get_attribute('name')
                        input_type = await input_elem.get_attribute('type') or 'text'
                        placeholder = await input_elem.get_attribute('placeholder') or ''
                        required = await input_elem.get_attribute('required') is not None

                        if name:
                            fields[name] = {
                                'type': input_type,
                                'placeholder': placeholder,
                                'required': required
                            }

                    # Analyze form purpose and vulnerability potential
                    form_html = await form.inner_html()
                    form_analysis = self._analyze_form_security(form_html, fields)

                    forms.append({
                        'type': 'form',
                        'url': urljoin(base_url, action),
                        'method': method.upper(),
                        'fields': fields,
                        'form_purpose': form_analysis['purpose'],
                        'vulnerability_potential': form_analysis['vuln_potential'],
                        'priority_tests': form_analysis['priority_tests']
                    })

                except Exception as e:
                    logger.debug(f"Error analyzing form {i}: {e}")

        except Exception as e:
            logger.debug(f"Error in form analysis: {e}")

        return forms

    def _analyze_form_security(self, form_html: str, fields: Dict) -> Dict:
        """Analyze form for security testing opportunities."""
        html_lower = form_html.lower()
        field_names = [name.lower() for name in fields.keys()]

        analysis = {
            'purpose': 'unknown',
            'vuln_potential': 'medium',
            'priority_tests': []
        }

        # Identify form purpose
        if any(keyword in html_lower for keyword in ['login', 'signin', 'password']):
            analysis['purpose'] = 'login'
            analysis['vuln_potential'] = 'high'
            analysis['priority_tests'] = ['SQL_INJECTION', 'BRUTE_FORCE', 'XSS']

        elif any(keyword in html_lower for keyword in ['upload', 'file']):
            analysis['purpose'] = 'file_upload'
            analysis['vuln_potential'] = 'critical'
            analysis['priority_tests'] = ['FILE_UPLOAD', 'PATH_TRAVERSAL', 'MALWARE_UPLOAD']

        elif any(keyword in html_lower for keyword in ['search', 'query']):
            analysis['purpose'] = 'search'
            analysis['vuln_potential'] = 'high'
            analysis['priority_tests'] = ['XSS', 'SQL_INJECTION', 'LDAP_INJECTION']

        elif any(keyword in html_lower for keyword in ['contact', 'message', 'feedback']):
            analysis['purpose'] = 'contact'
            analysis['vuln_potential'] = 'medium'
            analysis['priority_tests'] = ['XSS', 'EMAIL_INJECTION']

        elif any(keyword in html_lower for keyword in ['admin', 'config', 'settings']):
            analysis['purpose'] = 'admin'
            analysis['vuln_potential'] = 'critical'
            analysis['priority_tests'] = ['PRIVILEGE_ESCALATION', 'IDOR', 'XSS', 'CSRF']

        # Field-based analysis
        if any('id' in name for name in field_names):
            if 'IDOR' not in analysis['priority_tests']:
                analysis['priority_tests'].append('IDOR')

        if any('file' in name for name in field_names):
            if 'FILE_UPLOAD' not in analysis['priority_tests']:
                analysis['priority_tests'].append('FILE_UPLOAD')

        # Always test for CSRF on forms with multiple fields
        if len(fields) > 1 and 'CSRF' not in analysis['priority_tests']:
            analysis['priority_tests'].append('CSRF')

        return analysis

    async def _find_admin_hints(self, page: Page) -> List[Dict]:
        """Look for hints about admin panels or hidden functionality."""
        hints = []

        try:
            # Look for common admin-related text and links
            admin_keywords = ['admin', 'administrator', 'manage', 'dashboard', 'control panel', 'settings']

            for keyword in admin_keywords:
                # Check for links containing admin keywords
                admin_links = await page.query_selector_all(f'a:has-text("{keyword}")')
                for link in admin_links:
                    href = await link.get_attribute('href')
                    if href:
                        hints.append({
                            'type': 'admin_hint',
                            'url': href,
                            'text': await link.inner_text(),
                            'vulnerability_potential': 'high'
                        })

            # Look for hidden admin links (common pattern)
            hidden_selectors = [
                'a[style*="display:none"]',
                'a[style*="visibility:hidden"]',
                '.hidden a',
                '.admin a'
            ]

            for selector in hidden_selectors:
                try:
                    hidden_links = await page.query_selector_all(selector)
                    for link in hidden_links:
                        href = await link.get_attribute('href')
                        if href:
                            hints.append({
                                'type': 'hidden_admin',
                                'url': href,
                                'vulnerability_potential': 'critical'
                            })
                except:
                    pass

        except Exception as e:
            logger.debug(f"Error finding admin hints: {e}")

        return hints

    async def _find_upload_forms(self, page: Page) -> List[Dict]:
        """Specifically look for file upload functionality."""
        uploads = []

        try:
            file_inputs = await page.query_selector_all('input[type="file"]')

            for file_input in file_inputs:
                form = await file_input.evaluate_handle('el => el.closest("form")')
                if form:
                    action = await form.get_attribute('action')
                    method = await form.get_attribute('method') or 'POST'

                    # Check for file type restrictions
                    accept = await file_input.get_attribute('accept') or 'any'

                    uploads.append({
                        'type': 'file_upload',
                        'url': action,
                        'method': method.upper(),
                        'accepted_types': accept,
                        'vulnerability_potential': 'critical',
                        'priority_tests': ['FILE_UPLOAD', 'PATH_TRAVERSAL', 'MALWARE_UPLOAD', 'XSS']
                    })

        except Exception as e:
            logger.debug(f"Error finding upload forms: {e}")

        return uploads

    async def test_spa_routes(self, base_url: str) -> List[Dict]:
        """Test Single Page Application routes for hidden functionality."""
        spa_discoveries = []

        try:
            playwright = await async_playwright().start()
            browser = await playwright.chromium.launch(headless=True)
            page = await browser.new_page()

            # Common SPA route patterns to test
            common_routes = [
                '/admin', '/dashboard', '/profile', '/settings', '/api',
                '/users', '/config', '/debug', '/test', '/dev'
            ]

            for route in common_routes:
                try:
                    test_url = urljoin(base_url, route)
                    response = await page.goto(test_url, timeout=10000)

                    if response and response.status == 200:
                        title = await page.title()
                        content = await page.content()

                        # Check if this reveals interesting functionality
                        if self._is_interesting_content(content, title):
                            spa_discoveries.append({
                                'type': 'spa_route',
                                'url': test_url,
                                'title': title,
                                'vulnerability_potential': 'medium'
                            })

                except Exception as e:
                    logger.debug(f"SPA route test failed for {route}: {e}")

            await browser.close()
            await playwright.stop()

        except Exception as e:
            logger.error(f"SPA testing failed: {e}")

        return spa_discoveries

    def _is_interesting_content(self, content: str, title: str) -> bool:
        """Determine if page content is interesting for security testing."""
        interesting_keywords = [
            'admin', 'dashboard', 'api', 'config', 'settings', 'manage',
            'upload', 'file', 'user', 'profile', 'debug', 'error'
        ]

        content_lower = content.lower()
        title_lower = title.lower()

        return any(keyword in content_lower or keyword in title_lower
                  for keyword in interesting_keywords)

    def prioritize_targets(self, discoveries: List[Dict]) -> List[Dict]:
        """Prioritize discovered targets for vulnerability testing."""
        priority_order = {
            'file_upload': 10,
            'admin_hint': 9,
            'hidden_admin': 9,
            'api_endpoint': 8,
            'form': 7,
            'spa_route': 6
        }

        # Sort by priority and vulnerability potential
        discoveries.sort(key=lambda d: (
            priority_order.get(d['type'], 5),
            1 if d.get('vulnerability_potential') == 'critical' else
            0.8 if d.get('vulnerability_potential') == 'high' else
            0.5
        ), reverse=True)

        return discoveries