#!/usr/bin/env python3
"""
🧠 AI-DRIVEN BROWSER CRAWLER

Human-like website exploration using Playwright + AI to discover vulnerabilities
that traditional scanners miss. The AI makes intelligent decisions about what
to click, fill, and explore based on page content and security testing goals.
"""

import asyncio
import logging
import json
import re
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse
import time

try:
    from playwright.async_api import async_playwright, Page, Browser, BrowserContext
except ImportError:
    print("🚨 Playwright not available - installing...")
    import subprocess
    subprocess.run(['pip', 'install', 'playwright'], check=True)
    subprocess.run(['playwright', 'install', 'chromium'], check=True)
    from playwright.async_api import async_playwright, Page, Browser, BrowserContext

logger = logging.getLogger(__name__)

@dataclass
class CrawlDiscovery:
    """Represents a discovery made during AI-driven crawling."""
    url: str
    discovery_type: str  # 'endpoint', 'form', 'file_upload', 'admin_panel', 'api_call'
    method: str  # 'GET', 'POST', 'PUT', etc.
    parameters: Dict[str, str]  # Form fields, query params
    page_title: str
    interesting_content: str  # AI-identified security-relevant content
    vulnerability_hints: List[str]  # AI predictions about potential vulns
    confidence: float  # AI confidence in this discovery's importance
    screenshot_path: Optional[str] = None

class AIBrowserCrawler:
    """AI-powered browser crawler that navigates like a human security tester."""

    def __init__(self, ai_client=None, asset_manager=None):
        self.ai_client = ai_client
        self.asset_manager = asset_manager
        self.browser = None
        self.context = None
        self.visited_urls = set()
        self.discoveries = []

        # Crawling parameters
        self.max_depth = 3
        self.max_pages_per_domain = 50
        self.interaction_timeout = 10000  # 10 seconds per interaction
        self.crawl_budget_minutes = 15

    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def start(self):
        """Initialize browser for AI-driven crawling."""
        try:
            self.playwright = await async_playwright().start()

            # Launch browser with security testing optimizations
            self.browser = await self.playwright.chromium.launch(
                headless=True,
                args=[
                    '--disable-web-security',  # Allow CORS testing
                    '--disable-features=VizDisplayCompositor',
                    '--no-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-gpu',
                    '--disable-background-timer-throttling',
                    '--disable-backgrounding-occluded-windows',
                    '--disable-renderer-backgrounding'
                ]
            )

            # Create context with realistic user agent
            self.context = await self.browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            )

            logger.info("🧠 AI Browser Crawler initialized with human-like settings")

        except Exception as e:
            logger.error(f"Failed to initialize AI Browser Crawler: {e}")
            raise

    async def close(self):
        """Clean up browser resources."""
        try:
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if hasattr(self, 'playwright'):
                await self.playwright.stop()
        except Exception as e:
            logger.error(f"Error closing AI Browser Crawler: {e}")

    async def smart_crawl(self, start_url: str, target_hints: List[str] = None) -> List[CrawlDiscovery]:
        """
        Perform AI-guided crawling starting from a URL.

        Args:
            start_url: Starting URL to crawl
            target_hints: List of things to look for ('admin', 'api', 'upload', etc.)
        """
        logger.info(f"🧠 Starting AI-guided crawl of {start_url}")

        start_time = time.time()
        budget_seconds = self.crawl_budget_minutes * 60

        try:
            page = await self.context.new_page()

            # Set up request/response interception to capture API calls
            await self._setup_network_monitoring(page)

            # Begin crawling with AI guidance
            await self._crawl_page_with_ai(page, start_url, depth=0, target_hints=target_hints)

            # Continue crawling discovered pages
            pages_to_crawl = [d.url for d in self.discoveries if d.discovery_type == 'endpoint'][:10]

            for url in pages_to_crawl:
                if time.time() - start_time > budget_seconds:
                    logger.info(f"⏰ Crawl budget exceeded ({self.crawl_budget_minutes}m), stopping")
                    break

                if url not in self.visited_urls and len(self.visited_urls) < self.max_pages_per_domain:
                    await self._crawl_page_with_ai(page, url, depth=1, target_hints=target_hints)

            await page.close()

        except Exception as e:
            logger.error(f"Error during AI crawling: {e}")

        logger.info(f"🧠 AI crawl complete: {len(self.discoveries)} discoveries from {len(self.visited_urls)} pages")
        return self.discoveries

    async def _setup_network_monitoring(self, page: Page):
        """Set up network interception to capture API calls and AJAX requests."""
        async def handle_request(request):
            # Log interesting API calls
            if any(api_indicator in request.url.lower() for api_indicator in ['/api/', '/graphql', '.json', '/rest/']):
                discovery = CrawlDiscovery(
                    url=request.url,
                    discovery_type='api_call',
                    method=request.method,
                    parameters=await self._extract_request_data(request),
                    page_title='API Endpoint',
                    interesting_content=f"API call: {request.method} {request.url}",
                    vulnerability_hints=['API_SECURITY', 'IDOR', 'BROKEN_ACCESS_CONTROL'],
                    confidence=0.8
                )
                self.discoveries.append(discovery)

        async def handle_response(response):
            # Analyze responses for interesting headers, errors, etc.
            if response.status >= 400:
                # Interesting error responses
                try:
                    content = await response.text()
                    if any(error_hint in content.lower() for error_hint in ['sql', 'mysql', 'error', 'exception', 'debug']):
                        discovery = CrawlDiscovery(
                            url=response.url,
                            discovery_type='error_disclosure',
                            method='GET',
                            parameters={},
                            page_title=f'Error {response.status}',
                            interesting_content=content[:500],
                            vulnerability_hints=['INFORMATION_DISCLOSURE', 'ERROR_HANDLING'],
                            confidence=0.7
                        )
                        self.discoveries.append(discovery)
                except:
                    pass

        page.on('request', handle_request)
        page.on('response', handle_response)

    async def _crawl_page_with_ai(self, page: Page, url: str, depth: int, target_hints: List[str] = None):
        """Crawl a single page using AI to guide interactions."""
        if url in self.visited_urls or depth > self.max_depth:
            return

        try:
            logger.info(f"🧠 AI crawling: {url} (depth {depth})")
            self.visited_urls.add(url)

            # Navigate to page
            response = await page.goto(url, timeout=30000, wait_until='domcontentloaded')

            if not response or response.status >= 400:
                return

            # Wait for dynamic content
            await page.wait_for_timeout(2000)

            # Get page content for AI analysis
            title = await page.title()
            content = await page.content()

            # AI analysis of the page
            page_analysis = await self._ai_analyze_page(url, title, content, target_hints)

            # Capture screenshot for important pages
            screenshot_path = None
            if page_analysis.get('importance', 0) > 0.7:
                screenshot_path = await self._take_screenshot(page, url)

            # Record page discovery
            discovery = CrawlDiscovery(
                url=url,
                discovery_type='endpoint',
                method='GET',
                parameters={},
                page_title=title,
                interesting_content=page_analysis.get('summary', ''),
                vulnerability_hints=page_analysis.get('vulnerability_hints', []),
                confidence=page_analysis.get('importance', 0.5),
                screenshot_path=screenshot_path
            )
            self.discoveries.append(discovery)

            # AI-guided interactions
            interactions = page_analysis.get('recommended_interactions', [])

            for interaction in interactions[:5]:  # Limit interactions per page
                try:
                    await self._execute_ai_interaction(page, interaction)
                    await page.wait_for_timeout(1000)  # Brief pause between interactions
                except Exception as e:
                    logger.debug(f"Interaction failed: {e}")

            # Find and analyze forms
            await self._analyze_forms(page, url)

            # Discover new links to crawl
            if depth < self.max_depth:
                new_links = await self._ai_select_interesting_links(page, url, target_hints)

                for link_url in new_links[:3]:  # Limit links per page
                    if link_url not in self.visited_urls:
                        await self._crawl_page_with_ai(page, link_url, depth + 1, target_hints)

        except Exception as e:
            logger.error(f"Error crawling {url}: {e}")

    async def _ai_analyze_page(self, url: str, title: str, content: str, target_hints: List[str] = None) -> Dict:
        """Use AI to analyze page content and recommend actions."""
        if not self.ai_client:
            return {
                'importance': 0.5,
                'summary': title,
                'vulnerability_hints': [],
                'recommended_interactions': []
            }

        try:
            # Truncate content for AI analysis
            content_sample = content[:5000] if len(content) > 5000 else content

            prompt = f"""
            Analyze this webpage for security testing opportunities:

            URL: {url}
            Title: {title}
            Target hints: {', '.join(target_hints or [])}

            Content sample:
            {content_sample}

            Provide analysis in JSON format:
            {{
                "importance": 0.0-1.0,
                "summary": "brief description",
                "vulnerability_hints": ["VULN_TYPE1", "VULN_TYPE2"],
                "recommended_interactions": [
                    {{"action": "click", "selector": "#login-button", "reason": "test authentication"}},
                    {{"action": "fill", "selector": "#search", "value": "<script>alert(1)</script>", "reason": "test XSS"}}
                ]
            }}

            Focus on:
            - Admin panels, login forms, file uploads
            - API endpoints and AJAX functionality
            - Forms that might be vulnerable to injection
            - Interesting error messages or debug info
            - Authorization bypass opportunities
            """

            response = await self.ai_client.analyze(prompt)

            # Parse JSON response
            try:
                import json
                return json.loads(response)
            except:
                # Fallback if JSON parsing fails
                return {
                    'importance': 0.6,
                    'summary': title,
                    'vulnerability_hints': self._extract_hints_from_text(response),
                    'recommended_interactions': []
                }

        except Exception as e:
            logger.debug(f"AI page analysis failed: {e}")
            return {'importance': 0.5, 'summary': title, 'vulnerability_hints': [], 'recommended_interactions': []}

    def _extract_hints_from_text(self, text: str) -> List[str]:
        """Extract vulnerability hints from AI response text."""
        hints = []
        vuln_keywords = ['SQL_INJECTION', 'XSS', 'IDOR', 'CSRF', 'LFI', 'SSRF', 'SSTI', 'UPLOAD']

        for keyword in vuln_keywords:
            if keyword.lower() in text.lower():
                hints.append(keyword)

        return hints

    async def _execute_ai_interaction(self, page: Page, interaction: Dict):
        """Execute an AI-recommended interaction with the page."""
        action = interaction.get('action')
        selector = interaction.get('selector')
        value = interaction.get('value', '')

        try:
            if action == 'click':
                element = await page.wait_for_selector(selector, timeout=5000)
                if element:
                    await element.click()
                    logger.debug(f"🖱️ Clicked: {selector}")

            elif action == 'fill':
                element = await page.wait_for_selector(selector, timeout=5000)
                if element:
                    await element.fill(value)
                    logger.debug(f"✏️ Filled {selector} with: {value}")

            elif action == 'hover':
                element = await page.wait_for_selector(selector, timeout=5000)
                if element:
                    await element.hover()
                    logger.debug(f"👆 Hovered: {selector}")

        except Exception as e:
            logger.debug(f"Interaction failed for {selector}: {e}")

    async def _analyze_forms(self, page: Page, url: str):
        """Analyze forms on the page for vulnerability testing opportunities."""
        try:
            forms = await page.query_selector_all('form')

            for i, form in enumerate(forms):
                try:
                    action = await form.get_attribute('action') or url
                    method = await form.get_attribute('method') or 'GET'

                    # Get form fields
                    inputs = await form.query_selector_all('input, textarea, select')
                    parameters = {}

                    for input_elem in inputs:
                        name = await input_elem.get_attribute('name')
                        input_type = await input_elem.get_attribute('type')
                        if name:
                            parameters[name] = input_type or 'text'

                    # Determine form type and vulnerability potential
                    form_html = await form.inner_html()
                    form_type = self._classify_form_type(form_html, parameters)
                    vuln_hints = self._predict_form_vulnerabilities(form_type, parameters)

                    discovery = CrawlDiscovery(
                        url=urljoin(url, action),
                        discovery_type='form',
                        method=method.upper(),
                        parameters=parameters,
                        page_title=f"Form {i+1}",
                        interesting_content=f"{form_type} form with {len(parameters)} fields",
                        vulnerability_hints=vuln_hints,
                        confidence=0.8 if 'login' in form_type or 'upload' in form_type else 0.6
                    )
                    self.discoveries.append(discovery)

                except Exception as e:
                    logger.debug(f"Error analyzing form {i}: {e}")

        except Exception as e:
            logger.debug(f"Error analyzing forms: {e}")

    def _classify_form_type(self, form_html: str, parameters: Dict) -> str:
        """Classify the type of form based on its content."""
        html_lower = form_html.lower()
        param_names = [name.lower() for name in parameters.keys()]

        if any(keyword in html_lower for keyword in ['login', 'signin', 'password']):
            return 'login'
        elif any(keyword in html_lower for keyword in ['upload', 'file']):
            return 'file_upload'
        elif any(keyword in html_lower for keyword in ['search', 'query']):
            return 'search'
        elif any(keyword in html_lower for keyword in ['contact', 'message', 'email']):
            return 'contact'
        elif any(keyword in html_lower for keyword in ['admin', 'manage', 'config']):
            return 'admin'
        else:
            return 'generic'

    def _predict_form_vulnerabilities(self, form_type: str, parameters: Dict) -> List[str]:
        """Predict vulnerability types based on form characteristics."""
        vulns = ['XSS', 'CSRF']  # All forms potentially vulnerable to these

        if form_type == 'login':
            vulns.extend(['SQL_INJECTION', 'BRUTE_FORCE', 'AUTH_BYPASS'])
        elif form_type == 'file_upload':
            vulns.extend(['FILE_UPLOAD', 'PATH_TRAVERSAL', 'MALWARE_UPLOAD'])
        elif form_type == 'search':
            vulns.extend(['SQL_INJECTION', 'XSS', 'LDAP_INJECTION'])
        elif form_type == 'admin':
            vulns.extend(['PRIVILEGE_ESCALATION', 'IDOR', 'BROKEN_ACCESS_CONTROL'])

        # Parameter-based predictions
        param_names = [name.lower() for name in parameters.keys()]
        if any('id' in name for name in param_names):
            vulns.append('IDOR')
        if any('file' in name or 'upload' in name for name in param_names):
            vulns.append('FILE_UPLOAD')

        return list(set(vulns))

    async def _ai_select_interesting_links(self, page: Page, current_url: str, target_hints: List[str] = None) -> List[str]:
        """Use AI to select the most interesting links to crawl next."""
        try:
            # Get all links on the page
            links = await page.query_selector_all('a[href]')
            link_data = []

            for link in links[:20]:  # Limit to first 20 links
                href = await link.get_attribute('href')
                text = await link.inner_text()

                if href:
                    full_url = urljoin(current_url, href)
                    link_data.append({'url': full_url, 'text': text.strip()})

            if not link_data:
                return []

            # AI analysis to select interesting links
            if self.ai_client and target_hints:
                interesting_links = await self._ai_prioritize_links(link_data, target_hints)
                return interesting_links[:5]  # Top 5 links
            else:
                # Simple heuristic fallback
                return self._heuristic_select_links(link_data)

        except Exception as e:
            logger.debug(f"Error selecting links: {e}")
            return []

    async def _ai_prioritize_links(self, link_data: List[Dict], target_hints: List[str]) -> List[str]:
        """Use AI to prioritize which links to crawl."""
        if not self.ai_client:
            return []

        try:
            links_text = "\n".join([f"{i}: {link['text']} -> {link['url']}" for i, link in enumerate(link_data)])

            prompt = f"""
            Given these links and target hints, select the 5 most interesting for security testing:

            Target hints: {', '.join(target_hints)}

            Links:
            {links_text}

            Return only the URLs of the top 5 most interesting links, one per line.
            Prioritize: admin panels, APIs, upload forms, login pages, configuration pages.
            """

            response = await self.ai_client.analyze(prompt)

            # Extract URLs from response
            urls = []
            for line in response.split('\n'):
                line = line.strip()
                if line.startswith('http'):
                    urls.append(line)

            return urls

        except Exception as e:
            logger.debug(f"AI link prioritization failed: {e}")
            return []

    def _heuristic_select_links(self, link_data: List[Dict]) -> List[str]:
        """Simple heuristic to select interesting links."""
        interesting_keywords = ['admin', 'login', 'api', 'upload', 'config', 'manage', 'dashboard', 'panel']
        scored_links = []

        for link in link_data:
            score = 0
            text_lower = link['text'].lower()
            url_lower = link['url'].lower()

            for keyword in interesting_keywords:
                if keyword in text_lower or keyword in url_lower:
                    score += 1

            if score > 0:
                scored_links.append((score, link['url']))

        # Sort by score and return top URLs
        scored_links.sort(reverse=True)
        return [url for score, url in scored_links[:5]]

    async def _take_screenshot(self, page: Page, url: str) -> str:
        """Take screenshot of interesting pages."""
        try:
            # Create safe filename from URL
            safe_name = re.sub(r'[^\w\-_\.]', '_', urlparse(url).netloc + urlparse(url).path)
            screenshot_path = f"/tmp/crawler_{safe_name}_{int(time.time())}.png"

            await page.screenshot(path=screenshot_path, full_page=True)
            logger.debug(f"📸 Screenshot saved: {screenshot_path}")
            return screenshot_path

        except Exception as e:
            logger.debug(f"Screenshot failed: {e}")
            return None

    async def _extract_request_data(self, request) -> Dict[str, str]:
        """Extract data from HTTP requests."""
        try:
            data = {}

            # Query parameters
            url_parts = urlparse(request.url)
            if url_parts.query:
                query_params = dict(param.split('=') for param in url_parts.query.split('&') if '=' in param)
                data.update(query_params)

            # POST data
            if request.method in ['POST', 'PUT', 'PATCH']:
                try:
                    post_data = request.post_data
                    if post_data:
                        data['post_data'] = post_data[:200]  # Truncate
                except:
                    pass

            return data

        except Exception as e:
            logger.debug(f"Error extracting request data: {e}")
            return {}

    def get_vulnerability_candidates(self) -> List[CrawlDiscovery]:
        """Get discoveries that are most likely to contain vulnerabilities."""
        candidates = []

        for discovery in self.discoveries:
            if discovery.confidence > 0.7 or len(discovery.vulnerability_hints) > 2:
                candidates.append(discovery)

        # Sort by confidence and vulnerability hint count
        candidates.sort(key=lambda d: (d.confidence, len(d.vulnerability_hints)), reverse=True)
        return candidates

    def get_api_endpoints(self) -> List[CrawlDiscovery]:
        """Get discovered API endpoints for targeted testing."""
        return [d for d in self.discoveries if d.discovery_type == 'api_call']

    def get_forms(self) -> List[CrawlDiscovery]:
        """Get discovered forms for injection testing."""
        return [d for d in self.discoveries if d.discovery_type == 'form']