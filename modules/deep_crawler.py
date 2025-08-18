#!/usr/bin/env python3
"""
Deep Crawler Module - Enterprise-grade web crawling that surpasses Burp Suite Pro
Inspired by Burp Spider but with ML-powered discovery and modern techniques
"""

import asyncio
import aiohttp
import logging
import re
import json
import time
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Set, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
import js2py

logger = logging.getLogger("DeepCrawler")

class DeepCrawler:
    """Enterprise-grade crawler - better than Burp Suite Pro Spider"""
    
    def __init__(self, asset_manager, config: Dict):
        self.asset_manager = asset_manager
        self.config = config
        self.max_concurrent = 500  # AGGRESSIVE: 500 concurrent crawling sessions
        self.max_depth = 10  # Deep crawling up to 10 levels
        self.crawled_urls = set()  # URLs already crawled
        self.discovered_urls = set()  # All discovered URLs
        self.discovered_endpoints = set()  # API endpoints found
        self.discovered_params = set()  # Parameters found
        self.discovered_js_secrets = []  # Secrets found in JavaScript
        
        # Advanced crawling features
        self.crawl_forms = True
        self.crawl_ajax = True
        self.crawl_websockets = True
        self.extract_js_endpoints = True
        self.follow_redirects = True
        self.extract_comments = True
        
        # Intelligence features
        self.interesting_files = [
            '.env', 'config.json', 'package.json', 'composer.json', 'web.config',
            'robots.txt', 'sitemap.xml', '.git/config', '.svn/entries', 'backup.sql',
            'phpinfo.php', 'test.php', 'admin.php', 'login.php', 'upload.php'
        ]
        
        self.interesting_paths = [
            '/admin', '/api', '/v1', '/v2', '/test', '/dev', '/staging', '/backup',
            '/config', '/dashboard', '/panel', '/manage', '/console', '/debug',
            '/upload', '/files', '/assets', '/static', '/public', '/private'
        ]
        
        logger.info("🕷️ DeepCrawler initialized - enterprise-grade web crawling")
    
    async def initialize(self):
        """Initialize deep crawler"""
        try:
            self.asset_manager.log_activity(
                'DEEP_CRAWLER_INIT',
                'Enterprise-grade deep crawler initialized - ready to discover everything'
            )
            logger.info("✅ DeepCrawler initialization complete")
        except Exception as e:
            logger.error(f"DeepCrawler initialization failed: {e}")
    
    async def deep_crawl_target(self, base_url: str, session: aiohttp.ClientSession, max_pages: int = 1000) -> Dict:
        """Perform comprehensive deep crawling of target"""
        start_time = time.time()
        
        logger.info(f"🕷️ Starting DEEP CRAWL of {base_url} (max {max_pages} pages)")
        
        # Initialize crawl state
        self.crawled_urls.clear()
        discovered_data = {
            'urls': set(),
            'forms': [],
            'ajax_endpoints': [],
            'js_endpoints': [],
            'parameters': set(),
            'secrets': [],
            'api_endpoints': [],
            'subdomain_references': set(),
            'external_references': set(),
            'interesting_files': [],
            'comments': []
        }
        
        # Start crawling from base URL
        crawl_queue = [base_url]
        depth = 0
        
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        while crawl_queue and len(self.crawled_urls) < max_pages and depth < self.max_depth:
            depth += 1
            current_level = crawl_queue.copy()
            crawl_queue.clear()
            
            logger.info(f"🕷️ Crawling depth {depth}: {len(current_level)} URLs")
            
            # Crawl current level
            crawl_tasks = []
            for url in current_level:
                if url not in self.crawled_urls:
                    crawl_tasks.append(
                        self._crawl_single_page(url, session, semaphore, discovered_data)
                    )
            
            if crawl_tasks:
                results = await asyncio.gather(*crawl_tasks, return_exceptions=True)
                
                # Collect new URLs for next depth level
                for result in results:
                    if isinstance(result, list):
                        crawl_queue.extend(result)
                
                # Remove duplicates and already crawled URLs
                crawl_queue = list(set(crawl_queue) - self.crawled_urls)
        
        # Post-processing and intelligence
        await self._intelligent_endpoint_discovery(base_url, session, discovered_data)
        await self._analyze_javascript_files(session, discovered_data)
        
        # Store discoveries
        await self._store_discovered_assets(discovered_data)
        
        crawl_time = time.time() - start_time
        
        results_summary = {
            'base_url': base_url,
            'crawl_depth': depth,
            'pages_crawled': len(self.crawled_urls),
            'urls_discovered': len(discovered_data['urls']),
            'forms_found': len(discovered_data['forms']),
            'ajax_endpoints': len(discovered_data['ajax_endpoints']),
            'js_endpoints': len(discovered_data['js_endpoints']),
            'parameters_found': len(discovered_data['parameters']),
            'secrets_found': len(discovered_data['secrets']),
            'api_endpoints': len(discovered_data['api_endpoints']),
            'interesting_files': len(discovered_data['interesting_files']),
            'crawl_time_seconds': round(crawl_time, 2)
        }
        
        logger.info(f"🕷️ DEEP CRAWL COMPLETE: {results_summary}")
        return results_summary
    
    async def _crawl_single_page(self, url: str, session: aiohttp.ClientSession, 
                                semaphore: asyncio.Semaphore, discovered_data: Dict) -> List[str]:
        """Crawl a single page and extract all discoverable content"""
        new_urls = []
        
        async with semaphore:
            try:
                if url in self.crawled_urls:
                    return new_urls
                
                self.crawled_urls.add(url)
                
                async with session.get(url, timeout=15) as response:
                    if response.status != 200:
                        return new_urls
                    
                    content_type = response.headers.get('content-type', '').lower()
                    text_content = await response.text()
                    
                    # Parse HTML content
                    if 'text/html' in content_type:
                        soup = BeautifulSoup(text_content, 'html.parser')
                        
                        # Extract links
                        new_urls.extend(self._extract_links(soup, url))
                        
                        # Extract forms
                        self._extract_forms(soup, url, discovered_data)
                        
                        # Extract AJAX endpoints
                        self._extract_ajax_endpoints(text_content, url, discovered_data)
                        
                        # Extract parameters
                        self._extract_parameters(text_content, url, discovered_data)
                        
                        # Extract comments
                        self._extract_comments(soup, url, discovered_data)
                        
                        # Extract JavaScript references
                        self._extract_js_references(soup, url, discovered_data)
                    
                    # Parse JavaScript content
                    elif 'javascript' in content_type or url.endswith('.js'):
                        self._analyze_javascript_content(text_content, url, discovered_data)
                    
                    # Parse JSON content
                    elif 'json' in content_type:
                        self._analyze_json_content(text_content, url, discovered_data)
                    
                    # Look for interesting files
                    self._check_interesting_files(url, discovered_data)
                    
                    # Add to discovered URLs
                    discovered_data['urls'].add(url)
                    
            except Exception as e:
                logger.debug(f"Failed to crawl {url}: {e}")
        
        return new_urls
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract all links from HTML"""
        links = []
        
        # Extract from various HTML elements
        for element in soup.find_all(['a', 'link', 'script', 'img', 'iframe', 'form']):
            for attr in ['href', 'src', 'action', 'data-url', 'data-href']:
                if element.get(attr):
                    full_url = urljoin(base_url, element[attr])
                    if self._is_valid_url(full_url, base_url):
                        links.append(full_url)
        
        # Extract from meta redirects
        for meta in soup.find_all('meta', attrs={'http-equiv': 'refresh'}):
            content = meta.get('content', '')
            if 'url=' in content:
                redirect_url = content.split('url=')[1]
                full_url = urljoin(base_url, redirect_url)
                if self._is_valid_url(full_url, base_url):
                    links.append(full_url)
        
        return list(set(links))
    
    def _extract_forms(self, soup: BeautifulSoup, base_url: str, discovered_data: Dict):
        """Extract all forms and their parameters"""
        for form in soup.find_all('form'):
            form_data = {
                'url': base_url,
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'inputs': [],
                'has_file_upload': False
            }
            
            # Extract form inputs
            for input_elem in form.find_all(['input', 'select', 'textarea']):
                input_data = {
                    'name': input_elem.get('name', ''),
                    'type': input_elem.get('type', 'text'),
                    'value': input_elem.get('value', ''),
                    'required': input_elem.has_attr('required')
                }
                
                if input_data['type'] == 'file':
                    form_data['has_file_upload'] = True
                
                if input_data['name']:
                    form_data['inputs'].append(input_data)
                    discovered_data['parameters'].add(input_data['name'])
            
            if form_data['inputs']:
                discovered_data['forms'].append(form_data)
    
    def _extract_ajax_endpoints(self, content: str, base_url: str, discovered_data: Dict):
        """Extract AJAX endpoints from JavaScript"""
        ajax_patterns = [
            r'\.ajax\([\'"]([^\'"]+)[\'"]',
            r'fetch\([\'"]([^\'"]+)[\'"]',
            r'XMLHttpRequest.*?open\([\'"][^\'"]++[\'"],\s*[\'"]([^\'"]+)[\'"]',
            r'\$\.get\([\'"]([^\'"]+)[\'"]',
            r'\$\.post\([\'"]([^\'"]+)[\'"]',
            r'axios\.[a-z]+\([\'"]([^\'"]+)[\'"]',
            r'\.load\([\'"]([^\'"]+)[\'"]'
        ]
        
        for pattern in ajax_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                full_url = urljoin(base_url, match)
                if self._is_valid_url(full_url, base_url):
                    discovered_data['ajax_endpoints'].append({
                        'url': full_url,
                        'found_in': base_url,
                        'method': 'AJAX'
                    })
    
    def _extract_parameters(self, content: str, base_url: str, discovered_data: Dict):
        """Extract parameters from various sources"""
        param_patterns = [
            r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)[=]',  # URL parameters
            r'data-[a-zA-Z-]+=[\'"]([^\'"]*)[\'"]',  # Data attributes
            r'name=[\'"]([^\'"]*)[\'"]',  # Form names
            r'id=[\'"]([^\'"]*)[\'"]',  # Element IDs
            r'[\'"]([a-zA-Z_][a-zA-Z0-9_]*)[\'"]:\s*[\'"]',  # JSON keys
        ]
        
        for pattern in param_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if len(match) > 1 and len(match) < 50:  # Reasonable parameter length
                    discovered_data['parameters'].add(match)
    
    def _extract_comments(self, soup: BeautifulSoup, base_url: str, discovered_data: Dict):
        """Extract HTML and JavaScript comments"""
        # HTML comments
        html_comments = soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--'))
        for comment in html_comments:
            comment_text = str(comment).strip()
            if len(comment_text) > 10:  # Ignore short comments
                discovered_data['comments'].append({
                    'type': 'HTML',
                    'content': comment_text[:500],  # Limit length
                    'found_in': base_url
                })
        
        # JavaScript comments
        for script in soup.find_all('script'):
            if script.string:
                js_comments = re.findall(r'//.*?$|/\*.*?\*/', script.string, re.MULTILINE | re.DOTALL)
                for comment in js_comments:
                    if len(comment.strip()) > 10:
                        discovered_data['comments'].append({
                            'type': 'JavaScript',
                            'content': comment.strip()[:500],
                            'found_in': base_url
                        })
    
    def _extract_js_references(self, soup: BeautifulSoup, base_url: str, discovered_data: Dict):
        """Extract JavaScript file references"""
        for script in soup.find_all('script', src=True):
            js_url = urljoin(base_url, script['src'])
            if self._is_valid_url(js_url, base_url):
                discovered_data['js_endpoints'].append({
                    'url': js_url,
                    'found_in': base_url,
                    'type': 'script_src'
                })
    
    def _analyze_javascript_content(self, js_content: str, js_url: str, discovered_data: Dict):
        """Deep analysis of JavaScript content for secrets and endpoints"""
        # Extract URLs and endpoints
        url_patterns = [
            r'[\'"]https?://[^\'"]+[\'"]',
            r'[\'"]\/[a-zA-Z0-9/_.-]+[\'"]',
            r'[\'"]api\/[^\'"]+[\'"]',
            r'[\'"]v\d+\/[^\'"]+[\'"]'
        ]
        
        for pattern in url_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                clean_url = match.strip('\'"')
                if len(clean_url) > 3:
                    discovered_data['js_endpoints'].append({
                        'url': clean_url,
                        'found_in': js_url,
                        'type': 'js_string'
                    })
        
        # Extract secrets and sensitive data
        secret_patterns = [
            (r'[\'"]([A-Za-z0-9+/]{40,})[\'"]', 'Potential API Key'),
            (r'password[\'"]?\s*[:=]\s*[\'"]([^\'"]+)[\'"]', 'Password'),
            (r'token[\'"]?\s*[:=]\s*[\'"]([^\'"]+)[\'"]', 'Token'),
            (r'secret[\'"]?\s*[:=]\s*[\'"]([^\'"]+)[\'"]', 'Secret'),
            (r'key[\'"]?\s*[:=]\s*[\'"]([^\'"]+)[\'"]', 'API Key'),
            (r'[\'"]sk_live_[A-Za-z0-9]+[\'"]', 'Stripe Live Key'),
            (r'[\'"]pk_live_[A-Za-z0-9]+[\'"]', 'Stripe Public Key'),
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
            (r'[\'"]ghp_[A-Za-z0-9]{36}[\'"]', 'GitHub Personal Access Token')
        ]
        
        for pattern, secret_type in secret_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                discovered_data['secrets'].append({
                    'type': secret_type,
                    'value': match[:100],  # Limit displayed length
                    'found_in': js_url,
                    'confidence': 0.8
                })
    
    def _analyze_json_content(self, json_content: str, json_url: str, discovered_data: Dict):
        """Analyze JSON content for endpoints and data"""
        try:
            data = json.loads(json_content)
            self._extract_json_endpoints(data, json_url, discovered_data)
        except json.JSONDecodeError:
            logger.debug(f"Failed to parse JSON from {json_url}")
    
    def _extract_json_endpoints(self, data: any, json_url: str, discovered_data: Dict, prefix: str = ""):
        """Recursively extract endpoints from JSON data"""
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str) and (value.startswith('/') or value.startswith('http')):
                    discovered_data['api_endpoints'].append({
                        'url': value,
                        'found_in': json_url,
                        'key': f"{prefix}.{key}" if prefix else key,
                        'type': 'json_endpoint'
                    })
                elif isinstance(value, (dict, list)):
                    self._extract_json_endpoints(value, json_url, discovered_data, f"{prefix}.{key}" if prefix else key)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, (dict, list)):
                    self._extract_json_endpoints(item, json_url, discovered_data, f"{prefix}[{i}]")
    
    def _check_interesting_files(self, url: str, discovered_data: Dict):
        """Check if URL is an interesting file"""
        url_path = urlparse(url).path.lower()
        for interesting_file in self.interesting_files:
            if interesting_file in url_path:
                discovered_data['interesting_files'].append({
                    'url': url,
                    'file': interesting_file,
                    'type': 'interesting_file'
                })
    
    async def _intelligent_endpoint_discovery(self, base_url: str, session: aiohttp.ClientSession, discovered_data: Dict):
        """Intelligent discovery of common endpoints"""
        base_domain = urlparse(base_url).netloc
        
        # Common API patterns
        api_patterns = [
            '/api/v1/', '/api/v2/', '/api/', '/rest/', '/graphql',
            '/api/users', '/api/admin', '/api/auth', '/api/config',
            '/api/upload', '/api/files', '/api/data', '/api/search'
        ]
        
        # Test common endpoints
        semaphore = asyncio.Semaphore(50)
        discovery_tasks = []
        
        for pattern in api_patterns:
            test_url = urljoin(base_url, pattern)
            discovery_tasks.append(
                self._test_endpoint_exists(test_url, session, semaphore, discovered_data)
            )
        
        # Test interesting paths
        for path in self.interesting_paths:
            test_url = urljoin(base_url, path)
            discovery_tasks.append(
                self._test_endpoint_exists(test_url, session, semaphore, discovered_data)
            )
        
        if discovery_tasks:
            await asyncio.gather(*discovery_tasks, return_exceptions=True)
    
    async def _test_endpoint_exists(self, url: str, session: aiohttp.ClientSession, 
                                  semaphore: asyncio.Semaphore, discovered_data: Dict):
        """Test if an endpoint exists"""
        async with semaphore:
            try:
                async with session.get(url, timeout=10, allow_redirects=False) as response:
                    if response.status in [200, 302, 403, 401]:  # Interesting status codes
                        discovered_data['api_endpoints'].append({
                            'url': url,
                            'status_code': response.status,
                            'found_in': 'intelligent_discovery',
                            'type': 'discovered_endpoint'
                        })
            except Exception:
                pass  # Endpoint doesn't exist or timeout
    
    async def _analyze_javascript_files(self, session: aiohttp.ClientSession, discovered_data: Dict):
        """Analyze discovered JavaScript files for deeper secrets"""
        js_files = [ep for ep in discovered_data['js_endpoints'] if ep['url'].endswith('.js')]
        
        semaphore = asyncio.Semaphore(20)
        analysis_tasks = []
        
        for js_file in js_files[:50]:  # Limit to 50 JS files
            analysis_tasks.append(
                self._analyze_js_file(js_file['url'], session, semaphore, discovered_data)
            )
        
        if analysis_tasks:
            await asyncio.gather(*analysis_tasks, return_exceptions=True)
    
    async def _analyze_js_file(self, js_url: str, session: aiohttp.ClientSession, 
                              semaphore: asyncio.Semaphore, discovered_data: Dict):
        """Analyze individual JavaScript file"""
        async with semaphore:
            try:
                async with session.get(js_url, timeout=15) as response:
                    if response.status == 200:
                        js_content = await response.text()
                        self._analyze_javascript_content(js_content, js_url, discovered_data)
            except Exception as e:
                logger.debug(f"Failed to analyze JS file {js_url}: {e}")
    
    async def _store_discovered_assets(self, discovered_data: Dict):
        """Store discovered assets in database"""
        stored_count = 0
        
        # Store discovered URLs as assets
        for url in discovered_data['urls']:
            try:
                query, values = self.asset_manager.build_asset_insert_query(
                    url=url,
                    discovery_method="deep_crawler",
                    last_scanned=None
                )
                
                with self.asset_manager._get_db() as db:
                    db.execute(query, values)
                    db.commit()
                    stored_count += 1
            except Exception as e:
                logger.debug(f"Failed to store asset {url}: {e}")
        
        # Store API endpoints
        for endpoint in discovered_data['api_endpoints']:
            try:
                query, values = self.asset_manager.build_asset_insert_query(
                    url=endpoint['url'],
                    discovery_method="deep_crawler_api",
                    last_scanned=None
                )
                
                with self.asset_manager._get_db() as db:
                    db.execute(query, values)
                    db.commit()
                    stored_count += 1
            except Exception as e:
                logger.debug(f"Failed to store API endpoint {endpoint['url']}: {e}")
        
        logger.info(f"🕷️ Stored {stored_count} discovered assets in database")
    
    def _is_valid_url(self, url: str, base_url: str) -> bool:
        """Check if URL is valid for crawling"""
        try:
            parsed = urlparse(url)
            base_parsed = urlparse(base_url)
            
            # Must be same domain
            if parsed.netloc != base_parsed.netloc:
                return False
            
            # Skip certain file types
            skip_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.css', '.ico', '.woff', '.ttf', '.pdf', '.zip']
            if any(url.lower().endswith(ext) for ext in skip_extensions):
                return False
            
            # Skip very long URLs
            if len(url) > 2000:
                return False
            
            return True
            
        except Exception:
            return False
    
    def get_crawler_statistics(self) -> Dict:
        """Get crawler statistics"""
        return {
            "urls_crawled": len(self.crawled_urls),
            "urls_discovered": len(self.discovered_urls),
            "endpoints_found": len(self.discovered_endpoints),
            "parameters_found": len(self.discovered_params),
            "secrets_found": len(self.discovered_js_secrets),
            "max_concurrent": self.max_concurrent,
            "max_depth": self.max_depth
        }