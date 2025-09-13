from pathlib import Path
import random
import time
import requests
import json
#!/usr/bin/env python3
"""
Technology Detector Module - Advanced technology detection with AssetManager
"""

import asyncio
import aiohttp
import logging
import re
import hashlib
from datetime import datetime
from typing import List, Dict, Optional

logger = logging.getLogger("TechnologyDetector")

class TechnologyDetector:
    # --- WAF-aware HTTP helper ---

    def _safe_get(self, url: str, timeout: int = 15, attempts: int = 6, allow_headless: bool = True):

        """Browser-like GET with proxy rotation + headless fallback.

        Uses proxy_list from config.json. Returns a (status_code, final_url, headers_dict, text, via).

        """

        # Load proxies from config.json once

        try:

            cfg = json.loads(Path("config.json").read_text())

            proxies = cfg.get("proxy_list", [])

        except Exception:

            proxies = []

        # Common block markers

        block_pats = [r"Sorry,\s+you have been blocked", r"/cdn-cgi/trace", r"/cdn-cgi/challenge", r"Access Denied", r"PerimeterX", r"Attention Required! \| Cloudflare"]

        def looks_blocked(resp, text):

            if resp is not None and resp.status_code in (403, 429, 503):

                return True

            if resp is not None:

                svr = (resp.headers.get("server") or "").lower()

                if "cloudflare" in svr or "akamai" in svr:

                    return True

            if resp is not None and ("cf-ray" in resp.headers or "cf-cache-status" in resp.headers):

                return True

            text = (text or "")[:10000]

            for p in block_pats:

                if re.search(p, text, re.I):

                    return True

            return False

        def pick_proxy(i):

            if not proxies:

                return {}, None

            p = proxies[i % len(proxies)]

            pmap = {"http": p, "https": p}

            return pmap, p

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

                    return resp.status_code, resp.url, dict(resp.headers), txt, f"requests:{pname or direct}"

            except Exception as e:

                last_exc = e

            time.sleep(0.6 + random.random())

        # headless fallback

        if allow_headless:

            try:

                from selenium import webdriver

                from selenium.webdriver.chrome.options import Options

                opts = Options()

                opts.add_argument("--headless=new")

                opts.add_argument("--disable-gpu")

                opts.add_argument("--no-sandbox")

                opts.add_argument("--disable-dev-shm-usage")

                # Use the next proxy for headless if available

                if proxies:

                    opts.add_argument(f"--proxy-server={proxies[0]}")

                driver = webdriver.Chrome(options=opts)

                driver.set_page_load_timeout(25)

                driver.get(url)

                time.sleep(2.5)

                html = driver.page_source or ""

                driver.quit()

                if html:

                    return 200, url, {}, html, "headless"

            except Exception:

                pass

        raise RuntimeError(f"WAF blocked and headless failed for {url}; last={last_exc}")

    """Advanced technology detection using AssetManager field mappings"""
    
    def __init__(self, asset_manager, config: Dict):
        self.asset_manager = asset_manager  # Use YOUR AssetManager
        self.config = config
        self.max_concurrent = 50
        
        # Technology detection patterns
        self.detection_patterns = self._load_detection_patterns()
        
        logger.info("🔬 TechnologyDetector initialized with AssetManager integration")
    
    async def initialize(self):
        """Initialize technology detector"""
        try:
            # Log initialization using AssetManager
            self.asset_manager.log_activity(
                'TECH_DETECTOR_INIT',
                'TechnologyDetector initialized with advanced fingerprinting'
            )
            
            logger.info("✅ TechnologyDetector initialization complete")
            
        except Exception as e:
            logger.error(f"TechnologyDetector initialization failed: {e}")
    
    def adjust_performance(self, direction: str, max_concurrent: int):
        """Adjust detector performance based on CPU usage"""
        if direction == "increase":
            self.max_concurrent = min(75, max_concurrent // 4)
        else:
            self.max_concurrent = max(20, max_concurrent // 8)
        
        logger.debug(f"TechnologyDetector performance adjusted: {self.max_concurrent} concurrent")
    
    def _load_detection_patterns(self) -> Dict:
        """Load comprehensive technology detection patterns"""
        return {
            'web_servers': {
                'nginx': [r'nginx', r'server:\s*nginx'],
                'apache': [r'apache', r'server:\s*apache'],
                'iis': [r'iis', r'server:\s*microsoft-iis'],
                'cloudflare': [r'cloudflare', r'cf-ray', r'server:\s*cloudflare']
            },
            'languages': {
                'php': [r'x-powered-by.*php', r'set-cookie.*phpsessid', r'\.php'],
                'asp.net': [r'x-powered-by.*asp\.net', r'x-aspnet-version', r'\.aspx', r'\.asp\b'],
                # Broaden Python heuristics to include common servers/frameworks
                'python': [
                    r'server.*python', r'django', r'flask', r'werkzeug', r'gunicorn', r'uvicorn', r'waitress', r'tornado', r'starlette'
                ],
                'ruby': [r'x-powered-by.*ruby', r'server.*ruby', r'rails'],
                'node.js': [r'x-powered-by.*express', r'server.*node']
            },
            'frameworks': {
                'wordpress': [r'wp-content', r'wp-includes', r'/wp-json/', r'wordpress'],
                'drupal': [r'/sites/default/', r'drupal', r'x-drupal-cache'],
                'joomla': [r'/components/', r'/templates/', r'joomla'],
                'django': [r'django', r'csrfmiddlewaretoken'],
                'flask': [r'flask', r'werkzeug'],
                'laravel': [r'laravel', r'_token', r'illuminate'],
                'react': [r'react', r'reactdom', r'__react'],
                'angular': [r'angular', r'ng-app', r'ng-controller'],
                'vue.js': [r'vue\.js', r'vuejs', r'v-if', r'v-for']
            },
            'cms': {
                'shopify': [r'shopify', r'cdn\.shopify', r'myshopify'],
                'magento': [r'magento', r'/skin/frontend/', r'mage/cookies'],
                'woocommerce': [r'woocommerce', r'wc-', r'/woocommerce/']
            },
            'databases': {
                'mysql': [r'mysql', r'mariadb'],
                'postgresql': [r'postgresql', r'postgres'],
                'couchdb': [r'couchdb', r'server:\s*couchdb', r'x-couchdb'],
                'mongodb': [r'mongodb', r'mongo'],
                'redis': [r'redis']
            },
            'security_tools': {
                'cloudflare_waf': [r'cf-ray', r'cloudflare'],
                'aws_waf': [r'awswaf', r'aws-waf'],
                'incapsula': [r'incap_ses', r'visid_incap'],
                'sucuri': [r'sucuri', r'x-sucuri-id'],
                'wordfence': [r'wordfence', r'wfwaf']
            }
        }
    
    async def process_pending_assets(self, session: aiohttp.ClientSession, limit: int = 50) -> int:
        """Process assets needing technology detection"""
        
        # Get assets needing technology detection using AssetManager
        pending_assets = self.asset_manager.get_assets_needing_tech_detection(limit)
        
        if not pending_assets:
            return 0
        
        logger.info(f"🔬 Processing {len(pending_assets)} assets for technology detection")
        
        semaphore = asyncio.Semaphore(min(self.max_concurrent, len(pending_assets)))
        detection_tasks = []
        
        for asset in pending_assets:
            detection_tasks.append(
                self._detect_asset_technologies(asset, session, semaphore)
            )
        
        if detection_tasks:
            results = await asyncio.gather(*detection_tasks, return_exceptions=True)
            completed = sum(1 for r in results if r is True)
            
            logger.info(f"✅ Technology detection completed: {completed}/{len(detection_tasks)} assets")
            return completed
        
        return 0
    
    async def _detect_asset_technologies(self, asset: Dict, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore) -> bool:
        """Detect technologies for a single asset"""
        async with semaphore:
            try:
                url = asset['url']
                asset_id = asset['id']
                
                # Get proxy
                proxy = await self._get_proxy()
                
                async with session.get(url, proxy=proxy, timeout=15, ssl=False) as response:
                    headers = dict(response.headers)
                    content = await response.text()
                    
                    # Perform comprehensive technology detection
                    technologies = await self._comprehensive_technology_analysis(url, headers, content)
                    
                    # Update asset with detected technologies using AssetManager
                    success = self.asset_manager.update_technology_detection(asset_id, technologies)
                    
                    if success:
                        logger.debug(f"🔬 Technologies detected for {url}: {technologies}")
                        return True
                    else:
                        logger.warning(f"⚠️ Failed to update technologies for {url}")
                        return False
                        
            except Exception as e:
                logger.debug(f"Technology detection failed for {asset.get('url', 'unknown')}: {e}")
                return False
    
    async def _comprehensive_technology_analysis(self, url: str, headers: Dict, content: str) -> List[str]:
        """Comprehensive technology analysis"""
        detected_technologies = set()
        
        # Convert headers to lowercase for case-insensitive matching
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        content_lower = content.lower()
        
        # Analyze each technology category
        for category, technologies in self.detection_patterns.items():
            for tech_name, patterns in technologies.items():
                if self._match_technology_patterns(patterns, headers_lower, content_lower):
                    detected_technologies.add(tech_name.title())
        
        # URL-based hints (lightweight, non-binding)
        try:
            if any(ext in url.lower() for ext in ['.aspx', '.asp']):
                detected_technologies.add('ASP.NET')
        except Exception:
            pass

        # Additional analysis methods
        detected_technologies.update(await self._analyze_headers(headers))
        detected_technologies.update(await self._analyze_meta_tags(content))
        detected_technologies.update(await self._analyze_javascript(content))
        detected_technologies.update(await self._analyze_css(content))
        detected_technologies.update(await self._analyze_cookies(headers))
        
        # Version detection
        versioned_technologies = await self._detect_versions(detected_technologies, headers, content)
        
        return list(versioned_technologies)
    
    def _match_technology_patterns(self, patterns: List[str], headers: Dict, content: str) -> bool:
        """Match technology patterns against headers and content"""
        
        # Check headers
        headers_string = ' '.join(f"{k}: {v}" for k, v in headers.items())
        
        for pattern in patterns:
            if re.search(pattern, headers_string, re.IGNORECASE):
                return True
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    async def _analyze_headers(self, headers: Dict) -> set:
        """Analyze response headers for technology indicators"""
        technologies = set()
        
        # Normalize server/X-Powered-By lookups (case-insensitive)
        server = (headers.get('server') or headers.get('Server') or '').lower()
        powered_by = (headers.get('x-powered-by') or headers.get('X-Powered-By') or '').lower()
        
        # Server analysis
        if 'nginx' in server:
            technologies.add('Nginx')
            # Version extraction
            nginx_version = re.search(r'nginx/([\d.]+)', server)
            if nginx_version:
                technologies.add(f'Nginx {nginx_version.group(1)}')
        elif 'apache' in server:
            technologies.add('Apache')
            apache_version = re.search(r'apache/([\d.]+)', server)
            if apache_version:
                technologies.add(f'Apache {apache_version.group(1)}')
        elif 'iis' in server or 'microsoft-iis' in server:
            technologies.add('Microsoft IIS')
            technologies.add('ASP.NET')
        
        # X-Powered-By analysis
        if 'php' in powered_by:
            technologies.add('PHP')
            php_version = re.search(r'php/([\d.]+)', powered_by)
            if php_version:
                technologies.add(f'PHP {php_version.group(1)}')
        elif 'asp.net' in powered_by:
            technologies.add('ASP.NET')

        # Python/Flask common servers
        if any(sig in server for sig in ['werkzeug', 'gunicorn', 'uvicorn', 'waitress', 'tornado']):
            technologies.add('Python')
            # Flask often coexists with Werkzeug/gunicorn
            if 'werkzeug' in server:
                technologies.add('Flask')

        # Node/Express hint
        if 'express' in powered_by or 'express' in server:
            technologies.add('Node.js')

        # CouchDB server header
        if 'couchdb' in server or headers.get('x-couchdb', '').lower():
            technologies.add('CouchDB')
        
        # Security headers analysis
        if 'content-security-policy' in headers:
            technologies.add('Content Security Policy')
        if 'strict-transport-security' in headers:
            technologies.add('HSTS')
        
        return technologies
    
    async def _analyze_meta_tags(self, content: str) -> set:
        """Analyze HTML meta tags for technology indicators"""
        technologies = set()
        
        # Generator meta tag
        generator_pattern = r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']'
        generator_matches = re.findall(generator_pattern, content, re.IGNORECASE)
        
        for generator in generator_matches:
            generator_lower = generator.lower()
            if 'wordpress' in generator_lower:
                technologies.add('WordPress')
                # Version extraction
                wp_version = re.search(r'wordpress\s+([\d.]+)', generator_lower)
                if wp_version:
                    technologies.add(f'WordPress {wp_version.group(1)}')
            elif 'drupal' in generator_lower:
                technologies.add('Drupal')
            elif 'joomla' in generator_lower:
                technologies.add('Joomla')
        
        return technologies
    
    async def _analyze_javascript(self, content: str) -> set:
        """Analyze JavaScript for framework detection"""
        technologies = set()
        content_lower = content.lower()
        
        # React detection
        if 'react' in content_lower and ('reactdom' in content_lower or 'react-dom' in content_lower):
            technologies.add('React')
            # Version detection
            react_version = re.search(r'react["\s]*[:=]["\s]*([\d.]+)', content_lower)
            if react_version:
                technologies.add(f'React {react_version.group(1)}')
        
        # Angular detection
        if 'angular' in content_lower and 'ng-' in content_lower:
            technologies.add('Angular')
        
        # Vue.js detection
        if 'vue' in content_lower and ('vuejs' in content_lower or 'vue.js' in content_lower):
            technologies.add('Vue.js')
        
        # jQuery detection
        if 'jquery' in content_lower:
            technologies.add('jQuery')
            jquery_version = re.search(r'jquery["\s]*[v:]?\s*([\d.]+)', content_lower)
            if jquery_version:
                technologies.add(f'jQuery {jquery_version.group(1)}')
        
        return technologies
    
    async def _analyze_css(self, content: str) -> set:
        """Analyze CSS for framework detection"""
        technologies = set()
        content_lower = content.lower()
        
        # Bootstrap detection
        if 'bootstrap' in content_lower:
            technologies.add('Bootstrap')
            bootstrap_version = re.search(r'bootstrap["\s]*[v:]?\s*([\d.]+)', content_lower)
            if bootstrap_version:
                technologies.add(f'Bootstrap {bootstrap_version.group(1)}')
        
        # Foundation detection
        if 'foundation' in content_lower and 'zurb' in content_lower:
            technologies.add('Foundation')
        
        # Tailwind CSS detection
        if 'tailwind' in content_lower or 'tw-' in content_lower:
            technologies.add('Tailwind CSS')
        
        return technologies
    
    async def _analyze_cookies(self, headers: Dict) -> set:
        """Analyze cookies for technology detection"""
        technologies = set()
        
        set_cookie = headers.get('set-cookie', '').lower()
        
        if 'phpsessid' in set_cookie:
            technologies.add('PHP Session')
        if 'jsessionid' in set_cookie:
            technologies.add('Java Session')
        if 'asp.net_sessionid' in set_cookie:
            technologies.add('ASP.NET Session')
        if '__cfduid' in set_cookie:
            technologies.add('Cloudflare')
        
        return technologies
    
    async def _detect_versions(self, technologies: set, headers: Dict, content: str) -> set:
        """Detect specific versions of detected technologies"""
        versioned_technologies = set(technologies)
        
        # WordPress version detection
        if any('wordpress' in tech.lower() for tech in technologies):
            wp_version = self._detect_wordpress_version(content)
            if wp_version:
                versioned_technologies.add(f'WordPress {wp_version}')
        
        # More version detection can be added here
        
        return versioned_technologies
    
    def _detect_wordpress_version(self, content: str) -> Optional[str]:
        """Detect WordPress version from content"""
        
        # Look for version in generator meta tag
        version_patterns = [
            r'wordpress\s+([\d.]+)',
            r'wp-content/themes/[^/]+/.*?ver=([\d.]+)',
            r'wp-includes/.*?ver=([\d.]+)'
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    async def _get_proxy(self) -> Optional[str]:
        """Get proxy from proxy manager"""
        try:
            from .proxy_manager import ProxyManager
            proxy_manager = ProxyManager(self.asset_manager, self.config)
            return proxy_manager.get_random_proxy()
        except:
            return None
