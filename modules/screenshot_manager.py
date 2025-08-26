#!/usr/bin/env python3
"""
Screenshot Manager Module - Advanced screenshot capture with AssetManager
"""

import asyncio
import logging
import subprocess
import os
import hashlib
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from typing import Dict, Optional

# Use universal AuthManager (policy-driven) to refresh sessions
try:
    from .auth_manager import AuthManager
except Exception:
    AuthManager = None  # Fallback if not available; we will skip refresh

logger = logging.getLogger("ScreenshotManager")

class ScreenshotManager:
    """Advanced screenshot management using AssetManager field mappings"""
    
    def __init__(self, asset_manager, config: Dict):
        self.asset_manager = asset_manager  # Use YOUR AssetManager
        self.config = config
        self.max_concurrent = 100  # AGGRESSIVE: 100 concurrent screenshots with 1Gb bandwidth
        
        # Screenshot settings
        self.screenshot_dir = Path(config.get('screenshot_dir', 'screenshots'))
        self.screenshot_dir.mkdir(exist_ok=True)
        # Evidence bundle directory (DOM, headers, request log)
        self.evidence_dir = Path(config.get('evidence_dir', 'evidence'))
        self.evidence_dir.mkdir(exist_ok=True)
        # Storage state persistence per domain
        self.storage_state_dir = Path(config.get('storage_state_dir', 'storage_states'))
        self.storage_state_dir.mkdir(exist_ok=True)

        # AGGRESSIVE Browser settings for speed
        self.browser_timeout = 8  # Fast timeout - don't wait for slow sites
        self.window_size = "1366,768"
        self.enabled = True

        logger.info("📸 ScreenshotManager initialized with AssetManager integration")
        # Lazy flag to note if Playwright is usable for authenticated screenshots
        self._playwright_available_checked = False
        self._playwright_available = False
    
    async def initialize(self):
        """Initialize screenshot manager with hang prevention"""
        try:
            # Use asyncio.wait_for to prevent hangs
            chrome_available = await asyncio.wait_for(
                self._check_chrome_availability(),
                timeout=8.0
            )

            if not chrome_available:
                logger.warning("⚠️ Chrome not available - screenshots will be disabled")
                self.enabled = False
            
            # Log initialization using AssetManager
            self.asset_manager.log_activity(
                'SCREENSHOT_INIT',
                f'ScreenshotManager initialized - Chrome available: {chrome_available}'
            )
            
            logger.info("✅ ScreenshotManager initialization complete")
            
        except asyncio.TimeoutError:
            logger.warning("⚠️ Chrome check timed out - screenshots will be disabled")
            self.enabled = False
        except Exception as e:
            logger.error(f"ScreenshotManager initialization failed: {e}")
            self.enabled = False
            # Continue anyway - don't let screenshot issues block the engine
    
    def adjust_performance(self, direction: str, max_concurrent: int):
        """Adjust screenshot performance based on CPU usage"""
        if direction == "increase":
            self.max_concurrent = min(15, max_concurrent // 20)
        else:
            self.max_concurrent = max(5, max_concurrent // 30)
        
        logger.debug(f"ScreenshotManager performance adjusted: {self.max_concurrent} concurrent")
    
    async def _check_chrome_availability(self) -> bool:
        """Check if Chrome/Chromium is available for screenshots"""
        chrome_commands = [
            'google-chrome',
            'chromium-browser',
            'chromium',
            'chrome'
        ]
        
        for chrome_cmd in chrome_commands:
            try:
                # More robust Chrome check with shorter timeout
                result = subprocess.run(
                    [chrome_cmd, '--version'],
                    capture_output=True,
                    text=True,
                    timeout=2  # Reduced from 5 to 2 seconds
                )
                if result.returncode == 0:
                    logger.info(f"✅ Found Chrome: {chrome_cmd}")
                    return True
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
                logger.debug(f"Chrome check failed for {chrome_cmd}: {e}")
                continue
            except Exception as e:
                logger.debug(f"Unexpected error checking {chrome_cmd}: {e}")
                continue
        
        return False

    async def _check_playwright_availability(self) -> bool:
        """Lightweight check if Playwright is importable and Chromium can launch.

        We avoid any network or installation. Only checks imports and a no-op start/stop.
        """
        if self._playwright_available_checked:
            return self._playwright_available
        self._playwright_available_checked = True
        try:
            from playwright.async_api import async_playwright  # type: ignore
        except Exception as e:
            logger.debug(f"Playwright import failed: {e}")
            self._playwright_available = False
            return False
        # Do not actually launch here to keep it light; assume available if import works
        self._playwright_available = True
        return True
    
    async def process_pending_screenshots(self, session, limit: int = 30) -> int:
        """Process assets needing screenshots"""
        
        if not self.enabled:
            return 0

        # Get assets needing screenshots using AssetManager
        pending_assets = self.asset_manager.get_assets_needing_screenshots(limit)

        if not pending_assets:
            return 0
        
        logger.info(f"📸 Processing {len(pending_assets)} assets for screenshot capture")
        
        semaphore = asyncio.Semaphore(min(self.max_concurrent, len(pending_assets)))
        screenshot_tasks = []
        
        for asset in pending_assets:
            screenshot_tasks.append(
                self._capture_asset_screenshot(asset, semaphore)
            )
        
        if screenshot_tasks:
            results = await asyncio.gather(*screenshot_tasks, return_exceptions=True)
            completed = sum(1 for r in results if r is True)
            
            logger.info(f"✅ Screenshot capture completed: {completed}/{len(screenshot_tasks)} assets")
            return completed
        
        return 0
    
    async def _capture_asset_screenshot(self, asset: Dict, semaphore: asyncio.Semaphore) -> bool:
        """Capture screenshot for single asset"""
        async with semaphore:
            try:
                url = asset['url']
                asset_id = asset['id']
                
                # Generate screenshot filename
                screenshot_path = self._generate_screenshot_path(url)
                
                # Load per-domain auth from DB (dynamic) and merge into effective config
                eff_cfg, auth_cookie, auth_domain = self._build_effective_auth_config(url)

                use_auth = bool(auth_cookie) and (not auth_domain or (auth_domain in url))

                if use_auth and await self._check_playwright_availability():
                    success = await self._take_screenshot_with_playwright(url, screenshot_path, auth_cookie, auth_domain, eff_cfg)
                else:
                    # Fallback to CLI Chrome (fast path, unauthenticated)
                    success = await self._take_screenshot_with_chrome(url, screenshot_path)
                
                if success:
                    # Update asset with screenshot path using AssetManager
                    update_success = self.asset_manager.update_screenshot_path(asset_id, str(screenshot_path))
                    
                    if update_success:
                        logger.debug(f"📸 Screenshot captured and stored: {url}")
                        return True
                    else:
                        logger.warning(f"⚠️ Screenshot captured but database update failed: {url}")
                        return False
                else:
                    logger.debug(f"❌ Screenshot capture failed: {url}")
                    return False
                    
            except Exception as e:
                logger.error(f"Screenshot capture error for {asset.get('url', 'unknown')}: {e}")
                return False

    async def capture_url(self, url: str) -> Optional[str]:
        """Public helper to capture a screenshot for an arbitrary URL.

        Returns the screenshot path on success, or None on failure.
        Does not write to the database. Universal and target-agnostic.
        """
        try:
            if not self.enabled:
                return None
            screenshot_path = self._generate_screenshot_path(url)

            eff_cfg, auth_cookie, auth_domain = self._build_effective_auth_config(url)
            use_auth = bool(auth_cookie) and (not auth_domain or (auth_domain in url))

            if use_auth and await self._check_playwright_availability():
                ok = await self._take_screenshot_with_playwright(url, screenshot_path, auth_cookie, auth_domain, eff_cfg)
            else:
                ok = await self._take_screenshot_with_chrome(url, screenshot_path)

            return str(screenshot_path) if ok else None
        except Exception as e:
            logger.debug(f"capture_url error for {url}: {e}")
            return None
    
    def _generate_screenshot_path(self, url: str) -> Path:
        """Generate unique screenshot file path"""
        try:
            parsed = urlparse(url)
            
            # Create safe filename
            hostname = parsed.netloc.replace(':', '_').replace('/', '_')
            path_part = parsed.path.replace('/', '_').replace('?', '_').replace('&', '_')
            
            # Create unique identifier
            url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
            
            # Generate filename
            filename = f"{hostname}_{path_part}_{url_hash}.png"
            filename = filename.replace('__', '_').strip('_')
            
            return self.screenshot_dir / filename
            
        except Exception as e:
            logger.debug(f"Error generating screenshot path for {url}: {e}")
            # Fallback to hash-based filename
            url_hash = hashlib.md5(url.encode()).hexdigest()
            return self.screenshot_dir / f"screenshot_{url_hash}.png"

    def _derive_evidence_paths(self, screenshot_path: Path) -> Dict[str, Path]:
        """Given a screenshot path, derive sidecar evidence file paths."""
        base = screenshot_path.stem
        return {
            'html': (self.evidence_dir / f"{base}.html"),
            'headers': (self.evidence_dir / f"{base}.headers.json"),
            'requests': (self.evidence_dir / f"{base}.requests.jsonl"),
        }

    def _storage_state_path_for(self, domain: str) -> Path:
        safe = domain.replace(':', '_').replace('/', '_')
        return self.storage_state_dir / f"{safe}.json"
    
    async def _take_screenshot_with_chrome(self, url: str, screenshot_path: Path) -> bool:
        """Take screenshot using headless Chrome"""
        try:
            chrome_commands = [
                'google-chrome',
                'chromium-browser', 
                'chromium',
                'chrome'
            ]
            
            chrome_cmd = None
            for cmd in chrome_commands:
                try:
                    # Test if command exists
                    subprocess.run([cmd, '--version'], capture_output=True, timeout=2)
                    chrome_cmd = cmd
                    break
                except:
                    continue
            
            if not chrome_cmd:
                logger.debug("No Chrome browser found for screenshots")
                return False
            
            # Chrome arguments for headless screenshot
            chrome_args = [
                chrome_cmd,
                '--headless',
                '--no-sandbox',
                '--disable-gpu',
                '--disable-software-rasterizer',
                '--disable-dev-shm-usage',
                '--disable-extensions',
                '--disable-plugins',
                '--disable-background-timer-throttling',
                f'--window-size={self.window_size}',
                f'--screenshot={screenshot_path}',
                '--virtual-time-budget=10000',  # 10 second budget
            ]

            # Optional: allow disabling images for speed via config
            try:
                if bool(self.config.get('screenshot_disable_images', False)):
                    chrome_args.insert(8, '--disable-images')
            except Exception:
                pass
            
            # Keep unauthenticated fast path; authenticated handled by Playwright
            
            chrome_args.append(url)
            
            # Execute Chrome screenshot
            process = await asyncio.create_subprocess_exec(
                *chrome_args,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            
            try:
                await asyncio.wait_for(process.wait(), timeout=self.browser_timeout)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                logger.debug(f"Screenshot timeout for {url}")
                return False
            
            # Check if screenshot was created and is valid
            if screenshot_path.exists():
                file_size = screenshot_path.stat().st_size
                
                if file_size > 1000:  # Valid PNG should be > 1KB
                    logger.debug(f"✅ Screenshot captured: {url} ({file_size} bytes)")
                    return True
                else:
                    # Remove invalid screenshot
                    screenshot_path.unlink()
                    logger.debug(f"⚠️ Screenshot too small, removed: {url}")
                    return False
            else:
                logger.debug(f"❌ Screenshot file not created: {url}")
                return False
                
        except Exception as e:
            logger.debug(f"Chrome screenshot failed for {url}: {e}")
            return False

    def _build_effective_auth_config(self, url: str):
        """Build an effective config for this URL by merging stored per-domain policy and cookie."""
        try:
            from urllib.parse import urlparse
            host = (urlparse(url).hostname or '').strip().lower()
            # Start from base config
            cfg = dict(self.config)
            cookie_string = cfg.get('auth_cookie')
            domain = cfg.get('auth_domain') or host
            # Load from DB cookies table if present
            try:
                with self.asset_manager._get_db() as db:
                    row = db.execute("SELECT cookie, persistent, auth_keys, policy FROM cookies WHERE domain=?", (host,)).fetchone()
                    if row and (row[0] or row[3]):
                        if row[0]:
                            cookie_string = row[0]
                        # include locked pairs and auth key names in cfg
                        try:
                            if row[1]:
                                import json as _json
                                pl = _json.loads(row[1])
                                if isinstance(pl, list):
                                    cfg['auth_persistent_pairs'] = [str(x) for x in pl]
                            if row[2]:
                                import json as _json
                                aks = _json.loads(row[2])
                                if isinstance(aks, list):
                                    cfg['auth_keys'] = [str(x) for x in aks]
                        except Exception:
                            pass
                        if row[3]:
                            import json
                            try:
                                pol = json.loads(row[3]) if row[3] else None
                                if isinstance(pol, dict):
                                    if pol.get('headers'):
                                        cfg['auth_headers'] = pol['headers']
                                    if pol.get('bearer'):
                                        cfg['auth_bearer'] = pol['bearer']
                                    if pol.get('local_storage'):
                                        cfg['auth_local_storage'] = pol['local_storage']
                                    if pol.get('session_storage'):
                                        cfg['auth_session_storage'] = pol['session_storage']
                                    if pol.get('login'):
                                        cfg['login_url'] = pol['login'].get('url')
                                        cfg['login_username'] = pol['login'].get('username')
                                        cfg['login_password'] = pol['login'].get('password')
                            except Exception:
                                pass
            except Exception:
                pass
            return cfg, cookie_string, domain
        except Exception:
            return dict(self.config), self.config.get('auth_cookie'), self.config.get('auth_domain')

    async def _refresh_authentication(self, auth_domain: str) -> Optional[str]:
        """Universal session refresh using policy-driven AuthManager.

        - Loads policy from cookies table for the given domain
        - Replays generic login with CSRF extraction
        - Persists fresh cookie back to DB
        """
        try:
            if not AuthManager:
                return None
            am = AuthManager(self.asset_manager, self.config)
            cookie, pol = am.load_policy(auth_domain)
            if not pol or not (pol.get('login') and pol['login'].get('url')):
                return None
            # Use AuthManager to refresh session
            new_cookie = await am.refresh_session(auth_domain, pol)
            return new_cookie
        except Exception as e:
            logger.debug(f"Failed to refresh authentication generically: {e}")
            return None

    async def _take_screenshot_with_playwright(self, url: str, screenshot_path: Path, auth_cookie: Optional[str], auth_domain: Optional[str], effective_config: Optional[Dict]=None) -> bool:
        """Take authenticated screenshot using Playwright with universal cookie injection.

        - Auto-refreshes authentication if needed
        - Parses cookie string or dict
        - Scopes cookies to the target hostname or provided auth_domain
        - Waits for DOM ready and captures a high-quality PNG
        """
        try:
            from urllib.parse import urlparse
            from playwright.async_api import async_playwright  # type: ignore
            import json, random

            cfg = effective_config or self.config
            parsed = urlparse(url)
            hostname = parsed.hostname or ''
            # Determine cookie scope URL including port when present
            netloc = parsed.netloc or hostname
            scope_url = f"{parsed.scheme or 'http'}://{netloc}"

            # Auto-refresh authentication if we have an auth_domain (policy-driven)
            if auth_domain:
                fresh_cookie = await self._refresh_authentication(auth_domain)
                if fresh_cookie:
                    auth_cookie = fresh_cookie
                    logger.debug(f"🔄 Using fresh authentication for screenshot")

            # Normalize cookies into a name->value mapping
            cookie_map: Dict[str, str] = {}
            if isinstance(auth_cookie, dict):
                cookie_map = {str(k): str(v) for k, v in auth_cookie.items()}
            elif isinstance(auth_cookie, str):
                # Parse Cookie header format: "k1=v1; k2=v2; ..."
                try:
                    parts = [p.strip() for p in auth_cookie.split(';') if p.strip()]
                    for p in parts:
                        if '=' in p:
                            k, v = p.split('=', 1)
                            cookie_map[k.strip()] = v.strip()
                except Exception:
                    cookie_map = {}

            # Enforce locked cookie pairs except declared auth keys
            try:
                locked = cfg.get('auth_persistent_pairs') or []
                auth_names = set([str(x).strip() for x in (cfg.get('auth_keys') or []) if str(x).strip()])
                for kv in locked:
                    if isinstance(kv, str) and '=' in kv:
                        k, v = kv.split('=', 1)
                        k = k.strip(); v = v.strip()
                        if not k or not v:
                            continue
                        if k in auth_names:
                            cookie_map.setdefault(k, v)
                        else:
                            cookie_map[k] = v
            except Exception:
                pass

            if not cookie_map:
                logger.debug("No auth cookies parsed; falling back to unauthenticated Chrome path")
                return await self._take_screenshot_with_chrome(url, screenshot_path)

            # Launch lightweight Playwright Chromium
            async with async_playwright() as pw:
                # Stealth-ish profile and proxy support
                stealth = bool(self.config.get('stealth_mode', True))
                proxy_server = self.config.get('proxy_server') or os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy')
                # Dynamic proxy selection from ProxyManager if available
                try:
                    selector = self.config.get('proxy_selector')
                    if callable(selector):
                        sel = selector()
                        if sel:
                            proxy_server = sel
                except Exception:
                    pass
                browser_args = [
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-gpu',
                ]
                browser = await pw.chromium.launch(headless=True, args=browser_args)

                # Randomized but realistic UA if not provided
                ua = cfg.get('user_agent')
                if not ua:
                    ua_pool = [
                        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36',
                        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0 Safari/537.36',
                        'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15',
                    ]
                    ua = random.choice(ua_pool)

                extra_headers = {}
                # Authorization header injection
                if cfg.get('auth_bearer'):
                    extra_headers['Authorization'] = f"Bearer {cfg['auth_bearer']}"
                if isinstance(cfg.get('auth_headers'), dict):
                    for k,v in cfg['auth_headers'].items():
                        extra_headers[str(k)] = str(v)

                context_kwargs = dict(
                    ignore_https_errors=True,
                    viewport={"width": 1366, "height": 768},
                    user_agent=ua,
                    locale=self.config.get('locale', 'en-US'),
                    color_scheme=self.config.get('color_scheme', 'light'),
                    java_script_enabled=True,
                )
                if extra_headers:
                    context_kwargs['extra_http_headers'] = extra_headers
                if proxy_server:
                    context_kwargs['proxy'] = { 'server': proxy_server }

                # Load persisted storage_state if present
                storage_state_path = self._storage_state_path_for(hostname)
                if storage_state_path.exists():
                    context_kwargs['storage_state'] = str(storage_state_path)

                context = await browser.new_context(**context_kwargs)

                # Stealth tweaks and storage injection
                if stealth:
                    try:
                        await context.add_init_script("""
// Reduce automation fingerprints
Object.defineProperty(navigator, 'webdriver', { get: () => false });
window.chrome = { runtime: {} };
Object.defineProperty(navigator, 'languages', { get: () => ['en-US','en'] });
Object.defineProperty(navigator, 'platform', { get: () => 'Win32' });
""")
                    except Exception:
                        pass

                # Inject localStorage/sessionStorage if provided
                ls = cfg.get('auth_local_storage') or {}
                ss = cfg.get('auth_session_storage') or {}
                if ls or ss:
                    init_snippets = []
                    for k, v in (ls or {}).items():
                        init_snippets.append(f"try{{localStorage.setItem('{k}', '{str(v)}')}}catch(e){{}};")
                    for k, v in (ss or {}).items():
                        init_snippets.append(f"try{{sessionStorage.setItem('{k}', '{str(v)}')}}catch(e){{}};")
                    if init_snippets:
                        try:
                            await context.add_init_script("\n".join(init_snippets))
                        except Exception:
                            pass

                # Convert to Playwright cookie objects using url-based scoping (works for IPs)
                pw_cookies = []
                for name, value in cookie_map.items():
                    if not name:
                        continue
                    pw_cookies.append({
                        'name': name,
                        'value': value,
                        'url': scope_url,
                        'path': '/',
                        'httpOnly': False,
                        'secure': parsed.scheme == 'https',
                    })

                # Add cookies to context before navigation
                try:
                    await context.add_cookies(pw_cookies)
                except Exception as e:
                    logger.debug(f"Failed to add cookies to context: {e}")

                page = await context.new_page()
                # Collect request/response evidence
                req_log = []
                async def on_response(resp):
                    try:
                        if len(req_log) >= 50:
                            return
                        item = {
                            'url': resp.url,
                            'status': resp.status,
                        }
                        try:
                            hdrs = await resp.all_headers()
                            # keep small subset by limiting size
                            item['headers'] = {k: v[:200] for k, v in hdrs.items()}
                        except Exception:
                            pass
                        req_log.append(item)
                    except Exception:
                        pass
                page.on('response', on_response)
                try:
                    main_resp = await page.goto(url, wait_until='domcontentloaded', timeout=self.browser_timeout * 1000)
                except Exception as e:
                    logger.debug(f"Navigation error for {url}: {e}")
                    main_resp = None

                # Smart auth validation: detect login and pre-warm root, then retry once; attempt auto-login if policy provided
                try:
                    html = await page.content()
                    looks_login = ('type="password"' in html.lower()) or ('name="password"' in html.lower()) or ('signin' in html.lower()) or ('login' in html.lower())
                    if looks_login:
                        # Try auto-login if policy available
                        login_url = cfg.get('login_url')
                        login_user = cfg.get('login_username')
                        login_pass = cfg.get('login_password')
                        attempted_login = False
                        if login_url and login_user and login_pass:
                            attempted_login = await self._attempt_auto_login(context, login_url, login_user, login_pass)
                        if attempted_login:
                            try:
                                main_resp = await page.goto(url, wait_until='domcontentloaded', timeout=5000)
                            except Exception:
                                pass
                        else:
                            # Fallback: pre-warm root then retry
                            root = f"{parsed.scheme or 'http'}://{parsed.hostname}/"
                            try:
                                await page.goto(root, wait_until='domcontentloaded', timeout=4000)
                                await page.wait_for_timeout(300)
                                main_resp = await page.goto(url, wait_until='domcontentloaded', timeout=4000)
                            except Exception:
                                pass
                except Exception:
                    pass
                try:
                    # Give the page a brief moment for client-side rendering
                    await page.wait_for_timeout(300)
                    await page.screenshot(path=str(screenshot_path), full_page=True)
                finally:
                    # Persist storage state for future sessions (per-domain)
                    try:
                        await context.storage_state(path=str(self._storage_state_path_for(hostname)))
                    except Exception:
                        pass

                    # Save evidence bundle (HTML, headers, request log)
                    try:
                        ev = self._derive_evidence_paths(screenshot_path)
                        try:
                            html = await page.content()
                        except Exception:
                            html = ''
                        try:
                            headers_obj = {}
                            if main_resp is not None:
                                headers_obj = await main_resp.all_headers()
                            evidence = {
                                'url': url,
                                'status': (main_resp.status if main_resp is not None else None),
                                'headers': headers_obj,
                            }
                        except Exception:
                            evidence = {'url': url}
                        # Write files
                        ev['html'].write_text(html, encoding='utf-8', errors='ignore')
                        with ev['headers'].open('w', encoding='utf-8') as f:
                            json.dump(evidence, f, ensure_ascii=False, indent=2)
                        with ev['requests'].open('w', encoding='utf-8') as f:
                            for item in req_log:
                                f.write(json.dumps(item, ensure_ascii=False) + "\n")
                    except Exception:
                        pass

                    await context.close()
                    await browser.close()

            # Validate screenshot
            if screenshot_path.exists() and screenshot_path.stat().st_size > 1000:
                logger.debug(f"✅ Authenticated screenshot captured via Playwright: {url}")
                return True
            else:
                if screenshot_path.exists():
                    try:
                        screenshot_path.unlink()
                    except Exception:
                        pass
                logger.debug(f"⚠️ Auth screenshot too small or missing for: {url}")
                return False
        except Exception as e:
            logger.debug(f"Playwright screenshot failed for {url}: {e}")
            return False

    async def _attempt_auto_login(self, context, login_url: str, username: str, password: str) -> bool:
        """Universal login attempt: navigate to login_url, fill credentials, submit.

        Heuristics only — no site-specific logic. Works for common patterns.
        """
        try:
            page = await context.new_page()
            await page.goto(login_url, wait_until='domcontentloaded', timeout=8000)
            # Try find username/email field
            user_selectors = [
                'input[name="username"]', 'input#username', 'input[name="email"]', 'input#email', 'input[name="user"]'
            ]
            pass_selectors = [
                'input[type="password"]', 'input[name="password"]', 'input#password'
            ]
            submitted = False
            for sel in user_selectors:
                try:
                    if await page.locator(sel).count() > 0:
                        await page.fill(sel, username)
                        submitted = True
                        break
                except Exception:
                    continue
            for sel in pass_selectors:
                try:
                    if await page.locator(sel).count() > 0:
                        await page.fill(sel, password)
                        submitted = True
                        break
                except Exception:
                    continue
            # Click a submit/login button
            try:
                btn = page.locator('button[type="submit"], input[type="submit"], button:has-text("Login"), button:has-text("Sign in")')
                if await btn.count() > 0:
                    await btn.first.click()
                else:
                    # fallback: press Enter in password field
                    if await page.locator('input[type="password"]').count() > 0:
                        await page.locator('input[type="password"]').first.press('Enter')
            except Exception:
                pass
            # Wait for possible redirect
            await page.wait_for_load_state('domcontentloaded', timeout=6000)
            await page.wait_for_timeout(400)
            # Consider success if no obvious login markers
            content = (await page.content()).lower()
            looks_login = ('type="password"' in content) or ('name="password"' in content) or ('signin' in content) or ('login' in content)
            ok = not looks_login
            await page.close()
            return ok
        except Exception:
            return False
    
    def get_screenshot_statistics(self) -> Dict:
        """Get screenshot capture statistics"""
        try:
            screenshot_files = list(self.screenshot_dir.glob("*.png"))
            total_screenshots = len(screenshot_files)
            total_size = sum(f.stat().st_size for f in screenshot_files)
            
            return {
                "total_screenshots": total_screenshots,
                "total_size_mb": round(total_size / (1024 * 1024), 2),
                "average_size_kb": round(total_size / max(total_screenshots, 1) / 1024, 2),
                "screenshot_directory": str(self.screenshot_dir)
            }
        except Exception as e:
            logger.debug(f"Error getting screenshot statistics: {e}")
            return {
                "total_screenshots": 0,
                "total_size_mb": 0,
                "average_size_kb": 0,
                "screenshot_directory": str(self.screenshot_dir)
            }
    
    def cleanup_old_screenshots(self, days_old: int = 30):
        """Clean up screenshots older than specified days"""
        try:
            import time
            cutoff_time = time.time() - (days_old * 24 * 60 * 60)
            cleaned = 0
            
            for screenshot_file in self.screenshot_dir.glob("*.png"):
                if screenshot_file.stat().st_mtime < cutoff_time:
                    screenshot_file.unlink()
                    cleaned += 1
            
            logger.info(f"🧹 Cleaned up {cleaned} old screenshots (>{days_old} days)")
            
            # Log cleanup using AssetManager
            self.asset_manager.log_activity(
                'SCREENSHOT_CLEANUP',
                f'Cleaned up {cleaned} old screenshots older than {days_old} days'
            )
            
            return cleaned
            
        except Exception as e:
            logger.error(f"Screenshot cleanup failed: {e}")
            return 0
