#!/usr/bin/env python3
"""
🚀 MODULAR HIGH-PERFORMANCE VULNERABILITY SCANNER
Main orchestrator that coordinates all scanning modules
"""

import asyncio
import aiohttp
import logging
from logging.handlers import RotatingFileHandler
import os
import time
import psutil
import os, time
START_TIME = time.time()
from pathlib import Path
from datetime import datetime
import json
import hashlib

# Import all modular components
from modules.seclists_manager import SecListsManager
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.ultimate_discovery_engine import UltimateDiscoveryEngine
from modules.technology_detector import TechnologyDetector
from modules.proxy_manager import ProxyManager
from modules.ml_engine import MLEngine
from modules.screenshot_manager import ScreenshotManager
from modules.waf_bypass import WAFBypass
from modules.reconnaissance import ReconnaissanceEngine
from modules.nuclei_scanner import NucleiVulnerabilityScanner

# Import Multi-AI Pentester Team (XBOW-inspired)
from modules.multi_ai_pentester_team import MultiAIPentesterTeam

# Import YOUR AssetManager for centralized field mapping
from asset_manager import AssetManager

# Configure logging (file + console)
LOG_DIR = Path(__file__).resolve().parent / 'logs'
LOG_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("ModularScanner")
logger.setLevel(logging.INFO)

_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# File handler (rotating)
file_handler = RotatingFileHandler(LOG_DIR / 'engine.log', maxBytes=2_000_000, backupCount=3)
file_handler.setFormatter(_formatter)
file_handler.setLevel(logging.INFO)
logger.addHandler(file_handler)

# Console handler (keep succinct during prod)
console_handler = logging.StreamHandler()
console_handler.setFormatter(_formatter)
console_handler.setLevel(logging.INFO)
logger.addHandler(console_handler)

# Quiet noisy libraries
logging.getLogger('aiohttp').setLevel(logging.WARNING)
logging.getLogger('asyncio').setLevel(logging.WARNING)

# Load configuration
BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / 'config.json'

try:
    import json
    with open(CONFIG_PATH) as f:
        CONFIG = json.load(f)
except FileNotFoundError:
    CONFIG = {"cpu_target_utilization": 75, "proxy_list": []}

class ModularVulnerabilityScanner:
    """Main scanner orchestrator - coordinates all modules through AssetManager"""
    
    def __init__(self):
        # Track scanned assets to avoid duplicates
        self._scanned_assets = set()
        # Track completed domains to prevent infinite loops
        self.completed_domains = set()
        # Initialize YOUR AssetManager first (centralized field mapping)
        self.asset_manager = AssetManager()
        
        # ✅ CHECK FOR AUTHENTICATION - ENV VARS OR DATABASE
        self.auth_cookie = os.environ.get('MODSCAN_AUTH_COOKIE')
        self.auth_domain = os.environ.get('MODSCAN_AUTH_DOMAIN')
        
        # If no env vars, check database for saved cookies and policy
        if not self.auth_cookie:
            try:
                import sqlite3
                conn = sqlite3.connect('lean_recon.db')
                cursor = conn.execute("SELECT domain, cookie, policy FROM cookies LIMIT 1")
                row = cursor.fetchone()
                if row:
                    self.auth_domain = row[0]
                    self.auth_cookie = row[1]
                    policy_json = (row[2] if len(row) > 2 else None)
                    logger.info(f"🔐 Loaded authentication from database for: {self.auth_domain}")
                    logger.info(f"🍪 Using saved session cookie: {self.auth_cookie[:30]}...")
                    # Parse policy and merge into config
                    try:
                        import json as _json
                        pol = _json.loads(policy_json) if policy_json else None
                        if isinstance(pol, dict):
                            CONFIG.update({
                                'auth_headers': pol.get('headers'),
                                'auth_bearer': pol.get('bearer'),
                                'auth_local_storage': pol.get('local_storage'),
                                'auth_session_storage': pol.get('session_storage'),
                            })
                            login_cfg = pol.get('login') or {}
                            CONFIG.update({
                                'login_url': login_cfg.get('url'),
                                'login_username': login_cfg.get('username'),
                                'login_password': login_cfg.get('password'),
                            })
                    except Exception as e:
                        logger.debug(f"Failed parsing auth policy: {e}")
                conn.close()
            except Exception as e:
                logger.debug(f"Failed to load auth from database: {e}")
        
        if self.auth_cookie:
            logger.info(f"🔐 Authenticated scanning enabled for domain: {self.auth_domain}")
        else:
            logger.info("🌐 Unauthenticated scanning mode")
        
        # ✅ ADD AUTHENTICATION TO CONFIG
        AUTH_CONFIG = CONFIG.copy()
        AUTH_CONFIG['auth_cookie'] = self.auth_cookie
        AUTH_CONFIG['auth_domain'] = self.auth_domain
        
        # Initialize all scanning modules with AssetManager reference and authentication
        self.seclists_manager = SecListsManager(self.asset_manager, AUTH_CONFIG)
        self.vulnerability_scanner = VulnerabilityScanner(self.asset_manager, AUTH_CONFIG)
        self.proxy_manager = ProxyManager(self.asset_manager, AUTH_CONFIG)  # Initialize proxy manager first
        # Bind dynamic proxy chooser into screenshot config (callable)
        AUTH_CONFIG['proxy_selector'] = getattr(self.proxy_manager, 'get_random_proxy', None)
        self.discovery_engine = UltimateDiscoveryEngine(self.asset_manager, AUTH_CONFIG)
        self.technology_detector = TechnologyDetector(self.asset_manager, AUTH_CONFIG)
        self.ml_engine = MLEngine(self.asset_manager, AUTH_CONFIG)
        self.screenshot_manager = ScreenshotManager(self.asset_manager, AUTH_CONFIG)
        self.waf_bypass = WAFBypass(self.asset_manager, AUTH_CONFIG)
        self.reconnaissance = ReconnaissanceEngine(self.asset_manager, AUTH_CONFIG)
        self.nuclei_scanner = NucleiVulnerabilityScanner(self.asset_manager, AUTH_CONFIG)
        
        # Initialize Multi-AI Pentester Team (XBOW-inspired)
        self.ai_pentester_team = MultiAIPentesterTeam(self.asset_manager, AUTH_CONFIG)
        
        # Runtime controls and state will be set up after initialization
        
        # Dynamic resource-based performance settings (cap CPU target to 50%)
        self.cpu_target = min(CONFIG.get("cpu_target_utilization", 85), 50)
        self.memory_target = CONFIG.get("memory_target_utilization", 60)  # Allow up to 60% memory
        
        # Start with very conservative limits to prevent overload
        self.base_concurrent = 10
        self.max_concurrent = self.base_concurrent
        self.session_limit = self.max_concurrent * 2
        # Runtime controls and state
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        self.seen = set()  # de-duplication of scan keys
        self.findings_path = BASE_DIR / "findings.jsonl"
        
        logger.info("🚀 Modular Scanner initialized - all modules using AssetManager field mappings")
        # Nuclei long scan settings
        self.nuclei_long_enabled = CONFIG.get('nuclei_long_scan_enabled', True)
        self.nuclei_long_ttl_hours = CONFIG.get('nuclei_long_scan_ttl_hours', 24)

    async def _monitor_discovery_progress(self, domain: str, start_time: float, timeout: int):
        """Monitor discovery progress and alert about potential hangs."""
        try:
            alert_count = 0
            while True:
                await asyncio.sleep(60)
                alert_count += 1
                current_duration = time.time() - start_time
                if current_duration >= 60:
                    logger.warning(f"🐌 SLOW DISCOVERY ALERT #{alert_count}: {domain} taking {current_duration:.1f}s (normal: <60s)")
                if current_duration >= timeout:
                    break
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"Discovery monitoring error for {domain}: {e}")
    
    async def _initialize_all_modules_old(self):
        """Legacy initialization (kept for reference)"""
        
        # Initialize modules in parallel with timeout protection
        init_tasks = [
            self.seclists_manager.initialize(),
            # Skip VulnerabilityScanner - hangs on proxy checking
            # self.vulnerability_scanner.initialize(),
            self.technology_detector.initialize(),
            self.proxy_manager.initialize(),
            self.ml_engine.initialize(),
            self.screenshot_manager.initialize(),
            self.waf_bypass.initialize(),
            self.reconnaissance.initialize()
            # Skip AI team initialization that's causing hangs
            # self.ai_pentester_team.initialize()
        ]
        
        try:
            logger.info("🔧 Starting module initialization with 10s timeout...")
            # Add 10 second timeout to prevent initialization hangs
            results = await asyncio.wait_for(
                asyncio.gather(*init_tasks, return_exceptions=True),
                timeout=10.0
            )
            
            # Check for any exceptions in results
            logger.info("🔧 Checking initialization results...")
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.warning(f"⚠️ Module {i} initialization failed: {result}")
                    
            logger.info("✅ All modules initialized successfully")
        except asyncio.TimeoutError:
            logger.error("💥 Module initialization timed out - continuing with partial initialization")
            # Continue anyway - don't let one bad module kill the engine
        except Exception as e:
            logger.error(f"💥 Module initialization failed: {e} - continuing anyway")
        
        logger.info("✅ All modules initialized using AssetManager mappings")

    async def _with_timeout(self, coro, timeout: float = 8.0):
        """Run coroutine with timeout, returning (ok, error)."""
        try:
            await asyncio.wait_for(coro, timeout=timeout)
            return True, None
        except Exception as e:
            return False, e

    async def initialize_all_modules(self):
        """Initialize all modules concurrently; continue on failures."""

        modules = [
            ("SecListsManager", self.seclists_manager.initialize()),
            ("VulnerabilityScanner", self.vulnerability_scanner.initialize()),
            ("TechnologyDetector", self.technology_detector.initialize()),
            ("ProxyManager", self.proxy_manager.initialize()),
            ("MLEngine", self.ml_engine.initialize()),
            ("ScreenshotManager", self.screenshot_manager.initialize()),
            ("WAFBypass", self.waf_bypass.initialize()),
            ("ReconnaissanceEngine", self.reconnaissance.initialize()),
            # Skip AI team - causing hangs
            # ("MultiAIPentesterTeam", self.ai_pentester_team.initialize()),
        ]

        tasks = [self._with_timeout(coro, 8.0) for _, coro in modules]
        results = await asyncio.gather(*tasks, return_exceptions=False)

        failed = []
        for (name, _), (ok, err) in zip(modules, results):
            if ok:
                logger.info(f"✅ {name} initialization complete")
            else:
                failed.append(name)
                logger.warning(f"⚠️ {name} initialization failed: {err}")

        if failed:
            logger.warning(f"⚠️ Modules initialized with warnings: {', '.join(failed)}")
        else:
            logger.info("✅ All modules initialized")

    def monitor_and_adjust_performance(self) -> float:
        """Dynamic resource-based performance scaling"""
        try:
            current_cpu = psutil.cpu_percent(interval=0.2)
            current_memory = psutil.virtual_memory().percent
            
            # Calculate available resource capacity
            cpu_headroom = max(0, self.cpu_target - current_cpu)
            memory_headroom = max(0, self.memory_target - current_memory)
            
            # Scale concurrency conservatively to keep under target
            if current_cpu > self.cpu_target or current_memory > self.memory_target:
                # Over resource limits - scale down
                self.max_concurrent = max(10, int(self.max_concurrent * 0.7))
                self._adjust_module_performance("decrease")
            elif cpu_headroom > 15 and memory_headroom > 15:
                # Plenty of headroom - scale up slowly
                self.max_concurrent = min(self.base_concurrent * 2, int(self.max_concurrent * 1.05))
                self._adjust_module_performance("increase")
            
            # Update semaphore with new limit
            self.semaphore = asyncio.Semaphore(self.max_concurrent)
            self.session_limit = self.max_concurrent * 2
            
            logger.info(f"[Resources] CPU: {current_cpu:.1f}%/{self.cpu_target}% | Memory: {current_memory:.1f}%/{self.memory_target}% | Concurrent: {self.max_concurrent}")
            
            return current_cpu
        except Exception as e:
            logger.error(f"Resource monitoring error: {e}")
            return 50.0
    
    def _adjust_module_performance(self, direction: str):
        """Adjust performance of all modules"""
        modules = [
            self.vulnerability_scanner, self.discovery_engine,
            self.technology_detector, self.screenshot_manager
        ]
        
        for module in modules:
            if hasattr(module, 'adjust_performance'):
                module.adjust_performance(direction, self.max_concurrent)
    
    async def run_modular_progressive_scan(self):
        """Run progressive scanning using all modules"""
        logger.info("🔧 About to initialize all modules...")
        await self.initialize_all_modules()
        logger.info("🔧 Modules initialized, creating session...")
        
        logger.info("🎯 Starting Modular Progressive Vulnerability Scanner")
        
        # Create high-performance session
        connector = aiohttp.TCPConnector(
            limit=min(2000, self.max_concurrent),
            ssl=False,
            ttl_dns_cache=300,
            keepalive_timeout=30,
            enable_cleanup_closed=True
        )
        
        # ✅ INCLUDE AUTHENTICATION HEADERS IF AVAILABLE
        session_headers = {'User-Agent': 'ModularScanner/2025'}
        if self.auth_cookie and self.auth_domain:
            session_headers['Cookie'] = self.auth_cookie
            logger.info(f"🔐 Adding authentication headers for {self.auth_domain}")
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=15),
            headers=session_headers
        ) as session:
            
            scan_cycle = 0
            
            while True:
                try:
                    scan_cycle += 1
                    cpu_usage = self.monitor_and_adjust_performance()
                    
                    # Skip proxy health check to prevent hangs - proxies checked during initialization
                    logger.debug("⏭️ Skipping proxy health check to prevent hangs")
                    
                    logger.info(f"🔄 MODULAR SCAN CYCLE {scan_cycle} - CPU: {cpu_usage:.1f}%")
                    
                    # If in Direct URL Testing mode, run a streamlined, ordered pipeline:
                    # 1) Profile (to populate status_code)
                    # 2) Vulnerability scan
                    # 3) (Optional) AI pentesting
                    # Skip discovery and advanced recon entirely in this mode.
                    import os as _os
                    if _os.environ.get('MODSCAN_DIRECT_URL_TESTING'):
                        logger.info("🧪 Direct URL Testing pipeline: Tier2 -> Tier3 -> Tier4 (no discovery/recon)")
                        # Inline scan of exact URLs passed from dashboard (if provided)
                        try:
                            raw = _os.environ.get('MODSCAN_DIRECT_URLS')
                            if raw:
                                import json as _json
                                try:
                                    direct_list = _json.loads(raw)
                                except Exception:
                                    direct_list = [u.strip() for u in raw.replace('\r','\n').split('\n') if u.strip()]
                                assets_inline = [{'id': -1, 'url': u, 'status_code': 200, 'tech_stack': ''} for u in direct_list if u.startswith('http')]
                                if assets_inline:
                                    logger.info(f"⚡ Direct: Inline Tier3 scan of {len(assets_inline)} user URLs…")
                                    await self.vulnerability_scanner.scan_assets_for_vulnerabilities(assets_inline, session, semaphore_limit=8)
                                    logger.info("✅ Direct: Inline Tier3 scan complete")
                        except Exception as _dash:
                            logger.warning(f"Direct: inline scan of user URLs failed: {_dash}")

                        # Tier 2
                        try:
                            await self._tier2_modular_profiling(session)
                            logger.info("🧪 Direct: Tier2 completed; proceeding to Tier3…")
                        except Exception as _e2:
                            logger.warning(f"Tier 2 profiling error (direct): {_e2}")
                        # Immediate inline Tier 3 scan on latest direct URLs (guaranteed activity)
                        try:
                            with self.asset_manager._get_db() as db:
                                rows = db.execute(
                                    "SELECT url FROM assets WHERE title='Direct URL Test' ORDER BY id DESC LIMIT 8"
                                ).fetchall()
                            urls_inline = [r[0] for r in rows if r and r[0]]
                            if urls_inline:
                                assets_inline = [{'id': -1, 'url': u, 'status_code': 200, 'tech_stack': ''} for u in urls_inline]
                                logger.info(f"⚡ Direct: Inline Tier3 scan of {len(assets_inline)} URLs…")
                                await self.vulnerability_scanner.scan_assets_for_vulnerabilities(assets_inline, session, semaphore_limit=8)
                                logger.info("✅ Direct: Inline Tier3 scan complete")
                        except Exception as _inl:
                            logger.warning(f"Direct: inline scan failed: {_inl}")

                        # Tier 3 with timeout watchdog so dashboard never looks stuck
                        try:
                            logger.info("➡️ Direct: Starting Tier3 vulnerability scanning…")
                            await asyncio.wait_for(self._tier3_modular_vulnerability_scanning(session), timeout=60)
                            logger.info("✅ Direct: Tier3 completed")
                        except asyncio.TimeoutError:
                            logger.warning("⏰ Direct: Tier3 timed out after 60s — running emergency fallback on latest direct URLs")
                            # Emergency minimal inline scan on last few direct URLs
                            try:
                                with self.asset_manager._get_db() as db:
                                    rows = db.execute(
                                        "SELECT url FROM assets WHERE title='Direct URL Test' ORDER BY id DESC LIMIT 5"
                                    ).fetchall()
                                urls = [r[0] for r in rows if r and r[0]]
                                if urls:
                                    assets = [{'id': -1, 'url': u, 'status_code': 200, 'tech_stack': ''} for u in urls]
                                    await self.vulnerability_scanner.scan_assets_for_vulnerabilities(assets, session, semaphore_limit=8)
                                    logger.info(f"✅ Direct: Emergency fallback scanned {len(urls)} URLs")
                                else:
                                    logger.info("✅ Direct: No URLs available for emergency fallback")
                            except Exception as _ef:
                                logger.warning(f"Direct: emergency fallback failed: {_ef}")
                        except Exception as _e3:
                            logger.warning(f"Tier 3 vuln scanning error (direct): {_e3}")
                        # If dashboard requested only these URLs, skip the broader Tier3/Tier4 to avoid scanning everything
                        if _os.environ.get('MODSCAN_ONLY_DIRECT_URLS'):
                            logger.info("✅ Direct: Only user URLs requested — skipping broader Tier3/Tier4 this cycle")
                            continue

                        # Tier 4 (optional)
                        try:
                            await self._tier4_multi_ai_pentesting(session)
                        except Exception as _e4:
                            logger.debug(f"Tier 4 AI pentesting error (direct): {_e4}")
                    else:
                        # Execute all tiers using modular components (parallel where safe)
                        tier_tasks = [
                            self._tier1_modular_discovery(session),
                            self._tier2_modular_profiling(session),
                            self._tier3_modular_vulnerability_scanning(session),
                            self._tier4_multi_ai_pentesting(session),
                            self._tier5_modular_advanced_recon(session)
                        ]
                        await asyncio.gather(*tier_tasks, return_exceptions=True)
                    
                    # Report progress using AssetManager
                    await self._report_modular_progress(scan_cycle)
                    
                    await asyncio.sleep(5)
                    
                except KeyboardInterrupt:
                    logger.info("🛑 Modular scanner stopped by user")
                    break
                except Exception as e:
                    logger.error(f"Modular scan cycle error: {e}")
                    await asyncio.sleep(10)
    
    async def _tier1_modular_discovery(self, session: aiohttp.ClientSession):
        """Tier 1: Ultimate Discovery using UltimateDiscoveryEngine module"""
        try:
            # Get scope domains using AssetManager (schema tolerant)
            domains = self.asset_manager.get_scope_domains()
            
            if not domains:
                logger.warning("⚠️  No scope domains found")
                return
            
            # Check if this is Direct URL Testing mode (skip discovery)
            import os
            if os.environ.get('MODSCAN_DIRECT_URL_TESTING'):
                logger.info("⚡ DIRECT URL TESTING MODE: Skipping discovery, testing provided URLs only")
                return  # Skip discovery entirely
            
            logger.info(f"🔍 TIER 1: Ultimate discovery of {len(domains)} domains")
            
            total_discovered = 0
            # Process each domain with comprehensive discovery
            for domain in domains[:3]:  # Process 3 domains per cycle
                clean_domain = domain.replace('*.', '').replace('http://', '').replace('https://', '')
                
                # Check if domain already completed to prevent infinite loops
                if clean_domain in self.completed_domains:
                    logger.info(f"⏭️ Skip Tier-1: {clean_domain} already completed in this session")
                    continue
                
                logger.info(f"🎯 Running comprehensive discovery on: {clean_domain}")
                
                # Use Ultimate Discovery Engine with timeout detection and hang alerts
                discovered_urls = []
                discovery_start_time = time.time()
                discovery_timeout = 300  # 5 minutes timeout for discovery
                
                try:
                    # Start discovery task with timeout protection
                    discovery_task = asyncio.create_task(
                        self.discovery_engine.comprehensive_discovery(clean_domain)
                    )
                    
                    # Monitor for hangs and alert if taking too long
                    monitor_task = asyncio.create_task(
                        self._monitor_discovery_progress(clean_domain, discovery_start_time, discovery_timeout)
                    )
                    
                    # Wait for discovery or timeout
                    discovered_urls = await asyncio.wait_for(discovery_task, timeout=discovery_timeout)
                    monitor_task.cancel()
                    
                    discovery_duration = time.time() - discovery_start_time
                    logger.info(f"⚡ Discovery completed in {discovery_duration:.1f}s for {clean_domain}")
                    
                except asyncio.TimeoutError:
                    discovery_duration = time.time() - discovery_start_time
                    logger.error(f"⏰ HANG ALERT: Discovery timeout after {discovery_duration:.1f}s for {clean_domain}")
                    logger.warning(f"🚨 HUNG OPERATION DETECTED: {clean_domain} discovery exceeded {discovery_timeout}s timeout")
                    discovered_urls = []
                except Exception as e:
                    discovery_duration = time.time() - discovery_start_time
                    logger.error(f"🚨 Discovery error after {discovery_duration:.1f}s for {clean_domain}: {e}")
                    discovered_urls = []
                
                if discovered_urls:
                    logger.info(f"✅ Found {len(discovered_urls)} candidate URLs for {clean_domain}")
                    
                    # Validate candidates quickly (HEAD/GET) and only persist non-404s
                    method = "authenticated_discovery" if (self.auth_cookie and (self.auth_domain == clean_domain)) else "ultimate_discovery"
                    valid_statuses = set(list(range(200, 300)) + [301,302,307,308,401,403])
                    sem = asyncio.Semaphore(50)

                    async def try_fetch(u: str):
                        from urllib.parse import urlsplit, urlunsplit
                        async with sem:
                            for attempt in range(2):
                                url_try = u
                                if attempt == 1:
                                    try:
                                        sp = urlsplit(u)
                                        alt = 'http' if sp.scheme.lower() == 'https' else 'https'
                                        url_try = urlunsplit((alt, sp.netloc, sp.path or '/', sp.query, ''))
                                    except Exception:
                                        pass
                                try:
                                    # HEAD first
                                    async with session.head(url_try, allow_redirects=True, timeout=8) as r:
                                        if r.status in valid_statuses:
                                            return url_try, r.status
                                except Exception:
                                    pass
                                try:
                                    async with session.get(url_try, allow_redirects=True, timeout=10) as r:
                                        if r.status in valid_statuses:
                                            return url_try, r.status
                                except Exception:
                                    pass
                            return None, None

                    tasks = [try_fetch(u) for u in discovered_urls]
                    results = await asyncio.gather(*tasks, return_exceptions=False)
                    added = 0
                    for (url_ok, status_ok) in results:
                        if url_ok and status_ok is not None:
                            try:
                                self.asset_manager.add_asset(url_ok, clean_domain, method)
                                # Persist quick status fields
                                try:
                                    fields = {}
                                    fields['status_code'] = status_ok
                                    fields['last_scanned'] = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                                    self.asset_manager.update_asset_fields(self.asset_manager.get_asset_by_url(url_ok)['id'], fields)
                                except Exception:
                                    pass
                                added += 1
                            except Exception as e:
                                logger.debug(f"Error storing asset {url_ok}: {e}")
                    total_discovered += added
                    logger.info(f"✅ Valid URLs persisted: {added} for {clean_domain}")
                
                # Mark domain as completed to prevent infinite loops (regardless of results)
                self.completed_domains.add(clean_domain)
                logger.info(f"✅ COMPLETED: {clean_domain} discovery finished - marked as complete")
            
            logger.info(f"✅ TIER 1: Discovered {total_discovered} total URLs using UltimateDiscoveryEngine")
            
        except Exception as e:
            logger.error(f"Tier 1 ultimate discovery error: {e}")
    
    async def _tier2_modular_profiling(self, session: aiohttp.ClientSession):
        """Tier 2: Profiling using TechnologyDetector and ScreenshotManager"""
        try:
            import os as _os
            # First: basic HTTP profiling for assets lacking status_code
            try:
                filled = await self.reconnaissance.basic_profile_round(session, limit=500)
                if filled:
                    logger.info(f"🔎 TIER 2: Basic profiling filled {filled} assets")
            except Exception as e:
                logger.warning(f"Tier 2 basic profiling failed: {e}")

            # In Direct URL Testing mode, skip heavy tasks (tech detect + screenshots) to avoid stalls
            if _os.environ.get('MODSCAN_DIRECT_URL_TESTING'):
                logger.info("⏭️  TIER 2: Direct mode — skipping tech detection and screenshots")
                return

            # Otherwise, timebox each heavy task so Tier 3 isn’t blocked
            tech_completed = 0
            screenshot_completed = 0
            try:
                tech_completed = await asyncio.wait_for(
                    self.technology_detector.process_pending_assets(session, limit=75), timeout=10
                )
            except asyncio.TimeoutError:
                logger.warning("⏰ TIER 2: Technology detection timed out after 10s — continuing")
            except Exception as e:
                logger.warning(f"TIER 2: Technology detection failed: {e}")

            try:
                screenshot_completed = await asyncio.wait_for(
                    self.screenshot_manager.process_pending_screenshots(session, limit=30), timeout=10
                )
            except asyncio.TimeoutError:
                logger.warning("⏰ TIER 2: Screenshot processing timed out after 10s — continuing")
            except Exception as e:
                logger.warning(f"TIER 2: Screenshot processing failed: {e}")

            if (isinstance(tech_completed, int) and tech_completed > 0) or (isinstance(screenshot_completed, int) and screenshot_completed > 0):
                logger.info(f"✅ TIER 2: Technology detection: {int(tech_completed) if isinstance(tech_completed,int) else 0}, Screenshots: {int(screenshot_completed) if isinstance(screenshot_completed,int) else 0}")
        
        except Exception as e:
            logger.error(f"Tier 2 modular profiling error: {e}")
    
    async def _tier3_modular_vulnerability_scanning(self, session: aiohttp.ClientSession):
        """Tier 3: Vulnerability scanning using VulnerabilityScanner module"""
        try:
            logger.info("🔧 TIER 3: Preparing assets for vulnerability scanning…")
            # Get assets ready for scanning using AssetManager
            per_cycle = max(10, int(self.max_concurrent))
            ready_assets = self.asset_manager.get_assets_ready_for_deep_scan(per_cycle)
            
            if not ready_assets:
                logger.info("⚠️  TIER 3: No ready assets from main query — attempting direct URL fallback")
                try:
                    with self.asset_manager._get_db() as db:
                        rows = db.execute(
                            "SELECT url, IFNULL(tech_stack,''), IFNULL(status_code, 200) FROM assets WHERE title='Direct URL Test' ORDER BY id DESC LIMIT 10"
                        ).fetchall()
                    fallback_assets = [
                        {'id': -1, 'url': r[0], 'tech_stack': r[1] or '', 'status_code': r[2] or 200}
                        for r in rows if r and r[0]
                    ]
                    if fallback_assets:
                        ready_assets = fallback_assets
                        logger.info(f"🧪 TIER 3 fallback: scanning {len(ready_assets)} direct URLs")
                    else:
                        logger.info("✅ TIER 3: No direct URLs to scan in fallback")
                        return
                except Exception as fe:
                    logger.warning(f"TIER 3 fallback failed: {fe}")
                    return
            
            # ML-driven prioritization: order ready_assets by quick ML score if available
            try:
                if getattr(self.vulnerability_scanner, 'ml_engine', None):
                    scores = self.vulnerability_scanner.ml_engine.quick_score_assets(ready_assets)
                    ready_assets.sort(key=lambda a: scores.get(a['url'], 0.0), reverse=True)
            except Exception as e:
                logger.debug(f"ML prioritization skipped: {e}")
            logger.info(f"🚨 TIER 3: Modular vulnerability scanning {len(ready_assets)} assets")
            try:
                preview = ", ".join(a.get('url','') for a in ready_assets[:5])
                if len(ready_assets) > 5:
                    preview += ", …"
                logger.info(f"🔬 TIER 3 preview: {preview}")
            except Exception:
                pass
            
            # Process vulnerabilities using VulnerabilityScanner module
            vulnerability_results = await self.vulnerability_scanner.scan_assets_for_vulnerabilities(
                ready_assets, session, semaphore_limit=max(8, int(self.max_concurrent/2))
            )
            
            total_vulns = sum(len(vulns) for vulns in vulnerability_results if vulns)
            # Report attempted assets, not only those with findings
            assets_scanned = len(ready_assets)
            
            if total_vulns > 0:
                logger.warning(f"🚨 TIER 3: Found {total_vulns} vulnerabilities across {assets_scanned} assets")
                
                # Log using AssetManager
                self.asset_manager.log_activity(
                    'VULNERABILITY_FOUND',
                    f"Modular vulnerability scanning found {total_vulns} vulnerabilities"
                )
            else:
                logger.info(f"✅ TIER 3: Scanned {assets_scanned} assets, no vulnerabilities found")
            
        except Exception as e:
            logger.error(f"Tier 3 modular vulnerability scanning error: {e}")
        finally:
            # Opportunistically run a long Nuclei scan in background
            if self.nuclei_long_enabled:
                try:
                    await self._tier_long_nuclei_scan()
                except Exception as e2:
                    logger.debug(f"Background Nuclei long scan error: {e2}")
    
    async def _tier4_multi_ai_pentesting(self, session: aiohttp.ClientSession):
        """Tier 4: Multi-AI Pentester Team (XBOW-inspired parallel testing)"""
        try:
            # Get assets ready for AI pentesting
            # If CPU already near target, skip AI for this cycle
            if psutil.cpu_percent(interval=0.1) > (self.cpu_target - 5):
                logger.info("⏭️  Skipping AI pentesting this cycle to respect CPU target")
                return
            ready_assets = self.asset_manager.get_assets_ready_for_deep_scan(max(10, int(self.max_concurrent/2)))
            
            if not ready_assets:
                return
            
            # Extract URLs for testing
            # Limit to top-N URLs per cycle to control load
            urls = [asset['url'] for asset in ready_assets if asset.get('url')][:max(10, int(self.max_concurrent/2))]
            
            if not urls:
                return
            
            logger.info(f"🤖 TIER 4: Multi-AI Pentester Team testing {len(urls)} assets")
            logger.info("🎯 AI Specialists: SQLi Hunter, XSS Hunter, AuthZ Hunter, InfoDisc Hunter")
            
            # TEMPORARY: Skip AI team to test VulnerabilityScanner with real payloads
            # findings = await self.ai_pentester_team.parallel_pentest(urls, max_concurrent=8)
            findings = []  # Skip AI team for now
            
            if findings:
                # Get team performance summary
                summary = await self.ai_pentester_team.get_team_summary()
                
                logger.warning(f"🚨 TIER 4: Multi-AI Team found {len(findings)} vulnerabilities!")
                logger.info(f"📊 Team Performance: {summary['findings_by_severity']}")
                
                for agent, count in summary['findings_by_agent'].items():
                    logger.info(f"   {agent}: {count} findings")
                
                # Log using AssetManager
                self.asset_manager.log_activity(
                    'MULTI_AI_PENTEST_COMPLETE',
                    f"Multi-AI pentester team found {len(findings)} vulnerabilities across {len(urls)} assets"
                )
            else:
                logger.info(f"✅ TIER 4: Multi-AI Team tested {len(urls)} assets, no vulnerabilities found")
            
        except Exception as e:
            logger.error(f"Tier 4 multi-AI pentesting error: {e}")

    async def _tier_long_nuclei_scan(self) -> None:
        """Background long Nuclei scan across assets respecting TTL."""
        try:
            with self.asset_manager._get_db() as db:
                rows = db.execute(
                    """
                    SELECT url FROM assets
                    WHERE url LIKE 'http%'
                      AND (
                        last_nuclei_scan_at IS NULL OR
                        datetime(last_nuclei_scan_at) < datetime('now', ?)
                      )
                    ORDER BY id DESC LIMIT 200
                    """,
                    (f"-{int(self.nuclei_long_ttl_hours)} hours",)
                ).fetchall()
                urls = [r[0] for r in rows]
            if not urls:
                return
            found = await self.nuclei_scanner.run_long_scan(urls)
            with self.asset_manager._get_db() as db:
                now = datetime.utcnow().isoformat()
                db.executemany("UPDATE assets SET last_nuclei_scan_at=? WHERE url=?", [(now, u) for u in urls])
                db.commit()
            logger.info(f"🧪 Nuclei long scan complete: {found} findings across {len(urls)} URLs")
        except Exception as e:
            logger.debug(f"Nuclei long scan error: {e}")
    
    async def _tier5_modular_advanced_recon(self, session: aiohttp.ClientSession):
        """Tier 4: Advanced reconnaissance using ReconnaissanceEngine"""
        try:
            # Advanced recon using ReconnaissanceEngine module
            recon_results = await self.reconnaissance.perform_advanced_reconnaissance(
                session, limit=25
            )
            
            if recon_results:
                logger.info(f"🕵️ TIER 4: Advanced reconnaissance completed - {recon_results}")
            
        except Exception as e:
            logger.error(f"Tier 4 modular advanced recon error: {e}")
    
    async def _report_modular_progress(self, cycle: int):
        """Report progress using AssetManager statistics"""
        try:
            # Get statistics using AssetManager
            stats = self.asset_manager.get_progressive_scan_stats()
            
            # Get module-specific statistics
            proxy_stats = self.proxy_manager.get_proxy_statistics()
            ml_stats = self.ml_engine.get_ml_statistics()
            
            logger.info(f"📊 MODULAR CYCLE {cycle} PROGRESS:")
            logger.info(f"   Assets: {stats['discovered']} discovered, {stats['basic_complete']} profiled, {stats['deep_complete']} scanned")
            logger.info(f"   Proxies: {proxy_stats['healthy']}/{proxy_stats['total']} healthy")
            logger.info(f"   ML: {ml_stats['predictions_made']} predictions, {ml_stats['accuracy']:.2f} accuracy")
            
        except Exception as e:
            logger.debug(f"Progress reporting error: {e}")

def kill_existing_engines():
    """Kill any other running engine.py processes"""
    try:
        logger.info("🔍 Checking for existing engine processes...")
        current_pid = os.getpid()
        killed = 0
        for proc in psutil.process_iter(["pid", "cmdline"]):
            try:
                if proc.info["pid"] == current_pid:
                    continue
                cmdline = " ".join(proc.info.get("cmdline") or [])
                if "engine.py" in cmdline and "python" in cmdline:
                    proc.kill()
                    killed += 1
                    logger.info(f"💀 Killed PID {proc.info['pid']}")
            except Exception:
                continue

        if killed:
            logger.info(f"💀 Force killed {killed} existing engine processes")
        else:
            logger.info("📍 No other engine processes found")

        logger.info("✅ Process cleanup completed")
        return True
    except Exception as e:
        logger.error(f"❌ Process cleanup failed: {e}")
        return True

async def main():
    """Main entry point for modular scanner"""
    logger.info("🚀 Starting ModScan Engine with process management...")
    
    if os.environ.get("MODSCAN_SKIP_PROCESS_GUARD") == "1":
        logger.info("⏭️ Process guard skipped via environment variable")
    else:
        logger.info("🔍 Running process guard to ensure single engine instance...")
        if not kill_existing_engines():
            logger.error("💥 Failed to clean up existing processes - aborting")
            return
    
    logger.info("🎯 Starting new engine instance...")
    scanner = ModularVulnerabilityScanner()
    
    try:
        await scanner.run_modular_progressive_scan()
    except KeyboardInterrupt:
        logger.info("🛑 Modular scanner stopped by user")
    except Exception as e:
        logger.error(f"💥 Modular scanner error: {e}")

    def _should_scan(self, key: str) -> bool:
        """
        Idempotent de-dup of scan units. Returns True only on first sight.
        Use a stable key such as f"{method} {url}" or asset_id.
        """
        if key in self.seen:
            return False
        self.seen.add(key)
        return True

    def _stable_id(self, finding: dict) -> str:
        """
        Deterministic SHA256 over type, target, location-ish fields.
        """
        # Avoid import cost elsewhere; hashlib is imported at module level.
        fields = [
            str(finding.get("type", "")),
            str(finding.get("category", "")),
            str(finding.get("severity", "")),
            str(finding.get("target", "")),
            str(finding.get("endpoint", "")),
            str(finding.get("param", "")),
            str(finding.get("evidence", ""))[:200],  # cap noise
        ]
        s = "|".join(fields).encode("utf-8", "ignore")
        return hashlib.sha256(s).hexdigest()

    def _write_finding(self, finding: dict):
        """
        Append a single finding to findings.jsonl with a stable_id field.
        Safe to call from anywhere; creates file if missing.
        """
        try:
            if "stable_id" not in finding:
                finding["stable_id"] = self._stable_id(finding)
            finding.setdefault("ts", datetime.utcnow().isoformat() + "Z")
            line = (json.dumps(finding, ensure_ascii=False) + "\n")
            # Lazy open to avoid keeping fd around
            with open(self.findings_path, "a", encoding="utf-8") as fp:
                fp.write(line)
        except Exception as e:
            logger.error("Failed to write finding: %s", e)
    
    async def _monitor_discovery_progress(self, domain: str, start_time: float, timeout: int):
        """Monitor discovery progress and alert about potential hangs"""
        try:
            # Alert every 60 seconds if discovery is taking too long
            alert_count = 0
            
            while True:
                await asyncio.sleep(60)  # Check every 60 seconds
                alert_count += 1
                
                current_duration = time.time() - start_time
                
                # Alert if taking longer than normal (60s is normal)
                if current_duration >= 60:
                    logger.warning(f"🐌 SLOW DISCOVERY ALERT #{alert_count}: {domain} taking {current_duration:.1f}s (normal: <60s)")
                    
                    if alert_count == 1:
                        logger.info(f"💡 Tip: {domain} discovery may be slow - checking network/target availability")
                    elif alert_count == 2:
                        logger.warning(f"⚠️  {domain} discovery appears stuck - this may indicate a hang")
                    elif alert_count >= 3:
                        logger.error(f"🚨 CRITICAL: {domain} discovery likely hung - consider manual intervention")
                
                # Stop monitoring if we've exceeded the timeout
                if current_duration >= timeout:
                    break
                    
        except asyncio.CancelledError:
            # Normal cancellation when discovery completes
            pass
        except Exception as e:
            logger.debug(f"Discovery monitoring error for {domain}: {e}")

if __name__ == "__main__":
    asyncio.run(main())
