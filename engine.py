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
from pathlib import Path
from datetime import datetime
import json
import sys
import argparse
import re
from urllib.parse import urlparse

# Import all modular components
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.ultimate_discovery_engine import UltimateDiscoveryEngine
from modules.technology_detector import TechnologyDetector
from modules.proxy_manager import ProxyManager
from modules.screenshot_manager import ScreenshotManager
from modules.parallel_scanner_orchestrator import ParallelScannerOrchestrator
from asset_manager import AssetManager
from process_watchdog import ProcessWatchdog

# Configure logging
LOG_DIR = Path(__file__).resolve().parent / 'logs'
LOG_DIR.mkdir(parents=True, exist_ok=True)
logger = logging.getLogger("ModularScanner")
logger.setLevel(logging.INFO)
_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler = RotatingFileHandler(LOG_DIR / 'engine.log', maxBytes=2_000_000, backupCount=3)
file_handler.setFormatter(_formatter)
logger.addHandler(file_handler)
console_handler = logging.StreamHandler()
console_handler.setFormatter(_formatter)
logger.addHandler(console_handler)
logging.getLogger('aiohttp').setLevel(logging.WARNING)
logging.getLogger('asyncio').setLevel(logging.WARNING)

# Propagate core module logs into engine.log for unified visibility
for name in ("VulnerabilityScanner", "UltimateDiscovery", "ParallelScannerOrchestrator", "process_watchdog"):
    try:
        ml = logging.getLogger(name)
        ml.setLevel(logging.INFO)
        # Avoid duplicate handlers if re-run
        existing = {type(h) for h in ml.handlers}
        if type(file_handler) not in existing:
            ml.addHandler(file_handler)
        if type(console_handler) not in existing:
            ml.addHandler(console_handler)
        ml.propagate = False
    except Exception:
        pass

# Load configuration
BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / 'config.json'
try:
    with open(CONFIG_PATH) as f:
        CONFIG = json.load(f)
except FileNotFoundError:
    CONFIG = {"cpu_target_utilization": 75, "proxy_list": []}

class Engine:
    def __init__(self, domain_auth_overrides: dict | None = None):
        self.asset_manager = AssetManager()
        self.completed_domains = set()
        self.domain_auth = {}
        self.forced_scan_queue = []  # exact URLs requested on CLI for immediate deep scan
        self._load_authentication()
        # Merge any runtime overrides (e.g., CLI-provided login creds) BEFORE module init
        try:
            if domain_auth_overrides and isinstance(domain_auth_overrides, dict):
                for dom, cfg in domain_auth_overrides.items():
                    self.domain_auth.setdefault(dom, {}).update(cfg)
                logger.info(f"🔐 Applied runtime auth overrides for: {', '.join(domain_auth_overrides.keys())}")
        except Exception:
            pass
        self._initialize_modules()
    
    
    def _initialize_modules(self):
        """Initialize all scanner modules"""
        AUTH_CONFIG = CONFIG.copy()
        AUTH_CONFIG['domain_auth'] = self.domain_auth

        # Initialize process watchdog FIRST to handle cleanup from previous runs
        logger.info("🛡️  Initializing process watchdog for resource management")
        self.process_watchdog = ProcessWatchdog()
        
        # Clean up any zombie processes from previous engine runs
        logger.info("🧹 Cleaning up zombie processes from previous runs")
        self.process_watchdog.run_health_check()

        # Initialize parallel scanner orchestrator (replaces single scanner)
        logger.info("🎯 Initializing parallel scanner orchestrator for maximum performance")
        self.parallel_scanner = ParallelScannerOrchestrator(self.asset_manager, AUTH_CONFIG)
        
        # Keep single scanner for legacy compatibility (some methods still reference it)
        self.vulnerability_scanner = VulnerabilityScanner(self.asset_manager, AUTH_CONFIG)
        self.proxy_manager = ProxyManager(self.asset_manager, AUTH_CONFIG)
        AUTH_CONFIG['proxy_selector'] = getattr(self.proxy_manager, 'get_random_proxy', None)
        self.discovery_engine = UltimateDiscoveryEngine(self.asset_manager, AUTH_CONFIG)
        self.technology_detector = TechnologyDetector(self.asset_manager, AUTH_CONFIG)
        self.screenshot_manager = ScreenshotManager(self.asset_manager, AUTH_CONFIG)

        # Honor config and allow higher utilization on beefy hosts
        self.cpu_target = max(50, min(CONFIG.get("cpu_target_utilization", 85), 95))
        self.max_concurrent = 8  # REDUCED for more targeted scanning
        self.semaphore = asyncio.Semaphore(self.max_concurrent)

        # Load new efficiency settings
        self.targeted_mode = CONFIG.get("scanning", {}).get("targeted_mode", False)
        self.skip_duplicate_tests = CONFIG.get("scanning", {}).get("skip_duplicate_tests", False)
        self.test_ttl_minutes = CONFIG.get("scanning", {}).get("test_ttl_minutes", 60)
        self.max_tests_per_endpoint = CONFIG.get("scanning", {}).get("max_tests_per_endpoint", 3)
        self.focus_on_obvious_vulns = CONFIG.get("scanning", {}).get("focus_on_obvious_vulns", False)

        logger.info("🚀 Modular Scanner initialized")

    def seed_scope_targets(self, targets: list[str]) -> int:
        """Add provided targets to scope (domains or URLs allowed).
        - Accepts domains, wildcards (*.example.com), or full URLs
        - Normalizes to registered host (strips scheme/port/wildcard)
        Returns number of successfully added records.
        """
        added = 0
        run_scope_hosts = []

        for raw in targets or []:
            try:
                t = (raw or "").strip()
                if not t:
                    continue
                # Parse URL to host if needed
                if '://' in t:
                    p = urlparse(t)
                    host = (p.netloc or '').split('@')[-1]
                else:
                    host = t
                # Drop credentials/port and wildcard prefix
                host = host.split(':')[0]
                if host.startswith('*.'):
                    host = host[2:]
                host = host.lstrip('.')
                if not host:
                    continue

                run_scope_hosts.append(host)

                new_id = self.asset_manager.add_scope_target(host, is_active=1)
                if new_id:
                    added += 1
                    logger.info(f"📌 Added to scope: {host}")

                    # CRITICAL: Also create base assets for the domain so it gets scanned
                    base_urls = [f"https://{host}", f"http://{host}"]
                    for base_url in base_urls:
                        try:
                            asset_id = self.asset_manager.add_asset(
                                url=base_url,
                                host=host,
                                status_code=0,  # Will be discovered
                                tech_stack='',
                                discovered_at=None,  # Auto timestamp
                                force=True  # Ensure it gets added
                            )
                            if asset_id:
                                logger.debug(f"🌱 Seeded base asset: {base_url}")
                        except Exception as e:
                            logger.debug(f"Failed creating asset for {base_url}: {e}")
                else:
                    logger.info(f"➖ Already in scope: {host}")
            except Exception as e:
                logger.debug(f"Failed adding scope seed '{raw}': {e}")
                continue

        # Set run-scope isolation environment variable
        if run_scope_hosts:
            os.environ['MODSCAN_RUN_SCOPE_HOSTS'] = ','.join(run_scope_hosts)
            logger.info(f"🎯 Run scope isolated to: {', '.join(run_scope_hosts)}")

        return added

    async def _graceful_shutdown(self):
        """Best-effort cleanup of child processes and resources."""
        try:
            logger.info("🧹 Engine cleanup: closing screenshot manager")
            try:
                await self.screenshot_manager.close()
            except Exception:
                pass
            logger.info("🧹 Engine cleanup: terminating external tool processes")
            try:
                await self.vulnerability_scanner.cleanup_child_processes()
            except Exception:
                pass
            logger.info("🛡️  Final watchdog sweep for stuck processes")
            try:
                self.process_watchdog.run_health_check()
            except Exception:
                pass
        except Exception:
            pass

    def _check_cpu_usage(self):
        """🚀 INTRICATE PERFORMANCE MONITORING: CPU, memory, network, I/O for intelligent adaptation"""
        cpu_percent = psutil.cpu_percent(interval=0.5)  # Faster sampling for 10700K
        memory = psutil.virtual_memory()

        # 🌐 NETWORK BANDWIDTH INTELLIGENCE for 1GB connection
        net_io = psutil.net_io_counters()
        if not hasattr(self, '_last_net_check'):
            self._last_net_check = {'time': time.time(), 'bytes_sent': net_io.bytes_sent, 'bytes_recv': net_io.bytes_recv}
            self._bandwidth_history = []

        # Calculate real-time bandwidth utilization
        time_diff = time.time() - self._last_net_check['time']
        if time_diff > 1.0:  # Check every second
            bytes_sent_diff = net_io.bytes_sent - self._last_net_check['bytes_sent']
            bytes_recv_diff = net_io.bytes_recv - self._last_net_check['bytes_recv']

            # Convert to Mbps
            current_upload_mbps = (bytes_sent_diff * 8) / (time_diff * 1000000)
            current_download_mbps = (bytes_recv_diff * 8) / (time_diff * 1000000)
            total_bandwidth_mbps = current_upload_mbps + current_download_mbps

            # Track bandwidth history for intelligent scaling
            self._bandwidth_history.append(total_bandwidth_mbps)
            if len(self._bandwidth_history) > 60:  # Keep 1 minute history
                self._bandwidth_history.pop(0)

            self._last_net_check = {'time': time.time(), 'bytes_sent': net_io.bytes_sent, 'bytes_recv': net_io.bytes_recv}

            # 1GB = 1000 Mbps - calculate utilization
            bandwidth_utilization = total_bandwidth_mbps / 1000.0
            if len(self._bandwidth_history) > 0:
                avg_bandwidth = sum(self._bandwidth_history[-10:]) / min(10, len(self._bandwidth_history))
                logger.debug(f"🌐 Network: {total_bandwidth_mbps:.1f} Mbps current, {avg_bandwidth:.1f} Mbps avg ({bandwidth_utilization*100:.1f}% of 1GB)")

        # 🔧 ADVANCED PROCESS MONITORING
        try:
            current_process = psutil.Process()
            open_files = len(current_process.open_files())
            connections = len(current_process.connections())
            memory_mb = current_process.memory_info().rss / 1024 / 1024

            # 10700K + 32GB: Higher thresholds for high-end hardware
            if open_files > 1200:  # Higher limit for powerful system
                logger.error(f"🚨 CRITICAL: {open_files} open files - EMERGENCY THROTTLING")
                return "critical_resources"
            elif connections > 1000:  # 1GB connection can handle more
                logger.error(f"🚨 CONNECTION SATURATION: {connections} connections - AGGRESSIVE THROTTLING")
                return "connection_saturation"
            elif memory_mb > 8000:  # 8GB+ indicates serious issues on 32GB system
                logger.error(f"🚨 MEMORY CRITICAL: {memory_mb:.0f}MB - EMERGENCY CLEANUP")
                return "memory_critical"
            elif memory_mb > 6000:  # 6GB warning on 32GB system
                logger.warning(f"⚠️ MEMORY HIGH: {memory_mb:.0f}MB - THROTTLING RECOMMENDED")
                return "memory_high"

        except Exception as e:
            logger.debug(f"Advanced resource monitoring failed: {e}")

        # 🚀 INTELLIGENT SCALING FOR HIGH-END HARDWARE

        # Network bandwidth scaling (utilize 1GB connection fully)
        if hasattr(self, '_bandwidth_history') and len(self._bandwidth_history) > 5:
            recent_bandwidth = sum(self._bandwidth_history[-5:]) / min(5, len(self._bandwidth_history))
            bandwidth_utilization = recent_bandwidth / 1000.0  # 1GB = 1000 Mbps

            # Aggressive scaling when network is underutilized
            if bandwidth_utilization < 0.2 and cpu_percent < 40 and memory.percent < 50:
                logger.info(f"🚀 AGGRESSIVE SCALE: Network {bandwidth_utilization*100:.1f}%, CPU {cpu_percent}%, RAM {memory.percent}%")
                return "aggressive_scale"
            elif bandwidth_utilization > 0.85:  # Near saturation
                logger.warning(f"🌐 BANDWIDTH LIMIT: {bandwidth_utilization*100:.1f}% of 1GB - THROTTLING")
                return "bandwidth_limited"

        # CPU scaling optimized for 10700K (10 cores, 20 threads)
        if cpu_percent > 90:  # Very high threshold for 10700K
            logger.warning(f"🔥 CRITICAL CPU: {cpu_percent}% - EMERGENCY THROTTLING")
            return "cpu_critical"
        elif cpu_percent > 75:
            logger.warning(f"🔥 HIGH CPU: {cpu_percent}% - REDUCING CONCURRENCY")
            return "cpu_high"
        elif cpu_percent > 50:
            logger.info(f"🔶 MODERATE CPU: {cpu_percent}% - STABLE OPERATIONS")
            return "cpu_moderate"
        elif cpu_percent < 25:  # 10700K has massive headroom
            logger.debug(f"✅ LOW CPU: {cpu_percent}% - MASSIVE SCALE UP OPPORTUNITY")
            return "cpu_low"

        # Memory scaling optimized for 32GB
        if memory.percent > 90:  # Very high threshold for 32GB
            logger.warning(f"💾 CRITICAL MEMORY: {memory.percent}% - EMERGENCY THROTTLING")
            return "memory_critical"
        elif memory.percent > 75:
            logger.warning(f"💾 HIGH MEMORY: {memory.percent}% - REDUCING BATCH SIZES")
            return "memory_high"
        elif memory.percent < 30:  # Massive RAM available
            logger.debug(f"💾 LOW MEMORY: {memory.percent}% - CAN MASSIVELY INCREASE BATCHES")
            return "memory_low"

        # Default: System performing optimally
        logger.debug(f"✅ OPTIMAL: CPU {cpu_percent}%, RAM {memory.percent}%")
        return "optimal"

    def _load_authentication(self):
        """Load lightweight domain-level auth/cookie hints from config.

        Populates self.domain_auth with per-domain headers such as Cookie or Authorization that
        downstream modules (e.g., discovery engine) can consult. This stays optional and safe.
        Also loads login credentials for automatic authentication.
        """
        try:
            domain_auth: dict[str, dict] = {}
            # Cookie overrides from config
            co = CONFIG.get('cookie_overrides') or {}
            domains = (co.get('domains') or {}) if isinstance(co, dict) else {}
            global_overrides = (co.get('global_overrides') or {}) if isinstance(co, dict) else {}

            # Build a compact cookie string for each configured domain
            for dom, entry in domains.items():
                try:
                    cookie_map = {}
                    # Domain-specific security levels
                    levels = (entry.get('security_levels') or {}) if isinstance(entry, dict) else {}
                    default_level = (entry.get('default_level') or '').strip()
                    if default_level and default_level in levels:
                        lv = levels[default_level]
                        if isinstance(lv, str) and '=' in lv:
                            k, v = lv.split('=', 1)
                            cookie_map[k.strip()] = v.strip()
                    # Global overrides merged in
                    if isinstance(global_overrides, dict):
                        for k, v in global_overrides.items():
                            cookie_map[str(k).strip()] = str(v).strip()
                    # Flatten to Cookie header
                    cookie_header = '; '.join(f"{k}={v}" for k, v in cookie_map.items() if k and v)
                    if cookie_header:
                        domain_auth[str(dom).lstrip('.')]= {'Cookie': cookie_header}

                    # Handle login credentials for automatic authentication
                    login_config = (entry.get('login') or {}) if isinstance(entry, dict) else {}
                    if login_config and isinstance(login_config, dict):
                        login_url = login_config.get('url')
                        username = login_config.get('username')
                        password = login_config.get('password')
                        if login_url and username and password:
                            # Store login credentials in domain_auth for AuthManager
                            if str(dom).lstrip('.') not in domain_auth:
                                domain_auth[str(dom).lstrip('.')] = {}
                            domain_auth[str(dom).lstrip('.')]['login'] = {
                                'url': login_url,
                                'username': username,
                                'password': password
                            }
                            logger.info(f"🔐 Loaded login credentials for {dom}")

                except Exception:
                    continue
            # Authorized domains can be used by scanners as permissive hints
            authz = CONFIG.get('authorized_domains') or []
            for dom in authz:
                d = str(dom).lstrip('.')
                domain_auth.setdefault(d, {})
            self.domain_auth = domain_auth
        except Exception:
            self.domain_auth = {}

    async def run_scan_cycle(self):
        logger.info("🔧 All modules already initialized in __init__")
        
        # CRITICAL: Ensure database tables are initialized before accessing them
        logger.info("🗄️  Ensuring database tables are properly initialized...")
        try:
            # Force database table creation by accessing AssetManager
            _ = self.asset_manager.get_scope_targets()  # This will create scope table if needed
            logger.info("✅ Database tables verified and ready")
        except Exception as e:
            logger.error(f"❌ Database initialization failed: {e}")
            raise
        
        logger.info("🎯 Starting Modular Progressive Vulnerability Scanner with Parallel Processing")

        # Process watchdog already initialized in _initialize_modules()
        last_safety_check = 0
        SAFETY_CHECK_INTERVAL = 300  # Run safety checks every 5 minutes
        
        # Start the parallel scanner orchestrator in background
        orchestrator_task = asyncio.create_task(self.parallel_scanner.start_orchestrator())
        
        scan_cycle = 0
        try:
            while scan_cycle < int(os.environ.get('MODSCAN_MAX_CYCLES', '25')):
                scan_cycle += 1
                logger.info(f"🔄 SCAN CYCLE {scan_cycle}")
                self.monitor_and_adjust_performance()
                
                # SAFETY SYSTEMS: Run periodic process and database health checks
                current_time = time.time()
                if current_time - last_safety_check > SAFETY_CHECK_INTERVAL:
                    logger.info("🔒 Running safety systems check...")
                    try:
                        # Run process cleanup in background to avoid blocking scan
                        loop = asyncio.get_event_loop()
                        await loop.run_in_executor(None, self.process_watchdog.run_health_check)
                    except Exception as e:
                        logger.warning(f"Safety check failed: {e}")
                    last_safety_check = current_time

                # Check if we have work to do before running expensive operations
                try:
                    # Use proper AssetManager methods instead of direct database access
                    scope_targets = self.asset_manager.get_scope_targets()
                    pending_domains = len(scope_targets) if scope_targets else 0
                    
                    # Get unscanned assets using proper method
                    unscanned_assets = self.asset_manager.get_unscanned_assets()
                    unscanned_count = len(unscanned_assets) if unscanned_assets else 0
                    
                except Exception as e:
                    logger.warning(f"Could not check work status: {e}")
                    pending_domains = 1  # Assume there's work to do
                    unscanned_count = 0
                
                # Get scan-ready assets count safely
                try:
                    scan_ready_assets = self.asset_manager.get_assets_for_vulnerability_scan()
                    scan_ready_count = len(scan_ready_assets) if scan_ready_assets else 0
                except Exception as e:
                    logger.warning(f"Could not get scan-ready assets: {e}")
                    scan_ready_count = 1  # Assume there's work to do

                # Smart exit conditions - avoid redundant work
                if scan_cycle > 5 and pending_domains == 0 and unscanned_count == 0 and scan_ready_count == 0:
                    logger.info(f"🎯 No pending work found after {scan_cycle} cycles. Scan complete!")
                    break
                    
                logger.info(f"📊 Pending work: {pending_domains} domains, {unscanned_count} unscanned, {scan_ready_count} ready for vuln scan")

                # The session is now managed internally by the scanner modules
                # No need to create a session here.

                # PARALLEL TIER EXECUTION - maximize resource utilization
                # Run discovery, profiling, and deep scanning simultaneously using all resources
                tier_tasks = [
                    asyncio.create_task(self._tier1_modular_discovery(), name="Discovery"),
                    asyncio.create_task(self._tier2_modular_profiling(), name="Profiling"), 
                    asyncio.create_task(self._tier3_modular_vulnerability_scanning(), name="DeepScanning")
                ]
                
                # Wait for all tiers to complete, allowing them to work in parallel
                completed_tiers = await asyncio.gather(*tier_tasks, return_exceptions=True)
                
                # Log tier completion status
                for i, result in enumerate(completed_tiers):
                    tier_name = ["Discovery", "Profiling", "DeepScanning"][i]
                    if isinstance(result, Exception):
                        logger.error(f"Tier {tier_name} failed: {result}")
                    else:
                        logger.info(f"Tier {tier_name} completed successfully")

                # Cycle summary: vulnerabilities found in the last 10 minutes
                try:
                    from asset_manager import AssetManager
                    am = self.asset_manager if hasattr(self, 'asset_manager') else AssetManager()
                    recent = []
                    try:
                        recent = am.get_recent_vulnerabilities(minutes=10)  # compat shim present
                    except Exception:
                        pass
                    if recent:
                        # Aggregate by type and severity for a concise summary
                        by_type = {}
                        by_sev = {}
                        for r in recent:
                            t = (r.get('type') or '').upper()
                            s = (r.get('severity') or '').upper()
                            by_type[t] = by_type.get(t, 0) + 1
                            by_sev[s] = by_sev.get(s, 0) + 1
                        logger.info(f"📊 Cycle Summary: {len(recent)} vulns found in last 10m | Top types: {sorted(by_type.items(), key=lambda x: -x[1])[:5]} | Severity: {sorted(by_sev.items(), key=lambda x: -x[1])}")
                    else:
                        logger.info("📊 Cycle Summary: 0 vulnerabilities found in last 10m")
                except Exception as e:
                    logger.debug(f"Cycle summary failed: {e}")
                
                await asyncio.sleep(5)
                
        except KeyboardInterrupt:
            logger.info("🛑 Shutting down parallel scanner orchestrator...")
            orchestrator_task.cancel()
            try:
                await orchestrator_task
            except asyncio.CancelledError:
                pass
            # Cleanup resources and child processes
            await self._graceful_shutdown()
            raise
        finally:
            try:
                if not orchestrator_task.done():
                    orchestrator_task.cancel()
                    try:
                        await orchestrator_task
                    except Exception:
                        pass
            except Exception:
                pass
            await self._graceful_shutdown()

    # initialize_all_modules removed; modules are constructed synchronously in __init__

    def monitor_and_adjust_performance(self):
        """🚀 INTRICATE PERFORMANCE MONITORING: Intelligent adaptation for 10700K + 32GB + 1GB"""
        load_status = self._check_cpu_usage()

        # Adjust parallel scanner based on INTRICATE system analysis
        if hasattr(self, 'parallel_scanner') and self.parallel_scanner:
            current_workers = getattr(self.parallel_scanner, 'num_workers', 64)

            # 🚨 CRITICAL RESOURCE CONDITIONS
            if load_status in ["critical_resources", "connection_saturation", "memory_critical"]:
                # EMERGENCY: Drastically reduce workers to prevent crash
                new_workers = max(1, current_workers // 6)  # More aggressive for high-end system
                logger.error(f"🚨 {load_status.upper()}: EMERGENCY worker reduction {current_workers} → {new_workers}")
                self.parallel_scanner.num_workers = new_workers

            elif load_status == "bandwidth_limited":
                # Network saturated: Reduce by 40% to prevent packet loss
                new_workers = max(5, int(current_workers * 0.6))
                logger.warning(f"🌐 BANDWIDTH SATURATED: Reducing workers {current_workers} → {new_workers}")
                self.parallel_scanner.num_workers = new_workers

            elif load_status in ["cpu_critical", "memory_high"]:
                # High resource usage: Reduce by 50%
                new_workers = max(3, current_workers // 2)
                logger.warning(f"🔥 {load_status.upper()}: Reducing workers {current_workers} → {new_workers}")
                self.parallel_scanner.num_workers = new_workers

            elif load_status in ["cpu_high", "memory_high"]:
                # High usage: Moderate reduction (25%)
                new_workers = max(8, int(current_workers * 0.75))
                logger.warning(f"⚠️ {load_status.upper()}: Moderating workers {current_workers} → {new_workers}")
                self.parallel_scanner.num_workers = new_workers

            elif load_status == "cpu_moderate":
                # Stable operations: Minor adjustment
                new_workers = max(12, int(current_workers * 0.95))
                if new_workers != current_workers:
                    logger.info(f"🔶 STABLE: Minor adjustment {current_workers} → {new_workers}")
                    self.parallel_scanner.num_workers = new_workers

            # 🚀 AGGRESSIVE SCALING CONDITIONS for high-end hardware
            elif load_status == "aggressive_scale":
                # Network + CPU + RAM all underutilized: MASSIVE SCALE UP
                cpu_cores = os.cpu_count() or 10
                max_workers = min(100, cpu_cores * 8)  # 8x cores for massive parallelism
                new_workers = min(max_workers, int(current_workers * 1.5))  # 50% increase
                logger.info(f"🚀 AGGRESSIVE SCALE: MASSIVE boost {current_workers} → {new_workers}")
                self.parallel_scanner.num_workers = new_workers

            elif load_status in ["cpu_low", "memory_low", "optimal"]:
                # System has headroom: Scale up intelligently
                cpu_cores = os.cpu_count() or 10
                # 10700K: Can handle 6x cores safely, 8x aggressively
                target_max = min(80, cpu_cores * 6) if load_status == "optimal" else min(60, cpu_cores * 4)

                if current_workers < target_max:
                    scale_factor = 1.3 if load_status == "cpu_low" else 1.15  # More aggressive for CPU headroom
                    new_workers = min(target_max, int(current_workers * scale_factor))
                    logger.info(f"✅ {load_status.upper()}: Scaling up {current_workers} → {new_workers}")
                    self.parallel_scanner.num_workers = new_workers

    async def _tier1_modular_discovery(self):
        logger.info("Tier 1: Starting discovery...")
        # Get in-scope targets that need discovery
        scope_targets = self.asset_manager.get_scope_targets()
        
        for target in scope_targets:
            # Handle tuple format: (id, domain, is_active)
            if isinstance(target, tuple) and len(target) >= 2:
                domain = target[1]  # domain is second column
            elif isinstance(target, dict):
                domain = target.get('domain', '')
            else:
                continue
                
            if not domain:
                continue
            
            # CRITICAL FIX: Check if we recently discovered this domain (TTL check)
            ttl_hours = int(os.environ.get('MODSCAN_TTL_HOURS', '6'))  # Default 6 hours TTL

            # RESPECT --no-ttl FLAG: Skip TTL check completely when MODSCAN_TTL_HOURS=0
            if ttl_hours > 0:
                with self.asset_manager._get_db() as db:
                    cursor = db.execute("""
                        SELECT COUNT(*) FROM assets
                        WHERE url LIKE ?
                        AND discovered_at > datetime('now', '-{} hours')
                    """.format(ttl_hours), (f"%{domain}%",))
                    recent_discoveries = cursor.fetchone()[0]

                if recent_discoveries > 0:
                    logger.info(f"⏭️  Skipping {domain} - {recent_discoveries} recent discoveries within {ttl_hours}h TTL")
                    continue
                
            logger.info(f"🔍 Starting comprehensive discovery for {domain}")
            try:
                # GAU-FIRST APPROACH: Get historical URLs immediately for instant vuln scanning
                logger.info(f"⚡ GAU-FIRST DISCOVERY: {domain}")

                # Step 1: Fast GAU for instant URLs (20s max)
                gau_urls = set()
                try:
                    if not self.discovery_engine._is_internal_ip(domain):
                        gau_results = await self.discovery_engine._run_gau(domain)
                        gau_urls.update(gau_results)
                        logger.info(f"⚡ GAU: {len(gau_urls)} instant URLs for immediate testing")
                    else:
                        logger.info("⏭️ Skipping GAU for internal target")
                except Exception as e:
                    logger.warning(f"GAU failed: {e}")

                # Step 2: Immediate vulnerability scanning on GAU URLs
                if gau_urls:
                    logger.info(f"🔥 IMMEDIATE VULN SCAN: Testing {len(gau_urls)} GAU URLs")
                    # Store GAU URLs first for immediate scanning
                    validated_gau = await self._validate_discovered_urls(list(gau_urls))
                    if validated_gau:
                        self.asset_manager.add_assets_batch(validated_gau, discovery_method="gau_instant")
                        logger.info(f"⚡ STORED: {len(validated_gau)} GAU URLs ready for immediate vuln testing")

                # Step 3: Fast additional discovery in parallel (30s max) - RESPECT TARGETED MODE
                additional_urls = set()
                discovered_urls = []  # Ensure variable exists for later references
                try:
                    FAST_DISCOVERY_TIMEOUT = 30

                    # Use targeted discovery if enabled
                    if self.targeted_mode:
                        logger.info(f"🎯 TARGETED MODE: Using focused discovery for {domain}")
                        discovered_urls = await asyncio.wait_for(
                            self.discovery_engine.comprehensive_discovery(domain),
                            timeout=FAST_DISCOVERY_TIMEOUT
                        )
                    else:
                        discovered_urls = await asyncio.wait_for(
                            self.discovery_engine._fast_streamlined_discovery(domain),
                            timeout=FAST_DISCOVERY_TIMEOUT
                        )

                    additional_urls.update(discovered_urls)
                    logger.info(f"⚡ FAST: {len(additional_urls)} additional URLs from {'targeted' if self.targeted_mode else 'streamlined'} discovery")
                except asyncio.TimeoutError:
                    logger.info(f"⚡ Fast discovery completed within {FAST_DISCOVERY_TIMEOUT}s")
                except Exception as e:
                    logger.warning(f"Fast discovery failed: {e}")

                # Combine all URLs
                all_discovered = gau_urls | additional_urls
                logger.info(f"🎯 TOTAL DISCOVERED: {len(all_discovered)} URLs for {domain}")

                # Store ALL discovered URLs for vulnerability scanning
                if all_discovered:
                    logger.info(f"💾 STORING DISCOVERED URLS: Validating {len(all_discovered)} URLs")
                    validated_all = await self._validate_discovered_urls(list(all_discovered))
                    if validated_all:
                        self.asset_manager.add_assets_batch(validated_all, discovery_method="comprehensive_challenge")
                        logger.info(f"💾 STORED: {len(validated_all)} total URLs ready for vulnerability testing")
                    else:
                        logger.warning("⚠️ No valid endpoints found in comprehensive discovery")

                # EXTRA: If we found port bases but few/no paths on them, run per-port discovery now
                try:
                    from urllib.parse import urlsplit
                    port_bases = set()
                    for u in discovered_urls or []:
                        try:
                            sp = urlsplit(u)
                            if sp.netloc and ':' in sp.netloc:
                                host, port = sp.netloc.split(':', 1)
                                if port not in ('80', '443'):
                                    port_bases.add(f"{sp.scheme}://{host}:{port}")
                        except Exception:
                            continue

                    if port_bases:
                        logger.info(f"🛠️  Verifying {len(port_bases)} discovered ports for deeper paths")
                        extra_urls = set()
                        per_port_budget = int(os.environ.get('MODSCAN_PORT_DISCOVERY_TIMEOUT', '45'))
                        for base in list(port_bases)[:8]:  # sanity cap
                            # Only trigger if we have nothing beyond the base
                            has_paths = any((str(u).startswith(base + '/') and len(str(u)) > len(base) + 1) for u in discovered_urls)
                            if not has_paths:
                                try:
                                    addl = await asyncio.wait_for(
                                        self.discovery_engine._tier7_universal_port_discovery(base),
                                        timeout=per_port_budget
                                    )
                                    extra_urls.update(addl or [])
                                    logger.info(f"🔎 Port {base}: +{len(addl or [])} URLs")
                                except Exception as e:
                                    logger.debug(f"Port {base} extra discovery skipped/failed: {e}")
                        if extra_urls:
                            discovered_urls = list(set(discovered_urls or []) | extra_urls)
                except Exception as e:
                    logger.debug(f"Post-discovery port enrichment failed: {e}")
                
                # VALIDATE URLs before saving (only save real endpoints)
                if discovered_urls:
                    validated_assets = await self._validate_discovered_urls(discovered_urls)
                    logger.info(f"✅ Validated {len(validated_assets)} real endpoints from {len(discovered_urls)} discoveries")
                    
                    if validated_assets:
                        self.asset_manager.add_assets_batch(validated_assets, discovery_method="comprehensive_discovery")
                        logger.info(f"💾 Saved {len(validated_assets)} validated assets to database")
                    else:
                        logger.info("⚠️ No valid endpoints found in discovery results")
                    
            except Exception as e:
                logger.error(f"Discovery failed for {domain}: {e}")

    async def _validate_discovered_urls(self, discovered_urls, max_concurrent=15):  # INCREASED for better performance
        """Validate discovered URLs before saving to database - only save real endpoints"""
        if not discovered_urls:
            return []
            
        validated_assets = []
        timeout = aiohttp.ClientTimeout(total=8, connect=3)

        challenge_segment_keywords = {
            'mission', 'missions', 'challenge', 'challenges', 'level', 'levels', 'stage', 'stages',
            'exercise', 'exercises', 'task', 'tasks', 'quest', 'quests', 'lab', 'labs', 'dojo',
            'training', 'practice', 'ctf', 'wargame', 'capture', 'flag', 'arena', 'lesson',
            'lessons', 'module', 'modules', 'scenario', 'scenarios'
        }
        challenge_host_keywords = {
            'ctf', 'wargame', 'challenge', 'hack', 'training', 'missions', 'dojo', 'lab', 'labs',
            'quest', 'practice', 'capture', 'flag'
        }
        ordinal_patterns = (
            r'^(?:mission|challenge|level|stage|task|quest|lab|module|lesson)[-_]?\d+$',
            r'^(?:level|stage|mission)[0-9]+(?:[a-z])?$',
        )

        def _looks_like_challenge(host: str, segments: list[str]) -> bool:
            host_lower = (host or '').lower()
            seg_lowers = [seg.lower() for seg in segments]
            path_lower = '/'.join(seg_lowers)

            score = 0
            if any(keyword in host_lower for keyword in challenge_host_keywords):
                score += 1

            if any(any(keyword in seg for keyword in challenge_segment_keywords) for seg in seg_lowers):
                score += 1

            numeric_segments = sum(1 for seg in seg_lowers if seg.isdigit())
            if numeric_segments:
                score += 1

            if any(re.match(pattern, seg) for pattern in ordinal_patterns for seg in seg_lowers):
                score += 1

            path_indicators = ('/ctf', '/missions', '/challenge', '/quest', '/level', '/stage', '/task')
            if any(ind in path_lower for ind in path_indicators):
                score += 1

            return score >= 2

        async with aiohttp.ClientSession(timeout=timeout) as session:
            sem = asyncio.Semaphore(max_concurrent)
            
            async def validate_url(url):
                async with sem:
                    try:
                        from urllib.parse import urlsplit, urlparse
                        sp = urlsplit(url)
                        path = sp.path or '/'
                        segs = [seg for seg in path.split('/') if seg]

                        # Allow challenge/CTF URLs - less restrictive validation
                        # Skip obvious synthetic paths but allow numbered challenges
                        if len(segs) > 15:  # Increased from 10
                            return

                        is_challenge_url = _looks_like_challenge(sp.netloc, segs)

                        if not is_challenge_url:
                            # Apply stricter validation only for non-challenge URLs
                            if any('.' in seg for seg in segs[:-1]):
                                return
                            from collections import Counter
                            c = Counter(segs)
                            if any(v > 3 for v in c.values()):
                                return
                        # Validate with GET and follow redirects; accept terminal 200/201/202/204/401/403 on same host
                        async with session.get(url, allow_redirects=True) as get_response:
                            status_code = get_response.status
                            final_url = str(get_response.url)
                            final_sp = urlsplit(final_url)

                            # More permissive status codes for challenge URLs
                            if is_challenge_url:
                                accepted_codes = (200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 404, 500)
                            else:
                                accepted_codes = (200, 201, 202, 204, 401, 403)

                            if status_code in accepted_codes and final_sp.netloc == sp.netloc:
                                title = f'HTTP {status_code}'
                                tech_stack = ''
                                content_length = get_response.headers.get('content-length', 0)
                                try:
                                    html = await get_response.text()
                                    # Extract title
                                    if '<title>' in html.lower():
                                        start = html.lower().find('<title>') + 7
                                        end = html.lower().find('</title>', start)
                                        if end > start:
                                            title = html[start:end].strip()[:50]
                                    # Basic tech detection
                                    html_lower = html.lower()
                                    techs = []
                                    if 'asp.net' in html_lower or '.aspx' in url.lower():
                                        techs.append('ASP.NET')
                                    if 'server: microsoft-iis' in str(get_response.headers).lower():
                                        techs.append('IIS')
                                    if 'joomla' in html_lower:
                                        techs.append('Joomla')
                                    tech_stack = ', '.join(techs)
                                except Exception:
                                    pass
                                parsed = urlparse(url)
                                return {
                                    'url': final_url,
                                    'host': parsed.netloc,
                                    'status_code': status_code,
                                    'title': title,
                                    'tech_stack': tech_stack,
                                    'content_length': int(content_length) if content_length else 0,
                                    'validated': True
                                }
                    except Exception as e:
                        # Skip URLs that timeout, fail DNS, etc.
                        logger.debug(f"Validation failed for {url}: {e}")
                        return None
            
            # Validate all URLs in parallel
            validation_tasks = [validate_url(url) for url in discovered_urls]
            results = await asyncio.gather(*validation_tasks, return_exceptions=True)
            
            # Filter out failed validations and exceptions
            validated_assets = [result for result in results if result is not None and not isinstance(result, Exception)]
            
        return validated_assets

    async def _tier2_modular_profiling(self):
        logger.info("Tier 2: Starting profiling...")
        # FIXED: Simple direct profiling that actually works
        try:
            # Dynamic resource adjustment based on CPU usage and resource monitoring
            resource_status = self._check_cpu_usage()

            # CRITICAL FIX: Emergency cleanup actions for resource exhaustion
            if resource_status == "resource_exhaustion":
                logger.error("🚨 EMERGENCY: Running process cleanup to prevent crash")
                # Force garbage collection and cleanup
                import gc
                gc.collect()
                # Emergency process cleanup
                self.process_watchdog.run_health_check()
                batch_limit, concurrency = 1, 1  # Minimal operations
                sleep_delay = 5
            elif resource_status == "connection_leak":
                logger.error("🚨 CONNECTION CLEANUP: Forcing session cleanup")
                # Force session cleanup in vulnerability scanner
                if hasattr(self, 'vulnerability_scanner'):
                    await self.vulnerability_scanner.close_session()
                batch_limit, concurrency = 3, 2  # Very limited operations
                sleep_delay = 3
            elif resource_status == "memory_growth":
                logger.warning("🧹 MEMORY CLEANUP: Reducing operations and forcing cleanup")
                import gc
                gc.collect()
                batch_limit, concurrency = 5, 3  # Reduced operations
                sleep_delay = 2
            elif resource_status == "high":
                batch_limit, concurrency = 5, 3  # Less conservative - still safe
                sleep_delay = 1
            elif resource_status == "moderate":
                batch_limit, concurrency = 15, 8  # Increase for better performance
                sleep_delay = 0.5
            elif resource_status == "high_memory":
                batch_limit, concurrency = 10, 5  # Reduce batch, normal concurrency
                sleep_delay = 0.5
            else:
                # AGGRESSIVE SCALING: When resources are LOW, scale up significantly for faster coverage
                batch_limit, concurrency = 50, 20  # 2x increase for maximum performance
                sleep_delay = 0.1  # Faster cycles
                logger.info("🚀 LOW RESOURCE USAGE: Scaling up for maximum vulnerability discovery speed")
                
            logger.info(f"🎯 Resource status: {resource_status} - Using {concurrency} concurrent, batch {batch_limit}")
            
            # Get assets needing profiling with dynamic limits
            to_profile = self.asset_manager.get_assets_with_missing_data(limit=batch_limit)

            # Filter to run-scope hosts only if set
            run_scope_hosts = os.environ.get('MODSCAN_RUN_SCOPE_HOSTS')
            if run_scope_hosts:
                allowed_hosts = set(run_scope_hosts.split(','))
                to_profile = [asset for asset in to_profile if asset.get('host') in allowed_hosts]
                if to_profile:
                    logger.info(f"🎯 Filtered to run-scope: {len(to_profile)} assets for {', '.join(allowed_hosts)}")

            if to_profile:
                logger.info(f"Tier 2: Profiling {len(to_profile)} newly discovered assets")
                
                timeout = aiohttp.ClientTimeout(total=15)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    sem = asyncio.Semaphore(concurrency)  # Dynamic concurrency
                    
                    async def profile_asset(asset):
                        async with sem:
                            url = asset.get('url')
                            asset_id = asset.get('id')
                            if not url or not asset_id:
                                return
                                
                            try:
                                # HEAD request for status and headers
                                async with session.head(url) as response:
                                    status_code = response.status
                                    content_length = response.headers.get('content-length', 0)
                                    
                                    # For 200 responses, get title and capture response body
                                    title = f'HTTP {status_code}'
                                    response_body = ""
                                    if status_code == 200:
                                        try:
                                            async with session.get(url) as get_response:
                                                html = await get_response.text()
                                                
                                                # Capture response body (limit to 5KB for storage)
                                                response_body = html[:5000] if html else ""
                                                
                                                # Extract title
                                                if '<title>' in html.lower():
                                                    start = html.lower().find('<title>') + 7
                                                    end = html.lower().find('</title>', start)
                                                    if end > start:
                                                        title = html[start:end].strip()[:50]
                                        except Exception:
                                            title = f'HTTP {status_code}'
                                            response_body = "Error capturing response"
                                    
                                    # Save profiling results with response body for Burp-like testing
                                    self.asset_manager.update_asset_fields(asset_id, {
                                        'status_code': status_code,
                                        'title': title,
                                        'content_length': int(content_length) if content_length else 0,
                                        'response_time': None,  # Can add timing later
                                        'response_body': response_body,  # Store response for Burp-like analysis
                                        'last_scanned': None   # Will be set by update_asset_fields
                                    })
                                    
                                    if status_code == 200:
                                        logger.debug(f"✅ Profiled: {url} - {status_code} - {title}")
                                    
                            except Exception as e:
                                # Mark as error but continue
                                self.asset_manager.update_asset_fields(asset_id, {
                                    'status_code': 0,
                                    'title': f'Error: {str(e)[:30]}'
                                })
                                logger.debug(f"❌ Profile failed: {url} - {e}")
                    
                    # Process all assets in parallel
                    await asyncio.gather(*[profile_asset(asset) for asset in to_profile], return_exceptions=True)
                    
                    # Add adaptive sleep delay to prevent system overload
                    if sleep_delay > 0:
                        logger.debug(f"⏱️  Sleeping {sleep_delay}s to prevent resource overload")
                        await asyncio.sleep(sleep_delay)
                    
                    logger.info(f"Tier 2: Completed profiling {len(to_profile)} assets")
                    
            # 2) Technology detection for newly profiled 200 OK assets
            try:
                timeout = aiohttp.ClientTimeout(total=20)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    updated_count = await self.technology_detector.process_pending_assets(session, limit=15)  # INCREASED for better throughput
                    if updated_count:
                        logger.info(f"Tier 2: Technology detection updated {updated_count} assets")
            except Exception as e:
                logger.debug(f"Technology detection failed: {e}")
                
            # 3) Automatic screenshot capture for 200 OK assets without screenshots
            try:
                screenshot_assets = []
                with self.asset_manager._get_db() as db:
                    cursor = db.execute('''
                        SELECT id, url FROM assets 
                        WHERE status_code = 200 
                        AND (screenshot_path IS NULL OR screenshot_path = '')
                        LIMIT 3
                    ''')  # REDUCED: Only 3 screenshots per cycle for VM
                    screenshot_assets = [{'id': row[0], 'url': row[1]} for row in cursor.fetchall()]
                
                if screenshot_assets:
                    for asset in screenshot_assets:
                        try:
                            spath = await self.screenshot_manager.capture_url(asset['url'], asset_id=asset['id'])
                            if spath:
                                self.asset_manager.update_asset_fields(asset['id'], {'screenshot_path': spath})
                        except Exception:
                            pass
                            
                logger.info(f"Tier 2: Captured screenshots for {len(screenshot_assets)} assets")
            except Exception as e:
                logger.debug(f"Screenshot capture failed: {e}")
                
        except Exception as e:
            logger.error(f"Tier 2 profiling error: {e}")

    async def _tier3_modular_vulnerability_scanning(self):
        logger.info("Tier 3: Starting vulnerability scanning...")
        try:
            # UTILIZE ALL RESOURCES - no artificial limits, scale to actual worker capacity
            num_workers = getattr(self.parallel_scanner, 'num_workers', 64)
            
            # Get assets equal to worker capacity for maximum throughput (3x workers for good queuing)
            optimal_batch_size = num_workers * 3  # e.g., 64 workers * 3 = 192 assets per batch
            ready_assets = self.asset_manager.get_assets_ready_for_deep_scan(limit=optimal_batch_size)

            # Filter to run-scope hosts only if set (derive host from URL when missing)
            run_scope_hosts = os.environ.get('MODSCAN_RUN_SCOPE_HOSTS')
            if run_scope_hosts:
                allowed_hosts = set(h.strip().lower().lstrip('.') for h in run_scope_hosts.split(',') if h.strip())
                def _asset_host(a):
                    try:
                        h = (a.get('host') or '').strip().lower()
                        if not h:
                            h = (urlparse(a.get('url', '')).hostname or '').strip().lower()
                        return h.lstrip('.')
                    except Exception:
                        return ''
                filtered = [asset for asset in ready_assets if _asset_host(asset) in allowed_hosts]
                if filtered:
                    logger.info(f"🎯 Filtered deep scan to run-scope: {len(filtered)} assets for {', '.join(sorted(allowed_hosts))}")
                    ready_assets = filtered
                else:
                    logger.info("🎯 Run-scope filter left 0 assets; skipping deep scan this cycle")

            # If CLI provided exact URLs, scan them first in this cycle (universal-safe override)
            forced = []
            if getattr(self, 'forced_scan_queue', None):
                forced = list(self.forced_scan_queue)
                self.forced_scan_queue.clear()
                if forced:
                    logger.info(f"🎯 Forced direct scan: {len(forced)} exact URLs from CLI")
                    try:
                        await self.parallel_scanner.bulk_scan_targets(
                            targets=[{'asset_id': a['id'], 'url': a['url'], 'priority': 10, 'status_code': a.get('status_code'), 'tech_stack': a.get('tech_stack','')} for a in forced],
                            scan_types=['adaptive', 'comprehensive']
                        )
                    except Exception as e:
                        logger.error(f"Forced direct scan failed: {e}")

            if not ready_assets:
                logger.info("Tier 3: No assets ready for deep scan.")
                return

            logger.info(f"Tier 3: MAXIMUM UTILIZATION - Parallel scanning {len(ready_assets)} assets across {num_workers} workers.")
            
            # Prioritize login/auth endpoints first for better credential coverage
            def _priority_key(a):
                u = (a.get('url') or '').lower()
                hints = ['login','signin','logon','auth','account/login']
                return 0 if any(h in u for h in hints) else 1
            ready_assets = sorted(ready_assets, key=_priority_key)

            # Convert assets to parallel scan tasks (preserve status/tech for smarter scans)
            scan_tasks = []
            for asset in ready_assets:
                scan_tasks.append({
                    'asset_id': asset['id'],
                    'url': asset['url'],
                    'priority': 1,  # Equal priority for now
                    'status_code': asset.get('status_code'),
                    'tech_stack': asset.get('tech_stack', '')
                })
            
            # Execute parallel scan with all vulnerability types
            await self.parallel_scanner.bulk_scan_targets(
                targets=scan_tasks,
                scan_types=['adaptive', 'comprehensive']  # Run adaptive planner before legacy sweep
            )

        except Exception as e:
            logger.error(f"Tier 3 vulnerability scanning error: {e}", exc_info=True)

async def main():
    # CLI: allow direct targets and toggles without profiles
    parser = argparse.ArgumentParser(prog="modscan-engine", add_help=True)
    parser.add_argument('targets', nargs='*', help='Domains or URLs to add to scope')
    parser.add_argument('--no-ttl', action='store_true', help='Disable TTL for this run (fresh discovery)')
    parser.add_argument('--ttl-hours', type=int, default=None, help='Set TTL hours (0 disables TTL)')
    parser.add_argument('--max-cycles', type=int, default=None, help='Override scan cycle limit')
    parser.add_argument('--no-add-scope', action='store_true', help='Do not add positional targets to scope')
    parser.add_argument('--run-scope', type=str, default=None, help='Comma-separated list of hosts to isolate run scope (no env export needed)')
    parser.add_argument('--quiet', action='store_true', help='Reduce console output (warnings and errors only)')
    parser.add_argument('--debug', action='store_true', help='Verbose debug output for troubleshooting')
    parser.add_argument('--retest-all', action='store_true', help='Ignore prior findings/test history and retest everything')
    parser.add_argument('--login', type=str, default=None, help='Login credentials in format: url,username,password')
    # New: explicit flags for login URL/user/pass (alternative to --login)
    parser.add_argument('--login-url', type=str, default=None, help='Login URL for automatic authentication')
    parser.add_argument('--login-user', type=str, default=None, help='Username/email for login')
    parser.add_argument('--login-pass', type=str, default=None, help='Password for login')
    args, _ = parser.parse_known_args(sys.argv[1:])

    # Apply run-scope isolation before engine initialization so all modules honor it
    run_scope_hosts = []
    if args.run_scope:
        try:
            run_scope_hosts = [h.strip() for h in args.run_scope.split(',') if h.strip()]
            if run_scope_hosts:
                os.environ['MODSCAN_RUN_SCOPE_HOSTS'] = ','.join(run_scope_hosts)
                logger.info(f"🎯 Run scope isolated to: {', '.join(run_scope_hosts)}")
                if not os.environ.get('MODSCAN_DISABLE_MASSIVE_DISCOVERY'):
                    os.environ['MODSCAN_DISABLE_MASSIVE_DISCOVERY'] = 'true'
                if not os.environ.get('MODSCAN_DISABLE_INTELLIGENT_DIRECTORY'):
                    os.environ['MODSCAN_DISABLE_INTELLIGENT_DIRECTORY'] = 'true'
                if not os.environ.get('MODSCAN_DISABLE_TIER7_UNIVERSAL'):
                    os.environ['MODSCAN_DISABLE_TIER7_UNIVERSAL'] = 'true'
                if not os.environ.get('MODSCAN_DISABLE_FFUF_RECURSIVE'):
                    os.environ['MODSCAN_DISABLE_FFUF_RECURSIVE'] = 'true'
        except Exception as e:
            logger.warning(f"Failed to parse --run-scope: {e}")
            run_scope_hosts = []

    # Handle CLI login credentials (both --login and explicit flags)
    cli_login_creds = None
    try:
        login_url = None
        username = None
        password = None
        if args.login:
            parts = [p.strip() for p in args.login.split(',')]
            if len(parts) == 3:
                login_url, username, password = parts
            else:
                logger.warning("❌ Invalid --login format. Use: --login 'url,username,password'")
        # Explicit flags override combined if provided
        if args.login_url and args.login_user and args.login_pass:
            login_url = args.login_url.strip()
            username = args.login_user.strip()
            password = args.login_pass.strip()
        if login_url and username and password:
            domain = urlparse(login_url).hostname
            if domain:
                cli_login_creds = {
                    domain: {
                        'login': {
                            'url': login_url,
                            'username': username,
                            'password': password
                        }
                    }
                }
                logger.info(f"🔐 CLI login credentials prepared for {domain}")
            else:
                logger.warning("❌ Invalid login URL format - could not extract domain")
    except Exception as e:
        logger.warning(f"❌ Failed to parse CLI login credentials: {e}")

    logger.info("�� Starting ModScan Engine...")
    # Pass CLI-provided login/auth to Engine so modules see them at init time
    scanner = Engine(domain_auth_overrides=cli_login_creds or {})

    # Seed scope from CLI targets unless explicitly disabled
    direct_urls = []
    if args.targets:
        for t in args.targets:
            if '://' in t:
                direct_urls.append(t)
            else:
                direct_urls.append(f"https://{t}")
        if not args.no_add_scope:
            added = scanner.seed_scope_targets(args.targets)
            logger.info(f"🧭 Scope seeding complete: {added}/{len(args.targets)} targets added")

    # Ensure run-scope hosts are seeded after engine creation if requested
    if run_scope_hosts and not args.no_add_scope:
        try:
            added2 = scanner.seed_scope_targets(run_scope_hosts)
            logger.info(f"🧭 Run-scope seeding complete: {added2}/{len(run_scope_hosts)} targets added")
        except Exception:
            pass

    # Prepare forced scan for exact URLs (ensure assets exist and queue them)
    if direct_urls:
        try:
            with scanner.asset_manager._get_db() as db:
                f = scanner.asset_manager.get_asset_fields()
                forced_assets = []
                for u in direct_urls:
                    row = db.execute(
                        f"SELECT {f['id']}, {f['url']}, COALESCE({f['status_code']},0), COALESCE({f['tech_stack']},'') FROM assets WHERE {f['url']}=? LIMIT 1",
                        (u,)
                    ).fetchone()
                    if row:
                        forced_assets.append({'id': row[0], 'url': row[1], 'status_code': row[2], 'tech_stack': row[3]})
                    else:
                        db.execute(
                            f"INSERT INTO assets({f['url']}, {f['host']}, discovered_at, last_scanned) VALUES(?,?,datetime('now'), datetime('now'))",
                            (u, (urlparse(u).hostname or ''),)
                        )
                        aid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
                        forced_assets.append({'id': aid, 'url': u, 'status_code': 0, 'tech_stack': ''})
                # Mark as not deep scanned so normal selector would also consider them if needed
                for a in forced_assets:
                    try:
                        db.execute("UPDATE assets SET deep_scan_complete=0 WHERE id=?", (a['id'],))
                    except Exception:
                        pass
            scanner.forced_scan_queue = forced_assets
            logger.info(f"📌 Queued {len(forced_assets)} exact URL(s) for immediate scan")
        except Exception as e:
            logger.error(f"Failed to prepare forced scan URLs: {e}")

    # Apply runtime toggles via environment (non-invasive)
    if args.no_ttl:
        os.environ['MODSCAN_TTL_HOURS'] = '0'
        logger.info("⏱️ TTL disabled for this run (MODSCAN_TTL_HOURS=0)")
    elif isinstance(args.ttl_hours, int) and args.ttl_hours >= 0:
        os.environ['MODSCAN_TTL_HOURS'] = str(args.ttl_hours)
        logger.info(f"⏱️ TTL set to {args.ttl_hours}h for this run")
    if isinstance(args.max_cycles, int) and args.max_cycles > 0:
        os.environ['MODSCAN_MAX_CYCLES'] = str(args.max_cycles)
        logger.info(f"🔁 Max scan cycles set to {args.max_cycles}")

    # Adjust logging verbosity after init if requested
    try:
        if args.debug and not args.quiet:
            lvl = logging.DEBUG
        elif args.quiet and not args.debug:
            lvl = logging.WARNING
        else:
            lvl = logging.INFO
        # Root and our logger
        logging.getLogger().setLevel(lvl)
        logger.setLevel(lvl)
        for h in logger.handlers:
            try:
                h.setLevel(lvl)
            except Exception:
                pass
        # Quiet common module loggers too
        for name in ("process_watchdog", "UltimateDiscovery", "VulnerabilityScanner", "ParallelScannerOrchestrator"):
            try:
                logging.getLogger(name).setLevel(lvl)
            except Exception:
                pass
    except Exception:
        pass

    # Apply retest-all flag to bypass prior-findings/test-history gates universally
    try:
        if args.retest_all:
            os.environ['MODSCAN_FORCE_RETEST'] = '1'
            os.environ['MODSCAN_TEST_TTL_MIN'] = '0'
            logger.info("🔁 Retest-all enabled: bypassing prior findings/test history gates")
    except Exception:
        pass

    await scanner.run_scan_cycle()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("🛑 Engine stopped by user.")
    except Exception as e:
        logger.error(f"🚨 Engine crashed: {e}")
    finally:
        # Final cleanup - kill any remaining processes
        logger.info("🧹 Final process cleanup...")
        try:
            from process_watchdog import ProcessWatchdog
            ProcessWatchdog().run_health_check()
        except Exception:
            pass
