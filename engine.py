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

# Load configuration
BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / 'config.json'
try:
    with open(CONFIG_PATH) as f:
        CONFIG = json.load(f)
except FileNotFoundError:
    CONFIG = {"cpu_target_utilization": 75, "proxy_list": []}

class Engine:
    def __init__(self):
        self.asset_manager = AssetManager()
        self.completed_domains = set()
        self.domain_auth = {}
        self._load_authentication()
        self._initialize_modules()
    
    
    def _initialize_modules(self):
        """Initialize all scanner modules"""
        AUTH_CONFIG = CONFIG.copy()
        AUTH_CONFIG['domain_auth'] = self.domain_auth

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
        self.max_concurrent = 15  # INCREASED for better 10-core utilization
        self.semaphore = asyncio.Semaphore(self.max_concurrent)

        logger.info("🚀 Modular Scanner initialized")

    def seed_scope_targets(self, targets: list[str]) -> int:
        """Add provided targets to scope (domains or URLs allowed).
        - Accepts domains, wildcards (*.example.com), or full URLs
        - Normalizes to registered host (strips scheme/port/wildcard)
        Returns number of successfully added records.
        """
        added = 0
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
                self.asset_manager.add_scope_target(host, is_active=1)
                added += 1
                logger.info(f"📌 Added to scope: {host}")
            except Exception as e:
                logger.debug(f"Failed adding scope seed '{raw}': {e}")
                continue
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
        """Monitor CPU usage and adjust operations dynamically"""
        cpu_percent = psutil.cpu_percent(interval=1)
        memory_percent = psutil.virtual_memory().percent
        
        if cpu_percent > 75:
            logger.warning(f"⚠️  HIGH CPU: {cpu_percent}% - Reducing concurrency")
            return "high"
        elif cpu_percent > 60:
            logger.info(f"🔶 MODERATE CPU: {cpu_percent}% - Normal operations")
            return "moderate" 
        elif memory_percent > 80:
            logger.warning(f"⚠️  HIGH MEMORY: {memory_percent}% - Reducing batch sizes")
            return "high_memory"
        else:
            logger.debug(f"✅ LOW USAGE: CPU {cpu_percent}%, Memory {memory_percent}%")
            return "low"

    def _load_authentication(self):
        # ... (load auth logic)
        pass

    async def run_scan_cycle(self):
        logger.info("🔧 Initializing all modules...")
        await self.initialize_all_modules()
        logger.info("🎯 Starting Modular Progressive Vulnerability Scanner with Parallel Processing")

        # Initialize process safety watchdog
        self.process_watchdog = ProcessWatchdog()
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
                with self.asset_manager._get_db() as db:
                    # Check pending domains that need discovery
                    cursor = db.execute("SELECT COUNT(*) FROM scope WHERE is_active = 1")
                    pending_domains = cursor.fetchone()[0]
                    
                    # Check unscanned assets (missing status_code)
                    cursor = db.execute("SELECT COUNT(*) FROM assets WHERE status_code IS NULL")
                    unscanned_count = cursor.fetchone()[0]
                    
                    # Check assets ready for vulnerability scanning
                    cursor = db.execute("""
                        SELECT COUNT(*) FROM assets 
                        WHERE status_code = 200 
                        AND (last_scanned IS NULL OR last_scanned < datetime('now', '-1 day'))
                        AND tech_stack IS NOT NULL
                    """)
                    scan_ready_count = cursor.fetchone()[0]

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

    async def initialize_all_modules(self):
        # ... (module init logic)
        pass

    def monitor_and_adjust_performance(self):
        """Monitor system resources and adjust scanner performance dynamically"""
        load_status = self._check_cpu_usage()
        
        # Adjust parallel scanner based on system load
        if hasattr(self, 'parallel_scanner') and self.parallel_scanner:
            current_workers = getattr(self.parallel_scanner, 'num_workers', 64)
            
            if load_status == "high":
                # High CPU/Memory: Reduce workers by 50%
                new_workers = max(2, current_workers // 2)
                logger.warning(f"🔥 HIGH LOAD: Reducing workers {current_workers} → {new_workers}")
                self.parallel_scanner.num_workers = new_workers
                
            elif load_status == "high_memory":
                # High Memory: Reduce workers by 25%  
                new_workers = max(4, int(current_workers * 0.75))
                logger.warning(f"💾 HIGH MEMORY: Reducing workers {current_workers} → {new_workers}")
                self.parallel_scanner.num_workers = new_workers
                
            elif load_status == "moderate":
                # Moderate load: Slight reduction
                new_workers = max(8, int(current_workers * 0.9))
                if new_workers != current_workers:
                    logger.info(f"🔶 MODERATE LOAD: Adjusting workers {current_workers} → {new_workers}")
                    self.parallel_scanner.num_workers = new_workers
                    
            elif load_status == "low":
                # Low load: Can increase up to original max
                original_max = min(32, (os.cpu_count() or 4) * 2)
                if current_workers < original_max:
                    new_workers = min(original_max, int(current_workers * 1.1))
                    logger.info(f"✅ LOW LOAD: Scaling up workers {current_workers} → {new_workers}")
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
            
            # Check if we recently discovered this domain (TTL check)
            ttl_hours = int(os.environ.get('MODSCAN_TTL_HOURS', '6'))  # Default 6 hours TTL
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
                # Run comprehensive discovery to find all endpoints
                discovered_urls = await self.discovery_engine.comprehensive_discovery(domain)
                logger.info(f"🎯 Discovered {len(discovered_urls)} URLs for {domain}")
                
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
        timeout = aiohttp.ClientTimeout(total=8)
        
        async with aiohttp.ClientSession(timeout=timeout) as session:
            sem = asyncio.Semaphore(max_concurrent)
            
            async def validate_url(url):
                async with sem:
                    try:
                        from urllib.parse import urlsplit, urlparse
                        sp = urlsplit(url)
                        path = sp.path or '/'
                        segs = [seg for seg in path.split('/') if seg]
                        # Skip synthetic-looking paths: file-with-dot before last segment or repeated segments
                        if any('.' in seg for seg in segs[:-1]):
                            return
                        from collections import Counter
                        c = Counter(segs)
                        if any(v > 3 for v in c.values()) or len(segs) > 10:
                            return
                        # Validate with GET and follow redirects; require terminal 200/201/202/204/401/403 and same path
                        async with session.get(url, allow_redirects=True) as get_response:
                            status_code = get_response.status
                            final_url = str(get_response.url)
                            if status_code in (200, 201, 202, 204, 401, 403) and urlsplit(final_url).path == path:
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
                                    'url': url,
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
            # Dynamic resource adjustment based on CPU usage
            resource_status = self._check_cpu_usage()
            if resource_status == "high":
                batch_limit, concurrency = 5, 3  # Less conservative - still safe
                sleep_delay = 1
            elif resource_status == "moderate":
                batch_limit, concurrency = 15, 8  # Increase for better performance
                sleep_delay = 0.5
            elif resource_status == "high_memory":
                batch_limit, concurrency = 10, 5  # Reduce batch, normal concurrency
                sleep_delay = 0.5
            else:
                batch_limit, concurrency = 25, 12  # MUCH higher for 10-core VM
                sleep_delay = 0.2
                
            logger.info(f"🎯 Resource status: {resource_status} - Using {concurrency} concurrent, batch {batch_limit}")
            
            # Get assets needing profiling with dynamic limits
            to_profile = self.asset_manager.get_assets_with_missing_data(limit=batch_limit)
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
                                            response_body = f"Error capturing response: {str(e)[:100]}"
                                    
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
            
            if not ready_assets:
                logger.info("Tier 3: No assets ready for deep scan.")
                return

            logger.info(f"Tier 3: MAXIMUM UTILIZATION - Parallel scanning {len(ready_assets)} assets across {num_workers} workers.")
            
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
                scan_types=['comprehensive']  # Test all vulnerability types
            )

        except Exception as e:
            logger.error(f"Tier 3 vulnerability scanning error: {e}", exc_info=True)

async def main():
    # CLI: allow direct targets and toggles without profiles
    parser = argparse.ArgumentParser(prog="modscan-engine", add_help=True)
    parser.add_argument('targets', nargs='*', help='Domains or URLs to add to scope')
    parser.add_argument('--no-ttl', action='store_true', help='Disable TTL for this run (fresh discovery)')
    parser.add_argument('--max-cycles', type=int, default=None, help='Override scan cycle limit')
    parser.add_argument('--no-add-scope', action='store_true', help='Do not add positional targets to scope')
    args, _ = parser.parse_known_args(sys.argv[1:])

    logger.info("🚀 Starting ModScan Engine...")
    scanner = Engine()

    # Seed scope from CLI targets unless explicitly disabled
    if args.targets and not args.no_add_scope:
        added = scanner.seed_scope_targets(args.targets)
        logger.info(f"🧭 Scope seeding complete: {added}/{len(args.targets)} targets added")

    # Apply runtime toggles via environment (non-invasive)
    if args.no_ttl:
        os.environ['MODSCAN_TTL_HOURS'] = '0'
        logger.info("⏱️ TTL disabled for this run (MODSCAN_TTL_HOURS=0)")
    if isinstance(args.max_cycles, int) and args.max_cycles > 0:
        os.environ['MODSCAN_MAX_CYCLES'] = str(args.max_cycles)
        logger.info(f"🔁 Max scan cycles set to {args.max_cycles}")

    await scanner.run_scan_cycle()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("🛑 Engine stopped by user.")
