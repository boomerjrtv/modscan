#!/usr/bin/env python3
"""
🚀 MODULAR HIGH-PERFORMANCE VULNERABILITY SCANNER
Main orchestrator that coordinates all scanning modules
"""

import asyncio
import aiohttp
import logging
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

# Import Multi-AI Pentester Team (XBOW-inspired)
from modules.multi_ai_pentester_team import MultiAIPentesterTeam

# Import YOUR AssetManager for centralized field mapping
from asset_manager import AssetManager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ModularScanner")

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
        
        # Initialize all scanning modules with AssetManager reference
        self.seclists_manager = SecListsManager(self.asset_manager, CONFIG)
        self.vulnerability_scanner = VulnerabilityScanner(self.asset_manager, CONFIG)
        self.proxy_manager = ProxyManager(self.asset_manager, CONFIG)  # Initialize proxy manager first
        self.discovery_engine = UltimateDiscoveryEngine(self.asset_manager, CONFIG)
        self.technology_detector = TechnologyDetector(self.asset_manager, CONFIG)
        self.ml_engine = MLEngine(self.asset_manager, CONFIG)
        self.screenshot_manager = ScreenshotManager(self.asset_manager, CONFIG)
        self.waf_bypass = WAFBypass(self.asset_manager, CONFIG)
        self.reconnaissance = ReconnaissanceEngine(self.asset_manager, CONFIG)
        
        # Initialize Multi-AI Pentester Team (XBOW-inspired)
        self.ai_pentester_team = MultiAIPentesterTeam(self.asset_manager, CONFIG)
        
        # Runtime controls and state will be set up after initialization
        
        # Performance settings
        self.cpu_target = CONFIG.get("cpu_target_utilization", 75)
        self.max_concurrent = min(4000, self.cpu_target * 30)
        self.session_limit = self.max_concurrent * 3
        # Runtime controls and state
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        self.seen = set()  # de-duplication of scan keys
        self.findings_path = BASE_DIR / "findings.jsonl"
        
        logger.info("🚀 Modular Scanner initialized - all modules using AssetManager field mappings")
    
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
        cpu_usage = psutil.cpu_percent(interval=1)
        if cpu_usage > self.cpu_target:
            self.max_concurrent = max(100, int(self.max_concurrent * 0.9))
        elif cpu_usage < self.cpu_target - 10:
            self.max_concurrent = min(4000, int(self.max_concurrent * 1.1))
        logger.info(f"[Perf] CPU: {cpu_usage}% | Max concurrent: {self.max_concurrent}")
        """Monitor CPU and adjust all modules dynamically"""
        try:
            current_cpu = psutil.cpu_percent(interval=0.2)
            
            # Adjust all modules based on CPU usage
            if current_cpu < self.cpu_target - 15:
                self.max_concurrent = min(1200, self.max_concurrent + 50)
                # Notify all modules of performance increase
                self._adjust_module_performance("increase")
            elif current_cpu > self.cpu_target + 10:
                self.max_concurrent = max(100, self.max_concurrent - 20)
                # Notify all modules of performance decrease
                self._adjust_module_performance("decrease")
            
            return current_cpu
        except Exception as e:
            logger.error(f"CPU monitoring error: {e}")
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
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=15),
            headers={'User-Agent': 'ModularScanner/2025'}
        ) as session:
            
            scan_cycle = 0
            
            while True:
                try:
                    scan_cycle += 1
                    cpu_usage = self.monitor_and_adjust_performance()
                    
                    # Skip proxy health check to prevent hangs - proxies checked during initialization
                    logger.debug("⏭️ Skipping proxy health check to prevent hangs")
                    
                    logger.info(f"🔄 MODULAR SCAN CYCLE {scan_cycle} - CPU: {cpu_usage:.1f}%")
                    
                    # Execute all tiers using modular components
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
            # Get scope domains for discovery
            with self.asset_manager._get_db() as db:
                cursor = db.execute("SELECT domain FROM scope WHERE active = 1")
                domains = [row[0] for row in cursor.fetchall()]
            
            if not domains:
                logger.warning("⚠️  No scope domains found")
                return
            
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
                    logger.info(f"✅ Found {len(discovered_urls)} URLs for {clean_domain}")
                    total_discovered += len(discovered_urls)
                    
                    # Store discovered URLs in database
                    for url in discovered_urls:
                        try:
                            asset_data = {
                                'url': url,
                                'host': clean_domain,
                                'discovery_method': 'ultimate_discovery',
                                'discovered_at': datetime.now().isoformat()
                            }
                            self.asset_manager.add_asset(url, clean_domain, "ultimate_discovery")
                        except Exception as e:
                            logger.debug(f"Error storing asset {url}: {e}")
                
                # Mark domain as completed to prevent infinite loops (regardless of results)
                self.completed_domains.add(clean_domain)
                logger.info(f"✅ COMPLETED: {clean_domain} discovery finished - marked as complete")
            
            logger.info(f"✅ TIER 1: Discovered {total_discovered} total URLs using UltimateDiscoveryEngine")
            
        except Exception as e:
            logger.error(f"Tier 1 ultimate discovery error: {e}")
    
    async def _tier2_modular_profiling(self, session: aiohttp.ClientSession):
        """Tier 2: Profiling using TechnologyDetector and ScreenshotManager"""
        try:
            # Technology detection using TechnologyDetector module
            tech_tasks = [
                self.technology_detector.process_pending_assets(session, limit=75),
                self.screenshot_manager.process_pending_screenshots(session, limit=30)
            ]
            
            results = await asyncio.gather(*tech_tasks, return_exceptions=True)
            tech_completed = results[0] if len(results) > 0 and isinstance(results[0], int) else 0
            screenshot_completed = results[1] if len(results) > 1 and isinstance(results[1], int) else 0
            
            if tech_completed > 0 or screenshot_completed > 0:
                logger.info(f"✅ TIER 2: Technology detection: {tech_completed}, Screenshots: {screenshot_completed}")
            
        except Exception as e:
            logger.error(f"Tier 2 modular profiling error: {e}")
    
    async def _tier3_modular_vulnerability_scanning(self, session: aiohttp.ClientSession):
        """Tier 3: Vulnerability scanning using VulnerabilityScanner module"""
        try:
            # Get assets ready for scanning using AssetManager
            ready_assets = self.asset_manager.get_assets_ready_for_deep_scan(150)
            
            if not ready_assets:
                return
            
            logger.info(f"🚨 TIER 3: Modular vulnerability scanning {len(ready_assets)} assets")
            
            # Process vulnerabilities using VulnerabilityScanner module
            vulnerability_results = await self.vulnerability_scanner.scan_assets_for_vulnerabilities(
                ready_assets, session, semaphore_limit=150
            )
            
            total_vulns = sum(len(vulns) for vulns in vulnerability_results if vulns)
            assets_scanned = len([r for r in vulnerability_results if r])
            
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
    
    async def _tier4_multi_ai_pentesting(self, session: aiohttp.ClientSession):
        """Tier 4: Multi-AI Pentester Team (XBOW-inspired parallel testing)"""
        try:
            # Get assets ready for AI pentesting
            ready_assets = self.asset_manager.get_assets_ready_for_deep_scan(50)
            
            if not ready_assets:
                return
            
            # Extract URLs for testing
            urls = [asset['url'] for asset in ready_assets if asset.get('url')]
            
            if not urls:
                return
            
            logger.info(f"🤖 TIER 4: Multi-AI Pentester Team testing {len(urls)} assets")
            logger.info("🎯 AI Specialists: SQLi Hunter, XSS Hunter, AuthZ Hunter, InfoDisc Hunter")
            
            # Run parallel AI pentesting
            findings = await self.ai_pentester_team.parallel_pentest(urls, max_concurrent=20)
            
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
