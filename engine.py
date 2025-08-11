#!/usr/bin/env python3
"""
🚀 MODULAR HIGH-PERFORMANCE VULNERABILITY SCANNER
Main orchestrator that coordinates all scanning modules
"""

import asyncio
import aiohttp
import logging
import time
import psutil
from pathlib import Path
from datetime import datetime
import json
import hashlib

# Import all modular components
from modules.seclists_manager import SecListsManager
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.discovery_engine import DiscoveryEngine
from modules.technology_detector import TechnologyDetector
from modules.proxy_manager import ProxyManager
from modules.ml_engine import MLEngine
from modules.screenshot_manager import ScreenshotManager
from modules.waf_bypass import WAFBypass
from modules.reconnaissance import ReconnaissanceEngine

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
        # Initialize YOUR AssetManager first (centralized field mapping)
        self.asset_manager = AssetManager()
        
        # Initialize all scanning modules with AssetManager reference
        self.seclists_manager = SecListsManager(self.asset_manager, CONFIG)
        self.vulnerability_scanner = VulnerabilityScanner(self.asset_manager, CONFIG)
        self.proxy_manager = ProxyManager(self.asset_manager, CONFIG)  # Initialize proxy manager first
        self.discovery_engine = DiscoveryEngine(self.asset_manager, CONFIG, self.proxy_manager)  # Pass shared proxy manager
        self.technology_detector = TechnologyDetector(self.asset_manager, CONFIG)
        self.ml_engine = MLEngine(self.asset_manager, CONFIG)
        self.screenshot_manager = ScreenshotManager(self.asset_manager, CONFIG)
        self.waf_bypass = WAFBypass(self.asset_manager, CONFIG)
        self.reconnaissance = ReconnaissanceEngine(self.asset_manager, CONFIG)
        
        # Performance settings
        self.cpu_target = CONFIG.get("cpu_target_utilization", 75)
        self.max_concurrent = min(4000, self.cpu_target * 30)
        self.session_limit = self.max_concurrent * 3
        # Runtime controls and state
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        self.seen = set()  # de-duplication of scan keys
        self.findings_path = BASE_DIR / "findings.jsonl"
        
        logger.info("🚀 Modular Scanner initialized - all modules using AssetManager field mappings")
    
    async def initialize_all_modules(self):
        """Initialize all scanning modules"""
        
        # Initialize modules in parallel
        init_tasks = [
            self.seclists_manager.initialize(),
            self.vulnerability_scanner.initialize(),
            self.discovery_engine.start(),
            self.technology_detector.initialize(),
            self.proxy_manager.initialize(),
            self.ml_engine.initialize(),
            self.screenshot_manager.initialize(),
            self.waf_bypass.initialize(),
            self.reconnaissance.initialize()
        # Start background CPU auto-tuning of concurrency
        asyncio.create_task(self._cpu_autotune_loop())
        ]
        
        await asyncio.gather(*init_tasks, return_exceptions=True)
        
        logger.info("✅ All modules initialized using AssetManager mappings")
    
    def monitor_and_adjust_performance(self) -> float:
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
        await self.initialize_all_modules()
        
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
                    
                    # Update proxy health through ProxyManager
                    await self.proxy_manager.update_proxy_health(session)
                    
                    logger.info(f"🔄 MODULAR SCAN CYCLE {scan_cycle} - CPU: {cpu_usage:.1f}%")
                    
                    # Execute all tiers using modular components
                    tier_tasks = [
                        self._tier1_modular_discovery(session),
                        self._tier2_modular_profiling(session),
                        self._tier3_modular_vulnerability_scanning(session),
                        self._tier4_modular_advanced_recon(session)
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
        """Tier 1: Discovery using DiscoveryEngine module"""
        try:
            # Get new targets using DiscoveryEngine module
            new_targets = await self.discovery_engine.generate_intelligent_targets()
            
            if not new_targets:
                return
            
            logger.info(f"🔍 TIER 1: Modular discovery of {len(new_targets)} targets")
            
            # Process discovery using DiscoveryEngine
            discovered_count = await self.discovery_engine.process_discovery_batch(
                new_targets, session, semaphore_limit=300
            )
            
            logger.info(f"✅ TIER 1: Discovered {discovered_count} new assets using DiscoveryEngine")
            
        except Exception as e:
            logger.error(f"Tier 1 modular discovery error: {e}")
    
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
    
    async def _tier4_modular_advanced_recon(self, session: aiohttp.ClientSession):
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
    """Kill any existing engine processes before starting"""
    import subprocess
    import os
    import signal
    
    try:
        logger.info("🔍 Checking for existing engine processes...")
        
        # Find existing engine processes
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        engine_processes = []
        
        for line in result.stdout.split('\n'):
            if 'engine.py' in line and 'python' in line and str(os.getpid()) not in line:
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        pid = int(parts[1])
                        engine_processes.append(pid)
                        logger.info(f"📍 Found existing engine process: PID {pid}")
                    except ValueError:
                        continue
        
        # Kill existing processes
        for pid in engine_processes:
            try:
                os.kill(pid, signal.SIGTERM)
                logger.info(f"💀 Killed existing engine process: PID {pid}")
                time.sleep(1)
                
                # Force kill if still running
                try:
                    os.kill(pid, signal.SIGKILL)
                    logger.info(f"🔨 Force killed stubborn process: PID {pid}")
                except ProcessLookupError:
                    pass  # Process already dead
                    
            except ProcessLookupError:
                logger.info(f"✅ Process {pid} already terminated")
            except Exception as e:
                logger.error(f"❌ Failed to kill process {pid}: {e}")
        
        # Wait and verify all processes are dead
        time.sleep(2)
        
        # Double-check no engine processes remain
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        remaining = []
        for line in result.stdout.split('\n'):
            if 'engine.py' in line and 'python' in line and str(os.getpid()) not in line:
                remaining.append(line)
        
        if remaining:
            logger.error(f"⚠️  {len(remaining)} engine processes still running after cleanup!")
            for proc in remaining:
                logger.error(f"   Still running: {proc}")
            return False
        else:
            logger.info("✅ All existing engine processes successfully terminated")
            return True
            
    except Exception as e:
        logger.error(f"❌ Error during process cleanup: {e}")
        return False

async def main():
    """Main entry point for modular scanner"""
    logger.info("🚀 Starting ModScan Engine with process management...")
    
    # Kill any existing engine processes
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

    async def _cpu_autotune_loop(self):
        """
        Background task: keep CPU near target by adjusting concurrency.
        - Samples CPU every 2s.
        - Expands/shrinks the semaphore permits within bounds.
        """
        target = int(self.cpu_target)
        min_conc = max(32, int(self.max_concurrent * 0.10))
        max_conc = int(self.max_concurrent)
        # Current permits tracked as a soft state (start at max)
        current = max_conc
        try:
            while True:
                cpu = int(psutil.cpu_percent(interval=1))
                # If CPU is low, try to increase concurrency
                if cpu < target - 5 and current < max_conc:
                    delta = max(1, (target - cpu) // 2)
                    new = min(max_conc, current + delta)
                    # Grow: release additional permits
                    for _ in range(new - current):
                        self.semaphore.release()
                    current = new
                # If CPU is high, try to decrease concurrency
                elif cpu > target + 5 and current > min_conc:
                    delta = max(1, (cpu - target) // 2)
                    new = max(min_conc, current - delta)
                    # Shrink: acquire permits to reduce available slots
                    # NOTE: acquire with timeout to avoid deadlock
                    for _ in range(current - new):
                        try:
                            await asyncio.wait_for(self.semaphore.acquire(), timeout=0.1)
                        except asyncio.TimeoutError:
                            break
                    current = new
                await asyncio.sleep(2)
        except asyncio.CancelledError:
            return

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
            line = (json.dumps(finding, ensure_ascii=False) + "
")
            # Lazy open to avoid keeping fd around
            with open(self.findings_path, "a", encoding="utf-8") as fp:
                fp.write(line)
        except Exception as e:
            logger.error("Failed to write finding: %s", e)
if __name__ == "__main__":
    asyncio.run(main())
