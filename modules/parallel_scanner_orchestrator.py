#!/usr/bin/env python3
"""
🚀 PARALLEL SCANNER ORCHESTRATOR
Coordinates multiple vulnerability scanners running simultaneously for maximum speed
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import time
from concurrent.futures import ThreadPoolExecutor
import psutil
import random

from .vulnerability_scanner import VulnerabilityScanner
from .universal_scan_engine import UniversalScanEngine
from asset_manager import AssetManager

logger = logging.getLogger(__name__)

@dataclass
class ScanTask:
    """Represents a scanning task to be executed"""
    asset_id: int
    url: str
    scan_types: List[str]  # ['xss', 'sqli', 'lfi', etc.]
    priority: int = 1  # Higher = more priority
    created_at: float = None
    tech_stack: str = ""
    status_code: int | None = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = time.time()

class ParallelScannerOrchestrator:
    """
    Orchestrates multiple parallel vulnerability scanners for maximum performance.
    Replaces the old profile-based system with intelligent load balancing.
    """
    
    def __init__(self, asset_manager: AssetManager, config: Dict[str, Any], num_workers: int = None):
        self.asset_manager = asset_manager
        self.config = config
        
        # 🚀 MASSIVE HARDWARE UTILIZATION for 10700K + 32GB + 1GB internet
        override_workers = None
        try:
            override_workers = int(self.config.get('advanced_scanners', {}).get('max_concurrent_scanners') or 0)
        except Exception:
            override_workers = None

        if num_workers is not None:
            self.num_workers = int(num_workers)
        elif override_workers and override_workers > 0:
            # Use configured value - respect user limits, no hardcoded maximum
            self.num_workers = int(override_workers)
        else:
            cpu_count = psutil.cpu_count(logical=True) or psutil.cpu_count(logical=False) or 8
            memory_gb = psutil.virtual_memory().total // (1024**3)

            # 🎯 BALANCED PARALLELISM - good performance without overloading
            if cpu_count >= 10 and memory_gb >= 16:  # High-end hardware
                # Balanced approach for good performance
                self.num_workers = min(12, cpu_count)  # Reasonable parallelism
                logger.info(f"🚀 HIGH-END HARDWARE DETECTED: {cpu_count}C/{memory_gb}GB - Using {self.num_workers} workers")
            elif cpu_count >= 8 and memory_gb >= 8:
                self.num_workers = min(8, cpu_count)  # Good for medium hardware
            else:
                self.num_workers = min(6, cpu_count)  # Conservative for modest hardware
            
        logger.info(f"🚀 Parallel Scanner Orchestrator: {self.num_workers} worker threads")
        
        # Initialize worker pool
        self.scanner_pool = []
        # Larger queue for high-throughput environments
        self.task_queue = asyncio.Queue(maxsize=5000)
        self.active_tasks = {}  # task_id -> ScanTask
        self._queued_keys: set[str] = set()  # dedupe: url+scan_types
        self.worker_stats = {i: {'tasks_completed': 0, 'total_time': 0.0} for i in range(self.num_workers)}

        # Performance monitoring
        self.start_time = time.time()
        self.total_tasks_completed = 0
        self.total_vulnerabilities_found = 0

        # Load balancing state
        self.target_workload = {}  # domain -> current_active_scans

        # Initialize scanner workers
        self._initialize_workers()

        # Initialize adaptive universal scan engine
        try:
            self.universal_engine = UniversalScanEngine(self.asset_manager, self.config)
        except Exception as exc:
            logger.error(f"❌ Failed to initialize universal scan engine: {exc}")
            self.universal_engine = None
        
        # AI Pentester Team will be set by engine after initialization
        self.ai_pentester_team = None
        
    def set_ai_pentester_team(self, ai_team):
        """Set the Multi-AI Pentester Team for coordinated vulnerability testing"""
        self.ai_pentester_team = ai_team
        logger.info("🤖 Multi-AI Pentester Team integrated with parallel orchestrator")
        
    def _initialize_workers(self):
        """Initialize the pool of vulnerability scanner workers"""
        for i in range(self.num_workers):
            scanner = VulnerabilityScanner(self.asset_manager, self.config)
            self.scanner_pool.append(scanner)
            logger.debug(f"✅ Initialized scanner worker #{i+1}")
    
    async def add_scan_task(self, asset_id: int, url: str, scan_types: List[str], priority: int = 1, tech_stack: str = "", status_code: int | None = None):
        """Add a new scan task to the queue"""
        task = ScanTask(asset_id=asset_id, url=url, scan_types=scan_types, priority=priority, tech_stack=tech_stack or "", status_code=status_code)

        # Dedupe: avoid queueing same url+scan_types multiple times concurrently
        try:
            key = f"{url}|{','.join(sorted(scan_types))}"
            if key in self._queued_keys:
                logger.debug(f"⏭️ Deduped scan task already queued: {url} ({', '.join(scan_types)})")
                return False
            await self.task_queue.put(task)
            self._queued_keys.add(key)
            logger.debug(f"📋 Queued scan task: {url} ({', '.join(scan_types)})")
            return True
        except asyncio.QueueFull:
            logger.warning(f"⚠️ Task queue full, dropping scan for {url}")
            return False
    
    async def start_orchestrator(self):
        """Start the parallel scanning orchestrator"""
        logger.info("🎯 Starting Parallel Scanner Orchestrator")
        
        # Start worker coroutines
        worker_tasks = []
        for i in range(self.num_workers):
            task = asyncio.create_task(self._worker_loop(i))
            worker_tasks.append(task)
        
        # Start monitoring task
        monitor_task = asyncio.create_task(self._monitor_performance())
        
        try:
            # Wait for all workers and monitor
            await asyncio.gather(*worker_tasks, monitor_task)
        except KeyboardInterrupt:
            logger.info("🛑 Orchestrator shutdown requested")
            # Cancel all tasks
            for task in worker_tasks + [monitor_task]:
                task.cancel()
    
    async def _worker_loop(self, worker_id: int):
        """Main loop for a scanner worker"""
        scanner = self.scanner_pool[worker_id]
        worker_stats = self.worker_stats[worker_id]
        
        logger.debug(f"🏃 Worker #{worker_id+1} started")
        
        while True:
            try:
                # Get next task from queue (blocks until available)
                task = await self.task_queue.get()
                
                # Track active task
                task_id = f"worker_{worker_id}_{int(time.time() * 1000)}"
                self.active_tasks[task_id] = task
                
                # Update load balancing
                domain = self._extract_domain(task.url)
                self.target_workload[domain] = self.target_workload.get(domain, 0) + 1
                
                start_time = time.time()
                
                logger.info(f"🔍 Worker #{worker_id+1} scanning: {task.url}")
                
                # Execute the scan
                vulnerabilities_found = await self._execute_scan_task(scanner, task)
                
                # Update statistics
                end_time = time.time()
                scan_duration = end_time - start_time
                worker_stats['tasks_completed'] += 1
                worker_stats['total_time'] += scan_duration
                self.total_tasks_completed += 1
                self.total_vulnerabilities_found += len(vulnerabilities_found)
                
                # Update load balancing
                self.target_workload[domain] = max(0, self.target_workload.get(domain, 1) - 1)
                
                # Clean up
                del self.active_tasks[task_id]
                self.task_queue.task_done()
                # Remove from queued keys
                try:
                    qkey = f"{task.url}|{','.join(sorted(task.scan_types))}"
                    self._queued_keys.discard(qkey)
                except Exception:
                    pass
                
                logger.info(f"✅ Worker #{worker_id+1} completed {task.url} in {scan_duration:.1f}s - Found {len(vulnerabilities_found)} vulnerabilities")
                
            except asyncio.CancelledError:
                logger.info(f"🛑 Worker #{worker_id+1} cancelled")
                break
            except Exception as e:
                logger.error(f"❌ Worker #{worker_id+1} error: {e}")
                # Continue processing other tasks
                continue
    
    async def _execute_scan_task(self, scanner: VulnerabilityScanner, task: ScanTask) -> List[Dict]:
        """Execute a single scan task using the provided scanner"""
        vulnerabilities = []
        
        try:
            # Execute different scan types based on task specification
            for scan_type in task.scan_types:
                if scan_type == 'comprehensive':
                    # Run comprehensive scan (all vulnerability types)
                    # Use the REAL asset_id and pass through context (tech/status)
                    asset_dict = {'url': task.url, 'id': task.asset_id, 'tech_stack': task.tech_stack or '', 'status_code': task.status_code}
                    result = await scanner.scan_assets_for_vulnerabilities([asset_dict])
                    if result and len(result) > 0:
                        result = result[0]  # Extract findings from list
                elif scan_type == 'xss':
                    # Run XSS-specific scan
                    result = await scanner.test_xss_comprehensive(task.url)
                elif scan_type == 'sqli':
                    # Run SQL injection scan
                    result = await scanner.test_sql_injection_comprehensive(task.url)
                elif scan_type == 'lfi':
                    # Run Local File Inclusion scan
                    result = await scanner.test_lfi_comprehensive(task.url)
                elif scan_type == 'ssrf':
                    # Run Server-Side Request Forgery scan
                    result = await scanner.test_ssrf_comprehensive(task.url)
                elif scan_type == 'command_injection':
                    # Run Command Injection scan
                    result = await scanner.test_command_injection_comprehensive(task.url)
                elif scan_type == 'open_redirect':
                    # Run Open Redirect scan
                    result = await scanner.test_open_redirect_comprehensive(task.url)
                elif scan_type == 'adaptive':
                    if not self.universal_engine:
                        logger.warning("⚠️ Adaptive scan requested but universal engine unavailable")
                        result = []
                    else:
                        logger.info(f"🧠 Adaptive scan for {task.url}")
                        adaptive_asset = {
                            'url': task.url,
                            'id': task.asset_id,
                            'tech_stack': task.tech_stack or '',
                            'status_code': task.status_code,
                            'method': 'GET',
                        }
                        
                        # Run both universal adaptive scan AND Multi-AI Pentester Team
                        adaptive_results = []
                        
                        # 1. Universal adaptive scan (existing)
                        try:
                            universal_findings = await self.universal_engine.run_adaptive_scan(adaptive_asset)
                            if universal_findings:
                                adaptive_results.extend(universal_findings)
                                logger.info(f"🎯 Universal engine: {len(universal_findings)} findings for {task.url}")
                        except Exception as e:
                            logger.error(f"Universal adaptive scan failed for {task.url}: {e}")
                        
                        # 2. Multi-AI Pentester Team (NEW XBOW-STYLE)
                        if self.ai_pentester_team:
                            try:
                                logger.info(f"🤖 Multi-AI Pentester Team analyzing {task.url}")
                                ai_findings = await self.ai_pentester_team.parallel_pentest([task.url], max_concurrent=5)
                                if ai_findings:
                                    # Convert AI findings to standard format for storage
                                    for ai_finding in ai_findings:
                                        adaptive_results.append({
                                            'url': ai_finding.get('url', task.url),
                                            'type': ai_finding.get('type', 'Unknown'),
                                            'severity': ai_finding.get('severity', 'MEDIUM'),
                                            'payload': ai_finding.get('payload', ''),
                                            'evidence': ai_finding.get('evidence', ''),
                                            'confidence': 0.95,  # High confidence for AI-verified
                                            'source': f"AI Agent: {ai_finding.get('agent', 'Unknown')}",
                                            'ai_analysis': ai_finding.get('ai_analysis', ''),
                                            'discovered_at': ai_finding.get('discovered_at', ''),
                                            'affected_parameter': ai_finding.get('affected_parameter', '')
                                        })
                                    logger.info(f"🎯 AI Pentester Team: {len(ai_findings)} findings for {task.url}")
                                else:
                                    logger.info(f"ℹ️  AI Pentester Team: No vulnerabilities found for {task.url}")
                            except Exception as e:
                                logger.error(f"Multi-AI Pentester Team failed for {task.url}: {e}")
                        else:
                            logger.debug("⚠️ AI Pentester Team not available for adaptive scanning")
                        
                        result = adaptive_results
                else:
                    logger.warning(f"⚠️ Unknown scan type: {scan_type}")
                    continue

                if result and isinstance(result, list):
                    vulnerabilities.extend(result)
                    # CRITICAL FIX: Store findings in database immediately!
                    for finding in result:
                        try:
                            self.asset_manager.add_vulnerability_finding(finding, task.asset_id)
                            logger.info(f"🎯 STORED: {finding.vuln_type} - {finding.severity} - {task.url}")
                        except Exception as e:
                            logger.error(f"❌ Failed to store vulnerability: {e}")
                elif result:  # Single vulnerability finding
                    vulnerabilities.append(result)
                    # CRITICAL FIX: Store single finding in database!
                    try:
                        self.asset_manager.add_vulnerability_finding(result, task.asset_id)
                        logger.info(f"🎯 STORED: {result.vuln_type} - {result.severity} - {task.url}")
                    except Exception as e:
                        logger.error(f"❌ Failed to store vulnerability: {e}")
                    
        except Exception as e:
            logger.error(f"❌ Scan execution failed for {task.url}: {e}")
        
        return vulnerabilities
    
    async def _monitor_performance(self):
        """Monitor and log performance statistics"""
        while True:
            try:
                await asyncio.sleep(30)  # Report every 30 seconds
                
                uptime = time.time() - self.start_time
                avg_tasks_per_minute = (self.total_tasks_completed / uptime) * 60 if uptime > 0 else 0
                avg_vulns_per_minute = (self.total_vulnerabilities_found / uptime) * 60 if uptime > 0 else 0
                
                active_count = len(self.active_tasks)
                queue_size = self.task_queue.qsize()
                
                logger.info(f"📊 PERFORMANCE: {self.total_tasks_completed} tasks completed, "
                          f"{avg_tasks_per_minute:.1f} tasks/min, {avg_vulns_per_minute:.1f} vulns/min, "
                          f"Queue: {queue_size}, Active: {active_count}")
                
                # Log worker statistics
                for worker_id, stats in self.worker_stats.items():
                    if stats['tasks_completed'] > 0:
                        avg_time = stats['total_time'] / stats['tasks_completed']
                        logger.debug(f"Worker #{worker_id+1}: {stats['tasks_completed']} tasks, {avg_time:.1f}s avg")
                
                # Log target workload distribution
                if self.target_workload:
                    active_targets = {k: v for k, v in self.target_workload.items() if v > 0}
                    if active_targets:
                        logger.info(f"🎯 Active targets: {active_targets}")
                        
            except asyncio.CancelledError:
                logger.info("📊 Performance monitor stopped")
                break
            except Exception as e:
                logger.error(f"❌ Performance monitor error: {e}")
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL for load balancing"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except:
            return "unknown"
    
    def get_queue_size(self) -> int:
        """Get current queue size"""
        return self.task_queue.qsize()
    
    def get_active_tasks_count(self) -> int:
        """Get number of currently active tasks"""
        return len(self.active_tasks)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive orchestrator statistics"""
        uptime = time.time() - self.start_time
        
        return {
            'num_workers': self.num_workers,
            'uptime_seconds': uptime,
            'total_tasks_completed': self.total_tasks_completed,
            'total_vulnerabilities_found': self.total_vulnerabilities_found,
            'tasks_per_minute': (self.total_tasks_completed / uptime) * 60 if uptime > 0 else 0,
            'vulnerabilities_per_minute': (self.total_vulnerabilities_found / uptime) * 60 if uptime > 0 else 0,
            'queue_size': self.task_queue.qsize(),
            'active_tasks': len(self.active_tasks),
            'worker_stats': self.worker_stats.copy(),
            'target_workload': self.target_workload.copy()
        }

    async def bulk_scan_targets(self, targets: List[Dict[str, Any]], scan_types: List[str] = None):
        """
        Intelligently distribute multiple targets across workers with load balancing
        
        Args:
            targets: List of target dictionaries with 'asset_id', 'url', etc.
            scan_types: Types of scans to perform (defaults to comprehensive)
        """
        if scan_types is None:
            scan_types = ['adaptive', 'comprehensive']
        
        logger.info(f"🎯 Bulk scanning {len(targets)} targets with load balancing")
        
        # Sort targets by priority (if available) and distribute load
        sorted_targets = sorted(targets, key=lambda t: t.get('priority', 1), reverse=True)
        
        # Add tasks to queue with intelligent prioritization
        for target in sorted_targets:
            domain = self._extract_domain(target['url'])
            current_load = self.target_workload.get(domain, 0)
            
            # Adjust priority based on current load (less loaded targets get higher priority)
            adjusted_priority = target.get('priority', 1) + max(0, 5 - current_load)
            
            await self.add_scan_task(
                asset_id=target['asset_id'],
                url=target['url'],
                scan_types=scan_types,
                priority=adjusted_priority
            )
        
        logger.info(f"✅ Queued {len(targets)} scan tasks for parallel execution")
