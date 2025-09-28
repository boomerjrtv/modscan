"""
Massive Parallel Tool Orchestrator
=================================

Utilizes high-end hardware for maximum scanning throughput:
- Intel 10700K (10 cores, 20 threads)
- 32GB RAM
- 1GB symmetrical internet

Design Philosophy:
- Saturate network bandwidth with intelligent request distribution
- Maximize CPU utilization with concurrent tool execution
- RAM-efficient batching for large target sets
- Smart load balancing across tool types
"""

import asyncio
import aiohttp
import logging
import time
import psutil
import subprocess
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from datetime import datetime
import json
import tempfile
import os

from .confidence_engine import confidence_engine
from asset_manager import VulnerabilityFinding

logger = logging.getLogger(__name__)

@dataclass
class HardwareConfig:
    """Hardware configuration for optimal utilization"""
    cpu_cores: int = 10           # 10700K cores
    total_threads: int = 20       # Hyperthreading
    ram_gb: int = 32             # Total RAM
    bandwidth_mbps: int = 1000    # 1GB symmetrical

    # Calculated optimal values
    max_concurrent_tools: int = 50        # Multiple tools per core
    max_concurrent_requests: int = 200    # Network saturation
    nuclei_workers: int = 30             # Nuclei parallel templates
    dalfox_workers: int = 15             # XSS testing workers
    sqlmap_workers: int = 8              # Conservative for SQL injection
    ffuf_workers: int = 40               # Directory discovery workers

@dataclass
class ToolTask:
    """Individual tool execution task"""
    tool_name: str
    target_url: str
    priority: int  # 1=highest, 5=lowest
    estimated_duration: float  # seconds
    memory_requirement: int    # MB
    network_intensity: int     # 1-10 scale

class ParallelToolOrchestrator:
    """Massive parallel execution of security tools"""

    def __init__(self, hardware_config: HardwareConfig = None):
        self.config = hardware_config or HardwareConfig()
        self.running_tasks: Dict[str, asyncio.Task] = {}
        self.task_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self.results_queue: asyncio.Queue = asyncio.Queue()

        # Performance monitoring
        self.start_time = time.time()
        self.completed_tasks = 0
        self.active_tools: Set[str] = set()

        # Resource management
        self.memory_usage_mb = 0
        self.network_requests_per_second = 0

        # Tool executors
        self.thread_executor = ThreadPoolExecutor(max_workers=self.config.total_threads)
        self.process_executor = ProcessPoolExecutor(max_workers=self.config.cpu_cores)

    async def orchestrate_massive_scan(self, targets: List[str]) -> List[VulnerabilityFinding]:
        """
        Orchestrate massive parallel scanning across all tools

        Strategy:
        1. Distribute targets across tool types
        2. Launch tools in parallel with optimal concurrency
        3. Monitor resource utilization and adjust
        4. Collect and merge results
        """
        logger.info(f"🚀 MASSIVE PARALLEL SCAN: {len(targets)} targets")
        logger.info(f"🖥️  Hardware: {self.config.cpu_cores}C/{self.config.total_threads}T, {self.config.ram_gb}GB RAM, {self.config.bandwidth_mbps}Mbps")

        all_findings = []

        # Create tool task distribution
        tasks = self._create_task_distribution(targets)
        logger.info(f"📋 Generated {len(tasks)} parallel tool tasks")

        # Launch orchestration workers
        workers = [
            asyncio.create_task(self._nuclei_worker_pool()),
            asyncio.create_task(self._dalfox_worker_pool()),
            asyncio.create_task(self._sqlmap_worker_pool()),
            asyncio.create_task(self._ffuf_worker_pool()),
            asyncio.create_task(self._performance_monitor()),
            asyncio.create_task(self._results_collector())
        ]

        # Queue all tasks
        for task in tasks:
            await self.task_queue.put(task)

        # Wait for completion with timeout
        try:
            # Run for maximum 30 minutes
            await asyncio.wait_for(
                self._wait_for_completion(len(tasks)),
                timeout=1800  # 30 minutes
            )
        except asyncio.TimeoutError:
            logger.warning("⏰ Massive scan timed out after 30 minutes")

        # Collect final results
        while not self.results_queue.empty():
            findings = await self.results_queue.get()
            all_findings.extend(findings)

        # Cleanup workers
        for worker in workers:
            worker.cancel()

        # Performance summary
        duration = time.time() - self.start_time
        logger.info(f"🏁 MASSIVE SCAN COMPLETE: {self.completed_tasks} tasks in {duration:.1f}s")
        logger.info(f"📈 Throughput: {self.completed_tasks/duration:.1f} tasks/sec")
        logger.info(f"🔍 Total findings: {len(all_findings)}")

        return all_findings

    def _create_task_distribution(self, targets: List[str]) -> List[ToolTask]:
        """Create optimal task distribution across tools"""
        tasks = []

        for target in targets:
            # Nuclei - fast, parallel template execution
            tasks.append(ToolTask(
                tool_name='nuclei-general',
                target_url=target,
                priority=2,
                estimated_duration=30.0,
                memory_requirement=200,
                network_intensity=6
            ))

            tasks.append(ToolTask(
                tool_name='nuclei-lfi',
                target_url=target,
                priority=3,
                estimated_duration=15.0,
                memory_requirement=150,
                network_intensity=5
            ))

            # Dalfox XSS - medium intensity
            tasks.append(ToolTask(
                tool_name='dalfox',
                target_url=target,
                priority=2,
                estimated_duration=45.0,
                memory_requirement=300,
                network_intensity=7
            ))

            # SQLMap - conservative, high memory
            tasks.append(ToolTask(
                tool_name='sqlmap',
                target_url=target,
                priority=1,  # High priority for critical vulns
                estimated_duration=120.0,
                memory_requirement=500,
                network_intensity=4
            ))

            # ffuf - high network, fast
            tasks.append(ToolTask(
                tool_name='ffuf',
                target_url=target,
                priority=4,
                estimated_duration=60.0,
                memory_requirement=100,
                network_intensity=9
            ))

        # Sort by priority and estimated impact
        tasks.sort(key=lambda t: (t.priority, -t.network_intensity))
        return tasks

    async def _nuclei_worker_pool(self):
        """Nuclei worker pool - template parallelism"""
        nuclei_semaphore = asyncio.Semaphore(self.config.nuclei_workers)

        while True:
            try:
                task = await asyncio.wait_for(self.task_queue.get(), timeout=1.0)
                if task.tool_name.startswith('nuclei'):
                    asyncio.create_task(self._run_nuclei_task(task, nuclei_semaphore))
                else:
                    await self.task_queue.put(task)  # Put back if not nuclei
            except asyncio.TimeoutError:
                await asyncio.sleep(0.1)

    async def _run_nuclei_task(self, task: ToolTask, semaphore: asyncio.Semaphore):
        """Execute Nuclei with massive parallelism"""
        async with semaphore:
            try:
                cmd = [
                    '/home/michael/go/bin/nuclei',
                    '-u', task.target_url,
                    '-json', '-silent', '-no-color',
                    '-rate-limit', '50',  # High rate for 1GB connection
                    '-bulk-size', '25',   # Parallel template execution
                    '-timeout', '10s',
                    '-retries', '1',
                    '-c', str(self.config.nuclei_workers)  # Concurrency
                ]

                if task.tool_name == 'nuclei-lfi':
                    cmd.extend(['-tags', 'lfi,file-read'])
                elif task.tool_name == 'nuclei-general':
                    cmd.extend(['-tags', 'cve,exposure,misconfiguration'])

                start_time = time.time()

                # Execute with process pool for CPU utilization
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    self.process_executor,
                    self._run_subprocess,
                    cmd,
                    120  # 2 minute timeout
                )

                duration = time.time() - start_time

                # Parse results and calculate confidence
                findings = self._parse_nuclei_output(result, task.target_url)

                if findings:
                    await self.results_queue.put(findings)
                    logger.info(f"🎯 Nuclei {task.tool_name}: {len(findings)} findings from {task.target_url} ({duration:.1f}s)")

                self.completed_tasks += 1
                self.active_tools.discard(f"nuclei-{task.target_url}")

            except Exception as e:
                logger.error(f"❌ Nuclei task failed for {task.target_url}: {e}")

    async def _dalfox_worker_pool(self):
        """Dalfox worker pool - XSS testing parallelism"""
        dalfox_semaphore = asyncio.Semaphore(self.config.dalfox_workers)

        while True:
            try:
                task = await asyncio.wait_for(self.task_queue.get(), timeout=1.0)
                if task.tool_name == 'dalfox':
                    asyncio.create_task(self._run_dalfox_task(task, dalfox_semaphore))
                else:
                    await self.task_queue.put(task)
            except asyncio.TimeoutError:
                await asyncio.sleep(0.1)

    async def _run_dalfox_task(self, task: ToolTask, semaphore: asyncio.Semaphore):
        """Execute Dalfox with optimal settings"""
        async with semaphore:
            try:
                cmd = [
                    '/home/michael/go/bin/dalfox',
                    'url', task.target_url,
                    '--format', 'json',
                    '--silence',
                    '--delay', '20',      # Fast for 1GB connection
                    '--timeout', '10',
                    '--worker', str(min(15, self.config.dalfox_workers)),
                    '--waf-evasion',
                    '--mining-dict',
                    '--mining-dom',
                    '--follow-redirects',
                    '--mass'             # Mass scanning mode
                ]

                start_time = time.time()

                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    self.process_executor,
                    self._run_subprocess,
                    cmd,
                    180  # 3 minute timeout
                )

                duration = time.time() - start_time

                findings = self._parse_dalfox_output(result, task.target_url)

                if findings:
                    await self.results_queue.put(findings)
                    logger.info(f"🔥 Dalfox: {len(findings)} XSS findings from {task.target_url} ({duration:.1f}s)")

                self.completed_tasks += 1

            except Exception as e:
                logger.error(f"❌ Dalfox task failed for {task.target_url}: {e}")

    async def _sqlmap_worker_pool(self):
        """SQLMap worker pool - conservative concurrency"""
        sqlmap_semaphore = asyncio.Semaphore(self.config.sqlmap_workers)

        while True:
            try:
                task = await asyncio.wait_for(self.task_queue.get(), timeout=1.0)
                if task.tool_name == 'sqlmap':
                    asyncio.create_task(self._run_sqlmap_task(task, sqlmap_semaphore))
                else:
                    await self.task_queue.put(task)
            except asyncio.TimeoutError:
                await asyncio.sleep(0.1)

    async def _run_sqlmap_task(self, task: ToolTask, semaphore: asyncio.Semaphore):
        """Execute SQLMap with bug bounty safe settings"""
        async with semaphore:
            try:
                cmd = [
                    '/home/michael/.local/bin/sqlmap',
                    '-u', task.target_url,
                    '--batch',
                    '--level', '2',
                    '--risk', '1',        # Bug bounty safe
                    '--timeout', '15',
                    '--retries', '1',
                    '--delay', '1',       # Rate limiting
                    '--technique', 'BEU', # Boolean, Error, Union
                    '--threads', '3',     # Conservative threading
                    '--no-cast',
                    '--flush-session',
                    '--disable-coloring',
                    '--answers', 'quit=N,crack=N,dict=N,continue=Y'
                ]

                start_time = time.time()

                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    self.process_executor,
                    self._run_subprocess,
                    cmd,
                    300  # 5 minute timeout
                )

                duration = time.time() - start_time

                findings = self._parse_sqlmap_output(result, task.target_url)

                if findings:
                    await self.results_queue.put(findings)
                    logger.info(f"💉 SQLMap: {len(findings)} SQL injection findings from {task.target_url} ({duration:.1f}s)")

                self.completed_tasks += 1

            except Exception as e:
                logger.error(f"❌ SQLMap task failed for {task.target_url}: {e}")

    async def _ffuf_worker_pool(self):
        """ffuf worker pool - high network utilization"""
        ffuf_semaphore = asyncio.Semaphore(self.config.ffuf_workers)

        while True:
            try:
                task = await asyncio.wait_for(self.task_queue.get(), timeout=1.0)
                if task.tool_name == 'ffuf':
                    asyncio.create_task(self._run_ffuf_task(task, ffuf_semaphore))
                else:
                    await self.task_queue.put(task)
            except asyncio.TimeoutError:
                await asyncio.sleep(0.1)

    async def _run_ffuf_task(self, task: ToolTask, semaphore: asyncio.Semaphore):
        """Execute ffuf with high network utilization"""
        async with semaphore:
            try:
                cmd = [
                    '/home/michael/go/bin/ffuf',
                    '-u', f"{task.target_url}/FUZZ",
                    '-w', '/usr/share/wordlists/dirb/common.txt',
                    '-mc', '200,301,302,403,401,500',
                    '-rate', '100',       # High rate for 1GB connection
                    '-t', '50',           # High thread count
                    '-timeout', '10',
                    '-json'
                ]

                start_time = time.time()

                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    self.process_executor,
                    self._run_subprocess,
                    cmd,
                    120  # 2 minute timeout
                )

                duration = time.time() - start_time

                findings = self._parse_ffuf_output(result, task.target_url)

                if findings:
                    await self.results_queue.put(findings)
                    logger.info(f"🔍 ffuf: {len(findings)} discoveries from {task.target_url} ({duration:.1f}s)")

                self.completed_tasks += 1

            except Exception as e:
                logger.error(f"❌ ffuf task failed for {task.target_url}: {e}")

    async def _performance_monitor(self):
        """Monitor CPU, RAM, and network utilization"""
        while True:
            try:
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                network = psutil.net_io_counters()

                # Log performance every 30 seconds
                if int(time.time()) % 30 == 0:
                    logger.info(f"📊 Performance: CPU {cpu_percent:.1f}%, RAM {memory.percent:.1f}%, Active Tasks: {len(self.active_tools)}")
                    logger.info(f"🌐 Network: {network.bytes_sent/1024/1024:.1f}MB sent, {network.bytes_recv/1024/1024:.1f}MB recv")

                await asyncio.sleep(1)

            except Exception as e:
                logger.error(f"Performance monitoring error: {e}")
                await asyncio.sleep(5)

    async def _results_collector(self):
        """Collect and process results from all tools"""
        processed_results = 0

        while True:
            try:
                # Process results every second
                await asyncio.sleep(1)
                processed_results += 1

                if processed_results % 60 == 0:  # Every minute
                    logger.info(f"📈 Progress: {self.completed_tasks} tasks completed, {self.task_queue.qsize()} queued")

            except Exception as e:
                logger.error(f"Results collection error: {e}")

    async def _wait_for_completion(self, total_tasks: int):
        """Wait for all tasks to complete"""
        while self.completed_tasks < total_tasks:
            await asyncio.sleep(1)

            # Check if queue is empty and no active tools
            if self.task_queue.empty() and len(self.active_tools) == 0:
                break

    def _run_subprocess(self, cmd: List[str], timeout: int) -> Dict[str, Any]:
        """Run subprocess with timeout - executed in process pool"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            return {
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }

        except subprocess.TimeoutExpired:
            return {'stdout': '', 'stderr': 'Timeout', 'returncode': -1}
        except Exception as e:
            return {'stdout': '', 'stderr': str(e), 'returncode': -1}

    def _parse_nuclei_output(self, result: Dict[str, Any], url: str) -> List[VulnerabilityFinding]:
        """Parse Nuclei JSON output with evidence-based confidence"""
        findings = []

        if not result.get('stdout'):
            return findings

        for line in result['stdout'].strip().split('\n'):
            if not line.strip():
                continue

            try:
                nuclei_result = json.loads(line)
                info = nuclei_result.get('info', {})
                template_id = nuclei_result.get('template-id', 'unknown')

                # Use evidence-based confidence
                confidence_result = confidence_engine.calculate_confidence(
                    vuln_type='NUCLEI_FINDING',
                    response_text=str(nuclei_result),
                    payload=template_id
                )

                finding = VulnerabilityFinding(
                    url=nuclei_result.get('matched-at', url),
                    vuln_type=template_id.replace('-', '_').upper(),
                    severity=(info.get('severity', 'Medium')).title(),
                    confidence=confidence_result.score,
                    payload=nuclei_result.get('extracted-results', '') or template_id,
                    evidence=f"Nuclei template match: {info.get('name', 'Unknown')}. Evidence: {', '.join(confidence_result.evidence)}",
                    discovered_at=datetime.now(),
                    impact_description=info.get('description', 'Nuclei template detection'),
                    remediation=info.get('remediation', 'Review and fix identified issue')
                )
                findings.append(finding)

            except json.JSONDecodeError:
                continue

        return findings

    def _parse_dalfox_output(self, result: Dict[str, Any], url: str) -> List[VulnerabilityFinding]:
        """Parse Dalfox JSON output with evidence-based confidence"""
        findings = []

        if not result.get('stdout'):
            return findings

        try:
            dalfox_result = json.loads(result['stdout'])

            for vuln in dalfox_result.get('vulnerabilities', []):
                # Use evidence-based confidence
                confidence_result = confidence_engine.calculate_confidence(
                    vuln_type='XSS',
                    response_text=vuln.get('evidence', ''),
                    payload=vuln.get('payload', '')
                )

                finding = VulnerabilityFinding(
                    url=vuln.get('url', url),
                    vuln_type="XSS",
                    severity="High",
                    confidence=confidence_result.score,
                    payload=vuln.get('payload', ''),
                    evidence=f"Dalfox XSS detection. Evidence: {', '.join(confidence_result.evidence)}",
                    discovered_at=datetime.now(),
                    impact_description="Cross-site scripting vulnerability allows code execution",
                    remediation="Implement proper input validation and output encoding",
                    affected_parameter=vuln.get('parameter', 'unknown')
                )
                findings.append(finding)

        except json.JSONDecodeError:
            pass

        return findings

    def _parse_sqlmap_output(self, result: Dict[str, Any], url: str) -> List[VulnerabilityFinding]:
        """Parse SQLMap output with evidence-based confidence"""
        findings = []
        stdout = result.get('stdout', '')

        # Use evidence-based confidence
        confidence_result = confidence_engine.calculate_confidence(
            vuln_type='SQL_INJECTION',
            response_text=stdout,
            payload='sqlmap_scan'
        )

        if confidence_result.score >= 0.60:  # 60%+ confidence threshold
            finding = VulnerabilityFinding(
                url=url,
                vuln_type="SQL_INJECTION",
                severity="Critical",
                confidence=confidence_result.score,
                payload="SQLMap scan",
                evidence=f"SQLMap SQL injection detection. Evidence: {', '.join(confidence_result.evidence)}",
                discovered_at=datetime.now(),
                impact_description="SQL injection allows unauthorized database access",
                remediation="Use parameterized queries and input validation"
            )
            findings.append(finding)

        return findings

    def _parse_ffuf_output(self, result: Dict[str, Any], url: str) -> List[VulnerabilityFinding]:
        """Parse ffuf output for discovery findings"""
        findings = []

        # ffuf findings are informational discoveries, not vulnerabilities
        # Could be extended to create asset discoveries instead

        return findings

# Global orchestrator instance
parallel_orchestrator = ParallelToolOrchestrator()