"""
Adaptive Rate Controller - Intelligent Dynamic Rate Limiting
==========================================================

No more hardcoded bullshit. This system monitors real-time performance metrics
and adapts request rates, concurrency, and resource allocation dynamically.

Key Principles:
- Monitor actual network utilization, response times, error rates
- Detect WAF/rate limiting responses and back off intelligently
- Scale up aggressively when conditions allow
- Per-target adaptive learning (some targets handle 1000 req/sec, others 10)
- Real-time feedback loops with exponential backoff/ramp-up
- CPU, memory, and network bandwidth awareness
"""

import asyncio
import time
import logging
import statistics
import psutil
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
import aiohttp
import json

logger = logging.getLogger(__name__)

@dataclass
class PerformanceMetrics:
    """Real-time performance metrics for adaptive decisions"""
    timestamp: float
    response_time: float
    status_code: int
    error_type: Optional[str] = None
    bytes_received: int = 0
    target_host: str = ""
    tool_name: str = ""

@dataclass
class TargetProfile:
    """Learned performance profile for a specific target"""
    hostname: str
    max_safe_rate: float = 10.0        # Start conservative
    current_rate: float = 10.0
    max_concurrency: int = 5
    current_concurrency: int = 5

    # Performance history
    success_rate: float = 1.0
    avg_response_time: float = 0.0
    error_count: int = 0
    total_requests: int = 0

    # WAF/Protection detection
    waf_detected: bool = False
    rate_limited: bool = False
    last_rate_limit: Optional[float] = None

    # Learning metrics
    last_adjustment: float = 0.0
    consecutive_successes: int = 0
    consecutive_errors: int = 0

    # Performance bounds learned over time
    proven_max_rate: float = 10.0
    proven_max_concurrency: int = 5

@dataclass
class SystemResources:
    """Current system resource utilization"""
    cpu_percent: float
    memory_percent: float
    network_bytes_sent: int
    network_bytes_recv: int
    active_connections: int
    timestamp: float

class AdaptiveRateController:
    """
    Intelligent rate controller that learns optimal settings per target
    and adapts based on real-time performance feedback
    """

    def __init__(self):
        # Target-specific learned profiles
        self.target_profiles: Dict[str, TargetProfile] = {}

        # Performance monitoring
        self.metrics_history: deque = deque(maxlen=10000)  # Last 10k requests
        self.resource_history: deque = deque(maxlen=1000)   # Last 1k resource snapshots

        # Real-time tracking
        self.active_requests: Dict[str, int] = defaultdict(int)  # host -> count
        self.tool_performance: Dict[str, List[float]] = defaultdict(list)  # tool -> response_times

        # Adaptive parameters
        self.global_rate_multiplier = 1.0  # Global throttle when system overloaded
        self.learning_rate = 0.1            # How fast to adapt
        self.safety_margin = 0.8            # Conservative factor

        # Network bandwidth detection
        self.bandwidth_mbps = self._detect_bandwidth()
        self.max_network_utilization = 0.85  # Use 85% of available bandwidth

        # Start resource monitoring
        self._start_monitoring()

    def _detect_bandwidth(self) -> float:
        """Detect available network bandwidth"""
        try:
            # Check if we have bandwidth info in config
            # For now, assume 1000 Mbps (1GB) based on user info
            return 1000.0
        except:
            return 100.0  # Conservative fallback

    def _start_monitoring(self):
        """Start background resource monitoring"""
        asyncio.create_task(self._monitor_system_resources())

    async def _monitor_system_resources(self):
        """Continuously monitor system resources"""
        while True:
            try:
                net_io = psutil.net_io_counters()
                resources = SystemResources(
                    cpu_percent=psutil.cpu_percent(interval=0.1),
                    memory_percent=psutil.virtual_memory().percent,
                    network_bytes_sent=net_io.bytes_sent,
                    network_bytes_recv=net_io.bytes_recv,
                    active_connections=len(self.active_requests),
                    timestamp=time.time()
                )

                self.resource_history.append(resources)

                # Adjust global rate multiplier based on system load
                self._adjust_global_rate_multiplier(resources)

                await asyncio.sleep(1.0)  # Check every second

            except Exception as e:
                logger.error(f"Resource monitoring error: {e}")
                await asyncio.sleep(5.0)

    def _adjust_global_rate_multiplier(self, resources: SystemResources):
        """Adjust global rate multiplier based on system resources"""

        # CPU-based throttling
        if resources.cpu_percent > 95:
            self.global_rate_multiplier *= 0.7  # Aggressive throttle
        elif resources.cpu_percent > 85:
            self.global_rate_multiplier *= 0.9  # Moderate throttle
        elif resources.cpu_percent < 50:
            self.global_rate_multiplier = min(2.0, self.global_rate_multiplier * 1.1)  # Scale up

        # Memory-based throttling
        if resources.memory_percent > 90:
            self.global_rate_multiplier *= 0.8

        # Network bandwidth throttling
        if len(self.resource_history) >= 2:
            recent = list(self.resource_history)[-2:]
            if len(recent) == 2:
                bytes_diff = recent[1].network_bytes_sent - recent[0].network_bytes_sent
                time_diff = recent[1].timestamp - recent[0].timestamp

                if time_diff > 0:
                    current_mbps = (bytes_diff * 8) / (time_diff * 1000000)  # Convert to Mbps
                    bandwidth_usage = current_mbps / self.bandwidth_mbps

                    if bandwidth_usage > self.max_network_utilization:
                        self.global_rate_multiplier *= 0.8  # Throttle to prevent saturation
                    elif bandwidth_usage < 0.3:
                        self.global_rate_multiplier = min(3.0, self.global_rate_multiplier * 1.2)  # Scale up

        # Keep within reasonable bounds
        self.global_rate_multiplier = max(0.1, min(5.0, self.global_rate_multiplier))

    def get_target_profile(self, hostname: str) -> TargetProfile:
        """Get or create target profile"""
        if hostname not in self.target_profiles:
            self.target_profiles[hostname] = TargetProfile(hostname=hostname)
        return self.target_profiles[hostname]

    async def get_optimal_rate_and_concurrency(self, hostname: str, tool_name: str) -> Tuple[float, int]:
        """
        Get optimal rate and concurrency for target based on learned performance

        Returns: (requests_per_second, max_concurrency)
        """
        profile = self.get_target_profile(hostname)

        # Apply global throttling
        optimal_rate = profile.current_rate * self.global_rate_multiplier
        optimal_concurrency = max(1, int(profile.current_concurrency * self.global_rate_multiplier))

        # Tool-specific adjustments
        tool_multiplier = self._get_tool_multiplier(tool_name)
        optimal_rate *= tool_multiplier

        # Safety bounds
        optimal_rate = max(1.0, min(1000.0, optimal_rate))
        optimal_concurrency = max(1, min(100, optimal_concurrency))

        logger.debug(f"🎯 Rate for {hostname} ({tool_name}): {optimal_rate:.1f} req/s, {optimal_concurrency} concurrent")
        return optimal_rate, optimal_concurrency

    def _get_tool_multiplier(self, tool_name: str) -> float:
        """Get tool-specific rate multipliers based on tool characteristics"""
        multipliers = {
            'nuclei': 1.5,      # Nuclei is efficient, can handle higher rates
            'ffuf': 2.0,        # Directory discovery is very parallel-friendly
            'dalfox': 1.0,      # XSS testing is moderate
            'sqlmap': 0.5,      # SQL injection needs to be more careful
            'commix': 0.7,      # Command injection moderate
        }

        for tool_prefix, multiplier in multipliers.items():
            if tool_prefix in tool_name.lower():
                return multiplier

        return 1.0  # Default

    async def record_request_result(self, hostname: str, tool_name: str,
                                   response_time: float, status_code: int,
                                   content: str = "", error: str = ""):
        """Record request result and adapt rates based on performance"""

        profile = self.get_target_profile(hostname)

        # Create metrics record
        metrics = PerformanceMetrics(
            timestamp=time.time(),
            response_time=response_time,
            status_code=status_code,
            error_type=error if error else None,
            bytes_received=len(content.encode('utf-8', errors='ignore')),
            target_host=hostname,
            tool_name=tool_name
        )

        self.metrics_history.append(metrics)
        profile.total_requests += 1

        # Detect blocking/rate limiting
        is_blocked = self._detect_blocking(status_code, content, response_time)
        is_rate_limited = self._detect_rate_limiting(status_code, content)

        # Update profile based on result
        if is_blocked or is_rate_limited:
            await self._handle_blocking(profile, is_rate_limited)
        elif status_code in [200, 301, 302, 403, 404]:  # Successful responses (not blocked)
            await self._handle_success(profile, response_time)
        else:
            await self._handle_error(profile, status_code)

        # Learn from recent performance
        self._update_learning_metrics(profile)

    def _detect_blocking(self, status_code: int, content: str, response_time: float) -> bool:
        """Detect if request was blocked by WAF/security"""

        # Common blocking indicators
        blocking_indicators = [
            'blocked', 'forbidden', 'access denied', 'security violation',
            'ray id:', 'cloudflare', 'your ip address:', 'been blocked',
            'sorry, you have been blocked', 'sus', 'suspicious activity',
            'web application firewall', 'waf', 'security check',
            'bot protection', 'captcha', 'human verification'
        ]

        content_lower = content.lower()

        # Status code blocking
        if status_code in [403, 429, 503]:
            return True

        # Content-based blocking detection
        if any(indicator in content_lower for indicator in blocking_indicators):
            return True

        # Suspiciously fast responses (often blocking pages)
        if response_time < 0.1 and len(content) < 5000:
            return True

        return False

    def _detect_rate_limiting(self, status_code: int, content: str) -> bool:
        """Detect specific rate limiting responses"""

        rate_limit_indicators = [
            'rate limit', 'rate limiting', 'too many requests',
            'quota exceeded', 'limit exceeded', 'slow down',
            'retry after', 'try again later'
        ]

        if status_code == 429:  # Too Many Requests
            return True

        content_lower = content.lower()
        return any(indicator in content_lower for indicator in rate_limit_indicators)

    async def _handle_blocking(self, profile: TargetProfile, is_rate_limit: bool):
        """Handle blocked/rate limited requests"""

        profile.consecutive_errors += 1
        profile.consecutive_successes = 0
        profile.error_count += 1

        if is_rate_limit:
            profile.rate_limited = True
            profile.last_rate_limit = time.time()

        profile.waf_detected = True

        # Aggressive backoff for blocking
        backoff_factor = 0.3 if is_rate_limit else 0.5
        profile.current_rate = max(1.0, profile.current_rate * backoff_factor)
        profile.current_concurrency = max(1, int(profile.current_concurrency * backoff_factor))

        profile.last_adjustment = time.time()

        logger.warning(f"🚫 Blocking detected for {profile.hostname}: rate → {profile.current_rate:.1f}, concurrency → {profile.current_concurrency}")

    async def _handle_success(self, profile: TargetProfile, response_time: float):
        """Handle successful requests"""

        profile.consecutive_successes += 1
        profile.consecutive_errors = 0

        # Update running averages
        if profile.avg_response_time == 0:
            profile.avg_response_time = response_time
        else:
            profile.avg_response_time = 0.9 * profile.avg_response_time + 0.1 * response_time

        # Calculate success rate
        profile.success_rate = (profile.total_requests - profile.error_count) / profile.total_requests

        # Scale up if performing well
        if profile.consecutive_successes >= 10 and time.time() - profile.last_adjustment > 30:
            self._scale_up_performance(profile, response_time)

    async def _handle_error(self, profile: TargetProfile, status_code: int):
        """Handle error responses"""

        profile.consecutive_errors += 1
        profile.consecutive_successes = 0
        profile.error_count += 1

        # Moderate backoff for errors
        if profile.consecutive_errors >= 5:
            profile.current_rate *= 0.8
            profile.current_concurrency = max(1, int(profile.current_concurrency * 0.9))
            profile.last_adjustment = time.time()

    def _scale_up_performance(self, profile: TargetProfile, response_time: float):
        """Intelligently scale up performance when conditions allow"""

        # Only scale up if response time is good and no recent blocking
        if (response_time < 2.0 and
            profile.success_rate > 0.95 and
            not profile.waf_detected and
            time.time() - (profile.last_rate_limit or 0) > 300):  # 5 minutes since rate limit

            # Conservative scaling
            scale_factor = 1.2 if response_time < 1.0 else 1.1

            new_rate = profile.current_rate * scale_factor
            new_concurrency = int(profile.current_concurrency * scale_factor)

            # Don't exceed proven maximums by too much
            profile.current_rate = min(new_rate, profile.proven_max_rate * 2.0)
            profile.current_concurrency = min(new_concurrency, profile.proven_max_concurrency * 2)

            # Update proven maximums
            profile.proven_max_rate = max(profile.proven_max_rate, profile.current_rate)
            profile.proven_max_concurrency = max(profile.proven_max_concurrency, profile.current_concurrency)

            profile.last_adjustment = time.time()

            logger.info(f"🚀 Scaling up {profile.hostname}: rate → {profile.current_rate:.1f}, concurrency → {profile.current_concurrency}")

    def _update_learning_metrics(self, profile: TargetProfile):
        """Update learning metrics for target"""

        # Reset WAF detection after successful period
        if (profile.consecutive_successes > 50 and
            time.time() - (profile.last_rate_limit or 0) > 600):  # 10 minutes
            profile.waf_detected = False
            profile.rate_limited = False

    async def get_delay_between_requests(self, hostname: str, tool_name: str) -> float:
        """Get optimal delay between requests for rate limiting"""

        rate, _ = await self.get_optimal_rate_and_concurrency(hostname, tool_name)

        # Convert requests per second to delay in seconds
        base_delay = 1.0 / rate

        # Add jitter to avoid thundering herd
        import random
        jitter = random.uniform(0.8, 1.2)

        return base_delay * jitter

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary for monitoring"""

        summary = {
            'total_targets': len(self.target_profiles),
            'global_rate_multiplier': self.global_rate_multiplier,
            'bandwidth_mbps': self.bandwidth_mbps,
            'total_requests': len(self.metrics_history),
            'targets': {}
        }

        for hostname, profile in self.target_profiles.items():
            summary['targets'][hostname] = {
                'current_rate': profile.current_rate,
                'current_concurrency': profile.current_concurrency,
                'success_rate': profile.success_rate,
                'avg_response_time': profile.avg_response_time,
                'waf_detected': profile.waf_detected,
                'total_requests': profile.total_requests
            }

        return summary

# Global adaptive rate controller instance
adaptive_rate_controller = AdaptiveRateController()