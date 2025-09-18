#!/usr/bin/env python3
"""
Process Watchdog - Safety System for ModScan
Prevents and fixes process hanging, resource leaks, and scanner stacking issues
"""

import subprocess
import psutil
import time
import sqlite3
import re
import logging
from datetime import datetime, timedelta
from collections import defaultdict

class ProcessWatchdog:
    def __init__(self, config_path='config.json'):
        """Initialize process monitoring and safety systems."""
        self.max_process_runtime = 600  # 10 minutes max per scanner
        self.max_processes_per_tool = 10  # Max concurrent processes per tool
        self.check_interval = 60  # Check every 60 seconds
        self.db_path = '/home/michael/recon-platform/modscan/lean_recon.db'
        
        # Dynamic thresholds based on system load
        self.load_aware_thresholds = {
            'high_cpu': {'max_runtime': 180, 'max_per_tool': 3},      # 3 minutes, 3 max
            'moderate_cpu': {'max_runtime': 360, 'max_per_tool': 6},  # 6 minutes, 6 max  
            'normal': {'max_runtime': 600, 'max_per_tool': 10}        # 10 minutes, 10 max
        }
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - WATCHDOG - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Scanner tools to monitor (universal list; not target-specific)
        self.scanner_tools = [
            'sqlmap', 'dalfox', 'nuclei', 'commix', 'ffuf',
            # Headless/browser automation that often leaks processes
            'chromium', 'chrome', 'google-chrome', 'playwright', 'msedge'
        ]
        
    def get_scanner_processes(self):
        """Get all scanner processes with details."""
        processes = {}
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time', 'status']):
            try:
                # Check if it's a scanner process
                for tool in self.scanner_tools:
                    cmdline = proc.info.get('cmdline', [])
                    if cmdline and hasattr(cmdline, '__iter__') and not isinstance(cmdline, str):
                        if tool in ' '.join(cmdline).lower():
                            processes[proc.info['pid']] = {
                                'tool': tool,
                                'cmdline': ' '.join(cmdline),
                            'runtime': time.time() - proc.info['create_time'],
                            'status': proc.info['status'],
                            'proc': proc
                        }
                        break
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return processes
        
    def _get_current_load_status(self):
        """Determine current system load status for dynamic thresholds."""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory_percent = psutil.virtual_memory().percent
            
            if cpu_percent > 75 or memory_percent > 80:
                return 'high_cpu'
            elif cpu_percent > 60 or memory_percent > 70:
                return 'moderate_cpu'
            else:
                return 'normal'
        except Exception:
            return 'normal'
    
    def detect_hung_processes(self, processes):
        """Detect processes that have been running too long (with dynamic thresholds)."""
        hung_processes = []
        
        # Use dynamic thresholds based on current system load
        load_status = self._get_current_load_status()
        max_runtime = self.load_aware_thresholds[load_status]['max_runtime']
        
        for pid, info in processes.items():
            # Consider hung if running longer than load-aware max time
            if info['runtime'] > max_runtime:
                hung_processes.append(pid)
                self.logger.warning(f"HUNG PROCESS ({load_status}): {info['tool']} PID {pid} - {info['runtime']:.0f}s runtime (limit: {max_runtime}s)")
                
        return hung_processes
        
    def detect_process_stacking(self, processes):
        """Detect too many processes of same tool running (with dynamic limits)."""
        tool_counts = defaultdict(list)
        
        for pid, info in processes.items():
            tool_counts[info['tool']].append(pid)
            
        # Use dynamic limits based on system load
        load_status = self._get_current_load_status()
        max_per_tool = self.load_aware_thresholds[load_status]['max_per_tool']
        
        stacked_processes = []
        for tool, pids in tool_counts.items():
            if len(pids) > max_per_tool:
                excess_pids = pids[max_per_tool:]
                stacked_processes.extend(excess_pids)
                self.logger.warning(f"PROCESS STACKING ({load_status}): {tool} has {len(pids)} processes (max {max_per_tool})")
                
        return stacked_processes
        
    def detect_corrupted_urls(self, processes):
        """Detect processes running on corrupted URLs."""
        corrupted_processes = []
        
        corruption_patterns = [
            r'M\d{4,}',  # Pattern like M11540, M115411
            r'[a-zA-Z]{10,}[A-Z]{2,}[a-zA-Z]{5,}',  # Patterns like rieilgakM115411
            r',\d+,\d+,\d+,active',  # Patterns like ,1,1813,0,active
            r'http://[^/]*http://',  # Double http://
        ]
        
        for pid, info in processes.items():
            cmdline = info['cmdline']
            for pattern in corruption_patterns:
                if re.search(pattern, cmdline):
                    corrupted_processes.append(pid)
                    self.logger.warning(f"CORRUPTED URL: {info['tool']} PID {pid} - {pattern}")
                    break
                    
        return corrupted_processes
        
    def kill_problematic_processes(self, process_pids):
        """Safely kill problematic processes."""
        killed_count = 0
        
        for pid in process_pids:
            try:
                proc = psutil.Process(pid)
                # Terminate full tree first
                children = proc.children(recursive=True)
                for c in children:
                    try:
                        c.terminate()
                    except Exception:
                        pass
                proc.terminate()  # Try graceful termination first
                
                # Wait 5 seconds for graceful termination
                try:
                    gone, alive = psutil.wait_procs([proc] + children, timeout=5)
                    # Force kill any survivors
                    for a in alive:
                        try:
                            a.kill()
                        except Exception:
                            pass
                except psutil.TimeoutExpired:
                    try:
                        proc.kill()  # Force kill if needed
                    except Exception:
                        pass
                
                killed_count += 1
                self.logger.info(f"KILLED problematic process PID {pid}")
                
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                self.logger.warning(f"Failed to kill PID {pid}: {e}")
                
        return killed_count
        
    def cleanup_database_corruption(self):
        """Remove corrupted URLs from database."""
        try:
            with sqlite3.connect(self.db_path, timeout=30.0) as db:
                # Count corrupted URLs before cleanup
                count_query = """
                SELECT COUNT(*) FROM assets 
                WHERE url LIKE '%M11%' 
                   OR url LIKE '%,1,%' 
                   OR LENGTH(url) > 500
                   OR url LIKE '%http://%http://%'
                """
                corrupted_count = db.execute(count_query).fetchone()[0]
                
                if corrupted_count > 0:
                    # Delete corrupted URLs
                    delete_query = """
                    DELETE FROM assets 
                    WHERE url LIKE '%M11%' 
                       OR url LIKE '%,1,%' 
                       OR LENGTH(url) > 500
                       OR url LIKE '%http://%http://%'
                    """
                    db.execute(delete_query)
                    db.commit()
                    
                    self.logger.info(f"DATABASE CLEANUP: Removed {corrupted_count} corrupted URLs")
                    return corrupted_count
                    
        except Exception as e:
            self.logger.error(f"Database cleanup failed: {e}")
            
        return 0
        
    def get_system_health_stats(self):
        """Get system resource usage statistics."""
        return {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': psutil.disk_usage('/').percent,
            'load_avg': psutil.getloadavg()[0] if hasattr(psutil, 'getloadavg') else 0,
            'scanner_processes': len(self.get_scanner_processes())
        }
        
    def run_health_check(self):
        """Run comprehensive health check and cleanup."""
        self.logger.info("🔍 Starting process health check...")
        
        # Get all scanner processes
        processes = self.get_scanner_processes()
        
        if not processes:
            self.logger.info("✅ No scanner processes running")
            return
            
        self.logger.info(f"📊 Found {len(processes)} scanner processes")
        
        # Detect various issues
        hung_processes = self.detect_hung_processes(processes)
        stacked_processes = self.detect_process_stacking(processes)
        corrupted_processes = self.detect_corrupted_urls(processes)
        
        # Combine all problematic processes
        problematic_pids = set(hung_processes + stacked_processes + corrupted_processes)
        
        if problematic_pids:
            self.logger.warning(f"🚨 Found {len(problematic_pids)} problematic processes")
            killed_count = self.kill_problematic_processes(problematic_pids)
            self.logger.info(f"💀 Killed {killed_count} problematic processes")
        else:
            self.logger.info("✅ All scanner processes look healthy")
            
        # Database cleanup
        cleaned_urls = self.cleanup_database_corruption()
        if cleaned_urls > 0:
            self.logger.info(f"🧹 Database cleanup: removed {cleaned_urls} corrupted URLs")
            
        # System health stats
        stats = self.get_system_health_stats()
        self.logger.info(f"💻 System Health - CPU: {stats['cpu_percent']:.1f}%, Memory: {stats['memory_percent']:.1f}%, Active Scanners: {stats['scanner_processes']}")
        
    def monitor_loop(self):
        """Continuous monitoring loop."""
        self.logger.info(f"🚀 Process Watchdog started - checking every {self.check_interval}s")
        
        while True:
            try:
                self.run_health_check()
                time.sleep(self.check_interval)
                
            except KeyboardInterrupt:
                self.logger.info("🛑 Process Watchdog stopped by user")
                break
            except Exception as e:
                self.logger.error(f"Health check failed: {e}")
                time.sleep(30)  # Wait longer on errors


def main():
    """Run process watchdog."""
    watchdog = ProcessWatchdog()
    
    # Run single health check
    if len(sys.argv) > 1 and sys.argv[1] == '--once':
        watchdog.run_health_check()
    else:
        # Continuous monitoring
        watchdog.monitor_loop()


if __name__ == '__main__':
    import sys
    main()
