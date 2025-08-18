#!/usr/bin/env python3
"""
Adaptive Scanning Monitor - Auto-trigger deeper scans when discovery plateaus
"""

import time
import psutil
import sqlite3
import json
from datetime import datetime, timedelta
from asset_manager import AssetManager
import subprocess
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AdaptiveScanMonitor")

class AdaptiveScanningMonitor:
    def __init__(self):
        self.asset_manager = AssetManager()
        self.last_asset_count = 0
        self.last_vuln_count = 0
        self.discovery_stall_threshold = 300  # 5 minutes without new discoveries
        self.cpu_threshold = 20  # Below 20% CPU indicates idle
        self.monitoring_interval = 60  # Check every minute
        self.last_discovery_time = datetime.now()
        self.deeper_scan_triggered = False
        
    def get_current_stats(self):
        """Get current asset and vulnerability counts"""
        try:
            with self.asset_manager._get_db() as db:
                asset_count = db.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
                vuln_count = db.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
                
                # Get recent discoveries (last 10 minutes)
                recent_threshold = datetime.now() - timedelta(minutes=10)
                recent_threshold_str = recent_threshold.isoformat()
                
                recent_assets = db.execute(
                    "SELECT COUNT(*) FROM assets WHERE discovered_at > ?", 
                    (recent_threshold_str,)
                ).fetchone()[0]
                
                recent_vulns = db.execute(
                    "SELECT COUNT(*) FROM vulnerabilities WHERE detected_at > ?", 
                    (recent_threshold_str,)
                ).fetchone()[0]
                
                return {
                    'assets': asset_count,
                    'vulnerabilities': vuln_count,
                    'recent_assets': recent_assets,
                    'recent_vulns': recent_vulns
                }
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return None
    
    def get_system_performance(self):
        """Get current system performance metrics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            
            # Check for running scanner processes
            scanner_processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = ' '.join(proc.info['cmdline'] or [])
                    if any(keyword in cmdline.lower() for keyword in 
                           ['engine.py', 'discovery', 'scanner', 'recon']):
                        scanner_processes.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'cpu': proc.cpu_percent(),
                            'memory': proc.memory_percent()
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'scanner_processes': scanner_processes
            }
        except Exception as e:
            logger.error(f"Error getting performance: {e}")
            return None
    
    def check_discovery_plateau(self, current_stats):
        """Check if discovery has plateaued"""
        if not current_stats:
            return False
            
        new_assets = current_stats['assets'] - self.last_asset_count
        new_vulns = current_stats['vulnerabilities'] - self.last_vuln_count
        
        # Update counters
        if new_assets > 0 or new_vulns > 0:
            self.last_discovery_time = datetime.now()
            self.last_asset_count = current_stats['assets']
            self.last_vuln_count = current_stats['vulnerabilities']
            return False
        
        # Check if we've been stalled for too long
        time_since_discovery = datetime.now() - self.last_discovery_time
        return time_since_discovery.total_seconds() > self.discovery_stall_threshold
    
    def trigger_deeper_asset_discovery(self):
        """Trigger deeper asset discovery scan"""
        logger.info("🚀 TRIGGERING DEEPER ASSET DISCOVERY")
        
        try:
            # Create a deeper discovery configuration
            deep_config = {
                "discovery_depth": "aggressive",
                "wordlist_size": "large", 
                "subdomain_bruteforce": True,
                "port_scan_extended": True,
                "historical_analysis": True,
                "certificate_transparency_deep": True
            }
            
            # Write config for engine to pick up
            with open('deep_discovery_trigger.json', 'w') as f:
                json.dump({
                    "trigger_time": datetime.now().isoformat(),
                    "reason": "discovery_plateau_detected",
                    "config": deep_config
                }, f)
            
            logger.info("✅ Deep discovery trigger file created")
            return True
            
        except Exception as e:
            logger.error(f"Error triggering deep discovery: {e}")
            return False
    
    def trigger_deeper_vulnerability_scan(self):
        """Trigger deeper vulnerability scanning"""
        logger.info("🎯 TRIGGERING DEEPER VULNERABILITY SCAN")
        
        try:
            # Get assets that haven't been deeply scanned
            with self.asset_manager._get_db() as db:
                unscanned_assets = db.execute("""
                    SELECT url FROM assets 
                    WHERE deep_scan_complete IS NULL OR deep_scan_complete = 0
                    ORDER BY discovered_at DESC
                    LIMIT 50
                """).fetchall()
            
            if unscanned_assets:
                # Create deep scan trigger
                deep_scan_config = {
                    "scan_depth": "aggressive",
                    "vulnerability_types": ["XSS", "SQLi", "LFI", "RFI", "XXE", "SSTI"],
                    "payload_sets": "comprehensive",
                    "fuzzing_enabled": True,
                    "manual_verification": True
                }
                
                with open('deep_vuln_trigger.json', 'w') as f:
                    json.dump({
                        "trigger_time": datetime.now().isoformat(),
                        "reason": "vulnerability_discovery_plateau",
                        "target_count": len(unscanned_assets),
                        "config": deep_scan_config
                    }, f)
                
                logger.info(f"✅ Deep vulnerability scan triggered for {len(unscanned_assets)} assets")
                return True
            else:
                logger.info("ℹ️  All assets already deeply scanned")
                return False
                
        except Exception as e:
            logger.error(f"Error triggering deep vulnerability scan: {e}")
            return False
    
    def adaptive_scan_decision(self, stats, performance):
        """Make intelligent decision about what type of deeper scan to trigger"""
        
        # If we have very few assets, focus on asset discovery
        if stats['assets'] < 100:
            logger.info("🔍 Low asset count - prioritizing asset discovery")
            return self.trigger_deeper_asset_discovery()
        
        # If asset/vuln ratio is low, focus on vulnerability scanning
        elif stats['assets'] > 0:
            vuln_ratio = stats['vulnerabilities'] / stats['assets']
            if vuln_ratio < 0.5:  # Less than 0.5 vulns per asset
                logger.info(f"🎯 Low vulnerability ratio ({vuln_ratio:.2f}) - prioritizing vulnerability scanning")
                return self.trigger_deeper_vulnerability_scan()
        
        # Otherwise, balance both
        logger.info("⚖️  Balanced approach - triggering both discovery and scanning")
        asset_result = self.trigger_deeper_asset_discovery()
        vuln_result = self.trigger_deeper_vulnerability_scan()
        return asset_result or vuln_result
    
    def monitor_loop(self):
        """Main monitoring loop"""
        logger.info("🤖 Starting Adaptive Scanning Monitor")
        logger.info(f"📊 Discovery stall threshold: {self.discovery_stall_threshold}s")
        logger.info(f"🔄 CPU idle threshold: {self.cpu_threshold}%")
        
        while True:
            try:
                # Get current statistics
                stats = self.get_current_stats()
                performance = self.get_system_performance()
                
                if stats and performance:
                    logger.info(f"📊 Assets: {stats['assets']} (+{stats['recent_assets']} recent) | "
                              f"Vulns: {stats['vulnerabilities']} (+{stats['recent_vulns']} recent) | "
                              f"CPU: {performance['cpu_percent']:.1f}% | "
                              f"Processes: {len(performance['scanner_processes'])}")
                    
                    # Check if discovery has plateaued
                    discovery_stalled = self.check_discovery_plateau(stats)
                    system_idle = performance['cpu_percent'] < self.cpu_threshold
                    
                    if discovery_stalled and system_idle and not self.deeper_scan_triggered:
                        logger.warning("🚨 DISCOVERY PLATEAU DETECTED")
                        logger.info(f"⏰ No new discoveries for {(datetime.now() - self.last_discovery_time).total_seconds():.0f}s")
                        logger.info(f"💤 System CPU below {self.cpu_threshold}% - triggering deeper scans")
                        
                        success = self.adaptive_scan_decision(stats, performance)
                        if success:
                            self.deeper_scan_triggered = True
                            logger.info("✅ Deeper scanning triggered successfully")
                        else:
                            logger.error("❌ Failed to trigger deeper scanning")
                    
                    elif not discovery_stalled:
                        # Reset trigger if discovery resumed
                        if self.deeper_scan_triggered:
                            logger.info("🔄 Discovery resumed - resetting trigger")
                            self.deeper_scan_triggered = False
                
                # Wait before next check
                time.sleep(self.monitoring_interval)
                
            except KeyboardInterrupt:
                logger.info("🛑 Monitoring stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(self.monitoring_interval)

if __name__ == "__main__":
    monitor = AdaptiveScanningMonitor()
    monitor.monitor_loop()