#!/usr/bin/env python3
"""
Database Health Monitor - Safety System for ModScan Database
Detects and fixes corruption, validates data integrity, prevents resource leaks
"""

import sqlite3
import re
import time
import logging
from datetime import datetime, timedelta
from collections import defaultdict

class DatabaseHealthMonitor:
    def __init__(self, db_path='/home/michael/recon-platform/modscan/lean_recon.db'):
        """Initialize database health monitoring."""
        self.db_path = db_path
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - DB_HEALTH - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # URL corruption patterns to detect
        self.corruption_patterns = [
            (r'M\d{4,}', 'Random M-number sequences'),
            (r'[a-zA-Z]{10,}[A-Z]{2,}[a-zA-Z]{5,}', 'Garbled domain patterns'),
            (r',\d+,\d+,\d+,active', 'Comma-separated number sequences'),
            (r'http://[^/]*http://', 'Double HTTP protocol'),
            (r'[^.]\.[^/]*\.[^/]*http://', 'Domain followed by HTTP'),
            (r'%[0-9A-Fa-f]{2}%[0-9A-Fa-f]{2}%[0-9A-Fa-f]{2}%[0-9A-Fa-f]{2}%[0-9A-Fa-f]{2}', 'Excessive URL encoding'),
            (r'^[^h].*\.com.*http://', 'Malformed protocol mixing'),
        ]
        
    def get_db_connection(self, timeout=30.0):
        """Get database connection with timeout."""
        return sqlite3.connect(self.db_path, timeout=timeout, check_same_thread=False)
        
    def detect_corrupted_assets(self):
        """Find assets with corrupted URLs."""
        corrupted_assets = []
        
        try:
            with self.get_db_connection() as db:
                # Get all assets with URLs
                cursor = db.execute("SELECT id, url FROM assets WHERE url IS NOT NULL")
                assets = cursor.fetchall()
                
                for asset_id, url in assets:
                    if not url or not isinstance(url, str):
                        corrupted_assets.append((asset_id, url, "Invalid URL type"))
                        continue
                        
                    # Check for corruption patterns
                    for pattern, description in self.corruption_patterns:
                        if re.search(pattern, url):
                            corrupted_assets.append((asset_id, url, description))
                            break
                    else:
                        # Check for excessive length
                        if len(url) > 500:
                            corrupted_assets.append((asset_id, url, "URL too long"))
                        # Check for invalid schemes
                        elif not url.startswith(('http://', 'https://')):
                            corrupted_assets.append((asset_id, url, "Invalid URL scheme"))
                            
        except Exception as e:
            self.logger.error(f"Failed to detect corrupted assets: {e}")
            
        return corrupted_assets
        
    def detect_orphaned_vulnerabilities(self):
        """Find vulnerabilities linked to non-existent assets."""
        orphaned_vulns = []
        
        try:
            with self.get_db_connection() as db:
                # Find vulnerabilities with invalid asset_id references
                query = """
                SELECT v.id, v.asset_id, v.type, v.asset_url
                FROM vulnerabilities v
                LEFT JOIN assets a ON v.asset_id = a.id
                WHERE a.id IS NULL AND v.asset_id IS NOT NULL
                """
                cursor = db.execute(query)
                orphaned_vulns = cursor.fetchall()
                
        except Exception as e:
            self.logger.error(f"Failed to detect orphaned vulnerabilities: {e}")
            
        return orphaned_vulns
        
    def detect_duplicate_assets(self):
        """Find duplicate assets with same URL."""
        duplicates = []
        
        try:
            with self.get_db_connection() as db:
                query = """
                SELECT url, COUNT(*) as count, GROUP_CONCAT(id) as asset_ids
                FROM assets 
                WHERE url IS NOT NULL
                GROUP BY url
                HAVING count > 1
                ORDER BY count DESC
                """
                cursor = db.execute(query)
                duplicates = cursor.fetchall()
                
        except Exception as e:
            self.logger.error(f"Failed to detect duplicate assets: {e}")
            
        return duplicates
        
    def detect_stale_data(self, days_threshold=7):
        """Find assets that haven't been scanned in a while."""
        stale_assets = []
        cutoff_date = (datetime.now() - timedelta(days=days_threshold)).strftime('%Y-%m-%d %H:%M:%S')
        
        try:
            with self.get_db_connection() as db:
                query = """
                SELECT id, url, last_scanned, discovered_at
                FROM assets 
                WHERE (last_scanned IS NULL OR last_scanned < ?)
                AND discovered_at < ?
                ORDER BY discovered_at ASC
                """
                cursor = db.execute(query, (cutoff_date, cutoff_date))
                stale_assets = cursor.fetchall()
                
        except Exception as e:
            self.logger.error(f"Failed to detect stale data: {e}")
            
        return stale_assets
        
    def clean_corrupted_assets(self, corrupted_assets):
        """Remove corrupted assets from database."""
        cleaned_count = 0
        
        if not corrupted_assets:
            return cleaned_count
            
        try:
            with self.get_db_connection() as db:
                asset_ids = [asset_id for asset_id, _, _ in corrupted_assets]
                
                # Delete associated vulnerabilities first
                if asset_ids:
                    placeholders = ','.join(['?'] * len(asset_ids))
                    db.execute(f"DELETE FROM vulnerabilities WHERE asset_id IN ({placeholders})", asset_ids)
                    
                    # Delete corrupted assets
                    db.execute(f"DELETE FROM assets WHERE id IN ({placeholders})", asset_ids)
                    
                    cleaned_count = len(asset_ids)
                    db.commit()
                    
                    self.logger.info(f"🧹 Cleaned {cleaned_count} corrupted assets")
                    
        except Exception as e:
            self.logger.error(f"Failed to clean corrupted assets: {e}")
            
        return cleaned_count
        
    def clean_orphaned_vulnerabilities(self, orphaned_vulns):
        """Remove orphaned vulnerabilities."""
        cleaned_count = 0
        
        if not orphaned_vulns:
            return cleaned_count
            
        try:
            with self.get_db_connection() as db:
                vuln_ids = [vuln_id for vuln_id, _, _, _ in orphaned_vulns]
                
                if vuln_ids:
                    placeholders = ','.join(['?'] * len(vuln_ids))
                    db.execute(f"DELETE FROM vulnerabilities WHERE id IN ({placeholders})", vuln_ids)
                    cleaned_count = len(vuln_ids)
                    db.commit()
                    
                    self.logger.info(f"🧹 Cleaned {cleaned_count} orphaned vulnerabilities")
                    
        except Exception as e:
            self.logger.error(f"Failed to clean orphaned vulnerabilities: {e}")
            
        return cleaned_count
        
    def consolidate_duplicate_assets(self, duplicates):
        """Merge duplicate assets, keeping the most recent one."""
        consolidated_count = 0
        
        try:
            with self.get_db_connection() as db:
                for url, count, asset_ids_str in duplicates:
                    asset_ids = [int(id) for id in asset_ids_str.split(',')]
                    if len(asset_ids) <= 1:
                        continue
                        
                    # Keep the asset with highest ID (most recent)
                    keep_id = max(asset_ids)
                    remove_ids = [id for id in asset_ids if id != keep_id]
                    
                    # Update vulnerabilities to point to kept asset
                    for remove_id in remove_ids:
                        db.execute(
                            "UPDATE vulnerabilities SET asset_id = ? WHERE asset_id = ?",
                            (keep_id, remove_id)
                        )
                    
                    # Delete duplicate assets
                    placeholders = ','.join(['?'] * len(remove_ids))
                    db.execute(f"DELETE FROM assets WHERE id IN ({placeholders})", remove_ids)
                    
                    consolidated_count += len(remove_ids)
                    
                db.commit()
                self.logger.info(f"🔄 Consolidated {consolidated_count} duplicate assets")
                
        except Exception as e:
            self.logger.error(f"Failed to consolidate duplicates: {e}")
            
        return consolidated_count
        
    def get_database_stats(self):
        """Get comprehensive database statistics."""
        stats = {}
        
        try:
            with self.get_db_connection() as db:
                # Basic counts
                stats['total_assets'] = db.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
                stats['total_vulnerabilities'] = db.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
                stats['scanned_assets'] = db.execute("SELECT COUNT(*) FROM assets WHERE last_scanned IS NOT NULL").fetchone()[0]
                
                # Recent activity (last 24h)
                yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')
                stats['recent_assets'] = db.execute(
                    "SELECT COUNT(*) FROM assets WHERE discovered_at > ?", (yesterday,)
                ).fetchone()[0]
                stats['recent_vulnerabilities'] = db.execute(
                    "SELECT COUNT(*) FROM vulnerabilities WHERE detected_at > ?", (yesterday,)
                ).fetchone()[0]
                
                # Asset status distribution
                stats['unscanned_assets'] = stats['total_assets'] - stats['scanned_assets']
                
                # Vulnerability severity breakdown
                severity_query = """
                SELECT severity, COUNT(*) as count 
                FROM vulnerabilities 
                GROUP BY severity 
                ORDER BY count DESC
                """
                severity_breakdown = db.execute(severity_query).fetchall()
                stats['vulnerability_severity'] = dict(severity_breakdown)
                
        except Exception as e:
            self.logger.error(f"Failed to get database stats: {e}")
            
        return stats
        
    def run_comprehensive_health_check(self):
        """Run full database health check and cleanup."""
        self.logger.info("🔍 Starting comprehensive database health check...")
        
        # Get initial stats
        initial_stats = self.get_database_stats()
        self.logger.info(f"📊 Database Stats - Assets: {initial_stats.get('total_assets', 0)}, Vulnerabilities: {initial_stats.get('total_vulnerabilities', 0)}")
        
        # Detect issues
        corrupted_assets = self.detect_corrupted_assets()
        orphaned_vulns = self.detect_orphaned_vulnerabilities()
        duplicates = self.detect_duplicate_assets()
        stale_assets = self.detect_stale_data()
        
        # Report findings
        if corrupted_assets:
            self.logger.warning(f"🚨 Found {len(corrupted_assets)} corrupted assets")
            for asset_id, url, reason in corrupted_assets[:5]:  # Show first 5
                self.logger.warning(f"  - Asset {asset_id}: {reason} - {url[:100]}...")
                
        if orphaned_vulns:
            self.logger.warning(f"🚨 Found {len(orphaned_vulns)} orphaned vulnerabilities")
            
        if duplicates:
            self.logger.warning(f"🚨 Found {len(duplicates)} sets of duplicate assets")
            
        if stale_assets:
            self.logger.info(f"📅 Found {len(stale_assets)} stale assets (>7 days old)")
            
        # Clean up issues
        cleaned_assets = self.clean_corrupted_assets(corrupted_assets)
        cleaned_vulns = self.clean_orphaned_vulnerabilities(orphaned_vulns)
        consolidated_assets = self.consolidate_duplicate_assets(duplicates)
        
        # Final stats
        final_stats = self.get_database_stats()
        self.logger.info(f"✅ Cleanup Complete - Assets: {final_stats.get('total_assets', 0)} ({cleaned_assets} cleaned), Vulnerabilities: {final_stats.get('total_vulnerabilities', 0)} ({cleaned_vulns} cleaned)")
        
        return {
            'corrupted_assets_cleaned': cleaned_assets,
            'orphaned_vulns_cleaned': cleaned_vulns,
            'duplicate_assets_consolidated': consolidated_assets,
            'initial_stats': initial_stats,
            'final_stats': final_stats
        }


def main():
    """Run database health check."""
    monitor = DatabaseHealthMonitor()
    results = monitor.run_comprehensive_health_check()
    
    print("\n=== DATABASE HEALTH REPORT ===")
    print(f"Corrupted assets cleaned: {results['corrupted_assets_cleaned']}")
    print(f"Orphaned vulnerabilities cleaned: {results['orphaned_vulns_cleaned']}")
    print(f"Duplicate assets consolidated: {results['duplicate_assets_consolidated']}")
    

if __name__ == '__main__':
    main()