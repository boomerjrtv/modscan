#!/usr/bin/env python3
"""
Universal Scan Deduplication System

Prevents redundant vulnerability scans by tracking exact scanning methods per URL.
Creates unique scan fingerprints based on URL + scan type + parameters to ensure
we don't repeat the same vulnerability scan multiple times.

Universal design - works with any web application without target-specific logic.
"""
import hashlib
import json
import time
import sqlite3
from typing import Dict, List, Optional, Set
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class ScanDeduplicationManager:
    """Universal scan deduplication system for preventing redundant vulnerability scans"""
    
    def __init__(self, database_path: str):
        self.database_path = database_path
        self._initialize_scan_tracking_tables()
    
    def _initialize_scan_tracking_tables(self):
        """Initialize scan tracking tables for deduplication"""
        try:
            with self._get_db() as db:
                # Scan fingerprints table - tracks exactly what scans have been performed
                db.execute("""
                    CREATE TABLE IF NOT EXISTS scan_fingerprints (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        fingerprint TEXT UNIQUE NOT NULL,
                        url TEXT NOT NULL,
                        scan_type TEXT NOT NULL,
                        scan_method TEXT NOT NULL,
                        scan_parameters TEXT,
                        created_at TEXT NOT NULL,
                        last_scan_at TEXT NOT NULL,
                        scan_count INTEGER DEFAULT 1,
                        ttl_hours INTEGER DEFAULT 24,
                        findings_count INTEGER DEFAULT 0
                    )
                """)
                # Create indices separately (SQLite does not support inline INDEX declarations)
                db.execute("CREATE INDEX IF NOT EXISTS idx_scan_fpr_fingerprint ON scan_fingerprints(fingerprint)")
                db.execute("CREATE INDEX IF NOT EXISTS idx_scan_fpr_url ON scan_fingerprints(url)")
                db.execute("CREATE INDEX IF NOT EXISTS idx_scan_fpr_type ON scan_fingerprints(scan_type)")
                db.execute("CREATE INDEX IF NOT EXISTS idx_scan_fpr_last ON scan_fingerprints(last_scan_at)")
                
                # Scan sessions table - tracks scan batches/sessions
                db.execute("""
                    CREATE TABLE IF NOT EXISTS scan_sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT UNIQUE NOT NULL,
                        created_at TEXT NOT NULL,
                        scan_profile TEXT,
                        total_urls INTEGER DEFAULT 0,
                        completed_urls INTEGER DEFAULT 0,
                        findings_count INTEGER DEFAULT 0,
                        status TEXT DEFAULT 'active'
                    )
                """)
                
                db.commit()
                logger.debug("✅ Scan deduplication tables initialized")
        except Exception as e:
            logger.error(f"Failed to initialize scan tracking tables: {e}")
    
    def _get_db(self):
        """Get database connection with proper settings"""
        conn = sqlite3.connect(self.database_path, timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        return conn
    
    def create_scan_fingerprint(self, url: str, scan_type: str, scan_method: str, 
                               scan_parameters: Optional[Dict] = None) -> str:
        """
        Create unique fingerprint for a specific scan configuration
        
        Args:
            url: Target URL
            scan_type: Type of scan (e.g., 'vulnerability', 'xss', 'sqli', 'idor')
            scan_method: Specific method (e.g., '_detect_xss_vulnerabilities', '_detect_sqli')
            scan_parameters: Additional scan parameters (payloads, config, etc.)
        
        Returns:
            Unique fingerprint string for this exact scan configuration
        """
        # Normalize URL for consistent fingerprinting
        normalized_url = self._normalize_url_for_fingerprint(url)
        
        # Create fingerprint components
        fingerprint_data = {
            'url': normalized_url,
            'scan_type': scan_type.lower(),
            'scan_method': scan_method,
            'parameters': scan_parameters or {}
        }
        
        # Sort parameters for consistent hashing
        fingerprint_json = json.dumps(fingerprint_data, sort_keys=True, separators=(',', ':'))
        
        # Create SHA-256 fingerprint
        fingerprint = hashlib.sha256(fingerprint_json.encode('utf-8')).hexdigest()[:32]
        
        return f"{scan_type}_{fingerprint}"
    
    def should_perform_scan(self, url: str, scan_type: str, scan_method: str,
                           scan_parameters: Optional[Dict] = None, ttl_hours: int = 24) -> bool:
        """
        Check if this specific scan should be performed based on deduplication rules
        
        Args:
            url: Target URL
            scan_type: Type of scan
            scan_method: Specific scanning method
            scan_parameters: Scan configuration parameters
            ttl_hours: Time-to-live in hours before scan can be repeated
            
        Returns:
            True if scan should be performed, False if it's a duplicate within TTL
        """
        fingerprint = self.create_scan_fingerprint(url, scan_type, scan_method, scan_parameters)
        
        try:
            with self._get_db() as db:
                # Check if we've performed this exact scan recently
                cutoff_time = (datetime.now() - timedelta(hours=ttl_hours)).isoformat()
                
                result = db.execute("""
                    SELECT fingerprint, last_scan_at, scan_count, findings_count
                    FROM scan_fingerprints 
                    WHERE fingerprint = ? AND last_scan_at > ?
                """, (fingerprint, cutoff_time)).fetchone()
                
                if result:
                    logger.debug(f"⏭️ SKIP: {scan_type} scan on {url} - performed {result['scan_count']} time(s), "
                               f"last at {result['last_scan_at']}, found {result['findings_count']} issues")
                    return False
                    
                logger.debug(f"✅ ALLOW: {scan_type} scan on {url} - not performed recently")
                return True
                
        except Exception as e:
            logger.error(f"Failed to check scan deduplication: {e}")
            # Allow scan on error (fail open)
            return True
    
    def record_scan_performed(self, url: str, scan_type: str, scan_method: str,
                             scan_parameters: Optional[Dict] = None, findings_count: int = 0,
                             ttl_hours: int = 24) -> str:
        """
        Record that a specific scan has been performed
        
        Args:
            url: Target URL
            scan_type: Type of scan performed
            scan_method: Specific scanning method used
            scan_parameters: Scan configuration parameters
            findings_count: Number of findings discovered
            ttl_hours: TTL for this scan type
            
        Returns:
            Fingerprint of the recorded scan
        """
        fingerprint = self.create_scan_fingerprint(url, scan_type, scan_method, scan_parameters)
        current_time = datetime.now().isoformat()
        
        try:
            with self._get_db() as db:
                # Check if fingerprint already exists
                existing = db.execute("""
                    SELECT id, scan_count FROM scan_fingerprints WHERE fingerprint = ?
                """, (fingerprint,)).fetchone()
                
                if existing:
                    # Update existing record
                    db.execute("""
                        UPDATE scan_fingerprints 
                        SET last_scan_at = ?, scan_count = scan_count + 1, 
                            findings_count = ?, ttl_hours = ?
                        WHERE fingerprint = ?
                    """, (current_time, findings_count, ttl_hours, fingerprint))
                    logger.debug(f"📊 Updated scan record: {scan_type} on {url} (scan #{existing['scan_count'] + 1})")
                else:
                    # Insert new record
                    db.execute("""
                        INSERT INTO scan_fingerprints 
                        (fingerprint, url, scan_type, scan_method, scan_parameters, 
                         created_at, last_scan_at, ttl_hours, findings_count)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (fingerprint, url, scan_type, scan_method, 
                         json.dumps(scan_parameters or {}), current_time, current_time, 
                         ttl_hours, findings_count))
                    logger.debug(f"📝 Recorded new scan: {scan_type} on {url} ({findings_count} findings)")
                
                db.commit()
                
        except Exception as e:
            logger.error(f"Failed to record scan: {e}")
        
        return fingerprint
    
    def get_scan_history(self, url: str, scan_type: Optional[str] = None, days: int = 7) -> List[Dict]:
        """Get scan history for a URL"""
        try:
            with self._get_db() as db:
                cutoff_time = (datetime.now() - timedelta(days=days)).isoformat()
                
                query = """
                    SELECT fingerprint, url, scan_type, scan_method, scan_parameters,
                           created_at, last_scan_at, scan_count, findings_count
                    FROM scan_fingerprints 
                    WHERE url = ? AND last_scan_at > ?
                """
                params = [url, cutoff_time]
                
                if scan_type:
                    query += " AND scan_type = ?"
                    params.append(scan_type)
                
                query += " ORDER BY last_scan_at DESC"
                
                results = db.execute(query, params).fetchall()
                
                return [dict(row) for row in results]
                
        except Exception as e:
            logger.error(f"Failed to get scan history: {e}")
            return []
    
    def cleanup_old_scans(self, days_old: int = 30) -> int:
        """Clean up scan records older than specified days"""
        try:
            with self._get_db() as db:
                cutoff_time = (datetime.now() - timedelta(days=days_old)).isoformat()
                
                result = db.execute("""
                    DELETE FROM scan_fingerprints WHERE last_scan_at < ?
                """, (cutoff_time,))
                
                deleted_count = result.rowcount
                db.commit()
                
                logger.info(f"🧹 Cleaned up {deleted_count} old scan records (older than {days_old} days)")
                return deleted_count
                
        except Exception as e:
            logger.error(f"Failed to cleanup old scans: {e}")
            return 0
    
    def get_scan_stats(self) -> Dict:
        """Get statistics about scan deduplication"""
        try:
            with self._get_db() as db:
                stats = {}
                
                # Total scans tracked
                result = db.execute("SELECT COUNT(*) as total FROM scan_fingerprints").fetchone()
                stats['total_scan_fingerprints'] = result['total'] if result else 0
                
                # Scans by type
                results = db.execute("""
                    SELECT scan_type, COUNT(*) as count, SUM(findings_count) as total_findings
                    FROM scan_fingerprints 
                    GROUP BY scan_type
                    ORDER BY count DESC
                """).fetchall()
                stats['scans_by_type'] = [dict(row) for row in results]
                
                # Recent activity (last 24 hours)
                cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
                result = db.execute("""
                    SELECT COUNT(*) as recent_scans 
                    FROM scan_fingerprints 
                    WHERE last_scan_at > ?
                """, (cutoff,)).fetchone()
                stats['recent_scans_24h'] = result['recent_scans'] if result else 0
                
                return stats
                
        except Exception as e:
            logger.error(f"Failed to get scan stats: {e}")
            return {}
    
    def _normalize_url_for_fingerprint(self, url: str) -> str:
        """Normalize URL for consistent fingerprinting"""
        try:
            from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
            
            parsed = urlparse(url.strip())
            
            # Normalize scheme and host
            scheme = parsed.scheme.lower() or 'http'
            host = parsed.hostname.lower() if parsed.hostname else parsed.netloc.lower()
            port = parsed.port
            
            # Handle default ports
            netloc = host
            if port and not ((scheme == 'http' and port == 80) or (scheme == 'https' and port == 443)):
                netloc = f"{host}:{port}"
            
            # Keep path and query parameters for scan specificity
            path = parsed.path or '/'
            
            # Sort query parameters for consistency
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            sorted_query = urlencode(sorted(query_params.items()), doseq=True)
            
            normalized = urlunparse((scheme, netloc, path, parsed.params, sorted_query, ''))
            
            return normalized
            
        except Exception as e:
            logger.debug(f"URL normalization failed for {url}: {e}")
            return str(url)
