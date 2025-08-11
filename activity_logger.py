#!/usr/bin/env python3
"""
Activity logging system for tracking scanning events in real-time
"""
import sqlite3
import json
import time
from datetime import datetime
from pathlib import Path

# Configuration
BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / 'config.json'
with open(CONFIG_PATH, 'r') as f:
    CONFIG = json.load(f)

DB_PATH = CONFIG['database_path']

class ActivityLogger:
    def __init__(self):
        self.db_path = DB_PATH
        self.init_activities_table()

    def _get_db(self):
        conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        return conn

    def init_activities_table(self):
        """Initialize the activities table if it doesn't exist"""
        try:
            with self._get_db() as db:
                db.execute("""
                    CREATE TABLE IF NOT EXISTS activities (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        action TEXT NOT NULL,
                        target TEXT,
                        message TEXT,
                        details TEXT,
                        status TEXT DEFAULT 'info',
                        created_at TEXT NOT NULL
                    )
                """)
                # Create index for faster queries
                db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_activities_timestamp 
                    ON activities(timestamp DESC)
                """)
        except Exception as e:
            print(f"Error initializing activities table: {e}")

    def log_activity(self, action, target=None, message=None, details=None, status='info'):
        """Log a new activity event"""
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with self._get_db() as db:
                db.execute("""
                    INSERT INTO activities (timestamp, action, target, message, details, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (timestamp, action, target, message, details, status, timestamp))
        except Exception as e:
            print(f"Error logging activity: {e}")

    def get_recent_activities(self, limit=20):
        """Get recent activities for the feed"""
        try:
            with self._get_db() as db:
                cursor = db.execute("""
                    SELECT timestamp, action, target, message, details, status
                    FROM activities 
                    ORDER BY timestamp DESC, id DESC
                    LIMIT ?
                """, (limit,))
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"Error getting activities: {e}")
            return []

    def cleanup_old_activities(self, days_to_keep=7):
        """Clean up activities older than specified days"""
        try:
            cutoff_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with self._get_db() as db:
                db.execute("""
                    DELETE FROM activities 
                    WHERE timestamp < datetime('now', '-{} days')
                """.format(days_to_keep))
        except Exception as e:
            print(f"Error cleaning up activities: {e}")

    # Specific logging methods for common events
    def log_asset_discovered(self, url, method):
        """Log when a new asset is discovered"""
        self.log_activity(
            action='DISCOVERY',
            target=url,
            message=f'New asset discovered via {method}',
            status='success'
        )

    def log_asset_scanned(self, url, status_code, response_time=None):
        """Log when an asset is scanned"""
        message = f'HTTP scan completed - Status: {status_code}'
        if response_time:
            message += f' ({response_time:.2f}ms)'
        
        self.log_activity(
            action='SCAN',
            target=url,
            message=message,
            status='success' if status_code == 200 else 'warning'
        )

    def log_screenshot_captured(self, url):
        """Log when a screenshot is captured"""
        self.log_activity(
            action='SCREENSHOT',
            target=url,
            message='Screenshot captured successfully',
            status='success'
        )

    def log_vulnerability_found(self, url, vuln_type, severity='medium'):
        """Log when a vulnerability is discovered"""
        self.log_activity(
            action='VULNERABILITY',
            target=url,
            message=f'{vuln_type} vulnerability detected',
            details=f'Severity: {severity}',
            status='critical' if severity == 'high' else 'warning'
        )

    def log_scanner_started(self, scanner_type):
        """Log when a scanner starts"""
        self.log_activity(
            action='SCANNER_START',
            message=f'{scanner_type} scanner started',
            status='info'
        )

    def log_scanner_completed(self, scanner_type, assets_found=None):
        """Log when a scanner completes"""
        message = f'{scanner_type} scanner completed'
        if assets_found:
            message += f' - {assets_found} assets found'
            
        self.log_activity(
            action='SCANNER_COMPLETE',
            message=message,
            status='success'
        )

    def log_error(self, action, target=None, error_message=None):
        """Log an error event"""
        self.log_activity(
            action=action,
            target=target,
            message=error_message or 'An error occurred',
            status='error'
        )

# Global instance
activity_logger = ActivityLogger()