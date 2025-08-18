#!/usr/bin/env python3
"""
Smart TTL Manager - Per-Method Execution Tracking
Fixes the issue where entire domains are skipped due to global TTL
"""

import sqlite3
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from dataclasses import dataclass

logger = logging.getLogger("SmartTTLManager")

@dataclass
class MethodExecution:
    """Track individual method execution on assets"""
    asset_url: str
    method_name: str
    tool_name: str
    executed_at: datetime
    success: bool
    findings_count: int
    next_execution: datetime

class SmartTTLManager:
    def __init__(self, db_path: str = 'lean_recon.db'):
        self.db_path = db_path
        self._initialize_tracking_tables()
        
        # Method-specific TTL configurations
        self.method_ttl_config = {
            # Reconnaissance methods
            'subdomain_enumeration': {'ttl_hours': 24, 'retry_on_failure': 6},
            'dns_enumeration': {'ttl_hours': 12, 'retry_on_failure': 4},
            'url_discovery': {'ttl_hours': 8, 'retry_on_failure': 2},
            'parameter_discovery': {'ttl_hours': 6, 'retry_on_failure': 3},
            'technology_detection': {'ttl_hours': 12, 'retry_on_failure': 4},
            'content_discovery': {'ttl_hours': 4, 'retry_on_failure': 2},
            
            # Vulnerability methods  
            'injection_testing': {'ttl_hours': 2, 'retry_on_failure': 1},
            'authorization_testing': {'ttl_hours': 2, 'retry_on_failure': 1},
            'transport_security': {'ttl_hours': 24, 'retry_on_failure': 12},
            'web_services': {'ttl_hours': 4, 'retry_on_failure': 2},
            'cms_testing': {'ttl_hours': 8, 'retry_on_failure': 4},
            'comprehensive_scanning': {'ttl_hours': 6, 'retry_on_failure': 3},
            
            # Tool-specific overrides
            'nuclei': {'ttl_hours': 4, 'retry_on_failure': 2},
            'sqlmap': {'ttl_hours': 1, 'retry_on_failure': 0.5},
            'xsstrike': {'ttl_hours': 1, 'retry_on_failure': 0.5},
            'feroxbuster': {'ttl_hours': 2, 'retry_on_failure': 1},
            'subfinder': {'ttl_hours': 24, 'retry_on_failure': 6}
        }
        
        logger.info(f"🕰️ Smart TTL Manager initialized with {len(self.method_ttl_config)} method configurations")

    def _initialize_tracking_tables(self):
        """Initialize method execution tracking tables"""
        try:
            with sqlite3.connect(self.db_path) as db:
                # Method execution tracking
                db.execute('''
                    CREATE TABLE IF NOT EXISTS method_executions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        asset_url TEXT NOT NULL,
                        asset_id INTEGER,
                        method_name TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        completed_at TIMESTAMP,
                        success BOOLEAN DEFAULT 0,
                        findings_count INTEGER DEFAULT 0,
                        execution_time_seconds REAL DEFAULT 0,
                        error_message TEXT,
                        next_execution TIMESTAMP,
                        metadata TEXT DEFAULT '{}',
                        FOREIGN KEY (asset_id) REFERENCES assets(id)
                    )
                ''')
                
                # Create index for fast lookups
                db.execute('''
                    CREATE INDEX IF NOT EXISTS idx_method_executions_lookup 
                    ON method_executions(asset_url, method_name, executed_at)
                ''')
                
                # Method success/failure statistics
                db.execute('''
                    CREATE TABLE IF NOT EXISTS method_stats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        method_name TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        total_executions INTEGER DEFAULT 0,
                        successful_executions INTEGER DEFAULT 0,
                        total_findings INTEGER DEFAULT 0,
                        avg_execution_time REAL DEFAULT 0,
                        last_success TIMESTAMP,
                        success_rate REAL DEFAULT 0,
                        UNIQUE(method_name, tool_name)
                    )
                ''')
                
                logger.info("✅ Method execution tracking tables initialized")
                
        except Exception as e:
            logger.error(f"Failed to initialize tracking tables: {e}")

    def should_execute_method(self, asset_url: str, method_name: str, tool_name: str = None) -> bool:
        """Determine if a method should be executed on an asset"""
        try:
            tool_name = tool_name or method_name
            
            with sqlite3.connect(self.db_path) as db:
                # Check last execution
                query = '''
                    SELECT executed_at, success, next_execution
                    FROM method_executions 
                    WHERE asset_url = ? AND method_name = ? AND tool_name = ?
                    ORDER BY executed_at DESC LIMIT 1
                '''
                
                cursor = db.execute(query, (asset_url, method_name, tool_name))
                result = cursor.fetchone()
                
                if not result:
                    # Never executed - should run
                    logger.debug(f"✅ SHOULD EXECUTE: {method_name} never run on {asset_url}")
                    return True
                
                last_executed, success, next_execution = result
                last_executed = datetime.fromisoformat(last_executed)
                
                # Check if next execution time has passed
                if next_execution:
                    next_exec_time = datetime.fromisoformat(next_execution)
                    if datetime.now() >= next_exec_time:
                        logger.debug(f"✅ SHOULD EXECUTE: {method_name} TTL expired for {asset_url}")
                        return True
                
                # Check method-specific TTL
                config = self.method_ttl_config.get(method_name, {'ttl_hours': 6, 'retry_on_failure': 2})
                ttl_hours = config['retry_on_failure'] if not success else config['ttl_hours']
                
                time_since_execution = datetime.now() - last_executed
                if time_since_execution >= timedelta(hours=ttl_hours):
                    logger.debug(f"✅ SHOULD EXECUTE: {method_name} TTL expired ({ttl_hours}h) for {asset_url}")
                    return True
                
                logger.debug(f"⏭️ SKIP: {method_name} executed {time_since_execution} ago (TTL: {ttl_hours}h) on {asset_url}")
                return False
                
        except Exception as e:
            logger.error(f"TTL check failed for {method_name} on {asset_url}: {e}")
            return True  # Default to execute on error

    def record_method_execution(self, asset_url: str, method_name: str, tool_name: str = None, 
                              asset_id: int = None, success: bool = False, findings_count: int = 0,
                              execution_time: float = 0, error_message: str = None, 
                              metadata: Dict = None) -> int:
        """Record method execution"""
        try:
            tool_name = tool_name or method_name
            metadata = metadata or {}
            
            # Calculate next execution time
            config = self.method_ttl_config.get(method_name, {'ttl_hours': 6, 'retry_on_failure': 2})
            ttl_hours = config['retry_on_failure'] if not success else config['ttl_hours']
            next_execution = datetime.now() + timedelta(hours=ttl_hours)
            
            with sqlite3.connect(self.db_path) as db:
                # Record execution
                query = '''
                    INSERT INTO method_executions 
                    (asset_url, asset_id, method_name, tool_name, completed_at, success, 
                     findings_count, execution_time_seconds, error_message, next_execution, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                '''
                
                cursor = db.execute(query, (
                    asset_url, asset_id, method_name, tool_name, datetime.now(), success,
                    findings_count, execution_time, error_message, next_execution, json.dumps(metadata)
                ))
                
                execution_id = cursor.lastrowid
                
                # Update method statistics
                self._update_method_stats(db, method_name, tool_name, success, findings_count, execution_time)
                
                status = "SUCCESS" if success else "FAILED"
                logger.info(f"📝 RECORDED: {method_name} on {asset_url} - {status} ({findings_count} findings)")
                
                return execution_id
                
        except Exception as e:
            logger.error(f"Failed to record method execution: {e}")
            return -1

    def _update_method_stats(self, db, method_name: str, tool_name: str, success: bool, 
                           findings_count: int, execution_time: float):
        """Update method statistics"""
        try:
            # Get current stats
            query = '''
                SELECT total_executions, successful_executions, total_findings, avg_execution_time
                FROM method_stats WHERE method_name = ? AND tool_name = ?
            '''
            cursor = db.execute(query, (method_name, tool_name))
            result = cursor.fetchone()
            
            if result:
                total_exec, success_exec, total_findings, avg_time = result
                
                # Update existing stats
                new_total = total_exec + 1
                new_success = success_exec + (1 if success else 0)
                new_findings = total_findings + findings_count
                new_avg_time = ((avg_time * total_exec) + execution_time) / new_total
                success_rate = new_success / new_total
                
                update_query = '''
                    UPDATE method_stats 
                    SET total_executions = ?, successful_executions = ?, total_findings = ?,
                        avg_execution_time = ?, success_rate = ?, last_success = ?
                    WHERE method_name = ? AND tool_name = ?
                '''
                
                last_success = datetime.now() if success else None
                db.execute(update_query, (
                    new_total, new_success, new_findings, new_avg_time, success_rate, 
                    last_success, method_name, tool_name
                ))
            else:
                # Insert new stats
                insert_query = '''
                    INSERT INTO method_stats 
                    (method_name, tool_name, total_executions, successful_executions, 
                     total_findings, avg_execution_time, success_rate, last_success)
                    VALUES (?, ?, 1, ?, ?, ?, ?, ?)
                '''
                
                success_count = 1 if success else 0
                last_success = datetime.now() if success else None
                db.execute(insert_query, (
                    method_name, tool_name, success_count, findings_count, 
                    execution_time, success_count, last_success
                ))
                
        except Exception as e:
            logger.error(f"Failed to update method stats: {e}")

    def get_method_stats(self, method_name: str = None) -> List[Dict]:
        """Get method execution statistics"""
        try:
            with sqlite3.connect(self.db_path) as db:
                if method_name:
                    query = '''
                        SELECT method_name, tool_name, total_executions, successful_executions,
                               total_findings, avg_execution_time, success_rate, last_success
                        FROM method_stats WHERE method_name = ?
                        ORDER BY success_rate DESC, total_findings DESC
                    '''
                    cursor = db.execute(query, (method_name,))
                else:
                    query = '''
                        SELECT method_name, tool_name, total_executions, successful_executions,
                               total_findings, avg_execution_time, success_rate, last_success
                        FROM method_stats
                        ORDER BY success_rate DESC, total_findings DESC
                    '''
                    cursor = db.execute(query)
                
                results = []
                for row in cursor.fetchall():
                    results.append({
                        'method_name': row[0],
                        'tool_name': row[1],
                        'total_executions': row[2],
                        'successful_executions': row[3],
                        'total_findings': row[4],
                        'avg_execution_time': row[5],
                        'success_rate': row[6],
                        'last_success': row[7]
                    })
                
                return results
                
        except Exception as e:
            logger.error(f"Failed to get method stats: {e}")
            return []

    def get_pending_methods_for_asset(self, asset_url: str) -> List[str]:
        """Get methods that should be executed for an asset"""
        pending_methods = []
        
        for method_name in self.method_ttl_config.keys():
            if self.should_execute_method(asset_url, method_name):
                pending_methods.append(method_name)
        
        return pending_methods

    def get_stale_assets(self, hours: int = 24) -> List[Dict]:
        """Get assets that haven't been scanned with any method recently"""
        try:
            with sqlite3.connect(self.db_path) as db:
                query = '''
                    SELECT DISTINCT a.url, a.id, a.status_code, a.tech_stack,
                           MAX(me.executed_at) as last_method_execution
                    FROM assets a
                    LEFT JOIN method_executions me ON a.url = me.asset_url
                    GROUP BY a.url, a.id
                    HAVING last_method_execution IS NULL 
                       OR last_method_execution < datetime('now', '-{} hours')
                    ORDER BY last_method_execution ASC
                    LIMIT 100
                '''.format(hours)
                
                cursor = db.execute(query)
                results = []
                
                for row in cursor.fetchall():
                    results.append({
                        'url': row[0],
                        'id': row[1],
                        'status_code': row[2],
                        'tech_stack': row[3],
                        'last_method_execution': row[4]
                    })
                
                return results
                
        except Exception as e:
            logger.error(f"Failed to get stale assets: {e}")
            return []

    def cleanup_old_executions(self, days: int = 30):
        """Clean up old execution records"""
        try:
            with sqlite3.connect(self.db_path) as db:
                cutoff_date = datetime.now() - timedelta(days=days)
                
                query = '''
                    DELETE FROM method_executions 
                    WHERE executed_at < ?
                '''
                
                cursor = db.execute(query, (cutoff_date,))
                deleted_count = cursor.rowcount
                
                logger.info(f"🧹 Cleaned up {deleted_count} old method execution records")
                
        except Exception as e:
            logger.error(f"Failed to cleanup old executions: {e}")