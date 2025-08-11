
import sqlite3
import json
import time

# --- Configuration ---
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / 'config.json'
ASSET_MAPPING_PATH = BASE_DIR / 'asset_mapping.json'

with open(CONFIG_PATH, 'r') as f:
    CONFIG = json.load(f)
    
with open(ASSET_MAPPING_PATH, 'r') as f:
    ASSET_MAPPING = json.load(f)

DB_PATH = CONFIG['database_path']

class AssetManager:
    def __init__(self):
        self.db_path = DB_PATH
        self.field_mappings = ASSET_MAPPING.get('field_mappings', {})
        self.vuln_mappings = ASSET_MAPPING.get('vulnerability_mappings', {})
        self.activity_mappings = ASSET_MAPPING.get('activity_mappings', {})

    def _get_db(self):
        conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        return conn

    def get_asset_fields(self):
        """Returns database field names for assets based on mapping config"""
        return {
            'url': self.field_mappings.get('url', 'url'),
            'host': self.field_mappings.get('source', 'host'),  # 'source' maps to 'host' in DB
            'status_code': self.field_mappings.get('status', 'status_code'),
            'title': self.field_mappings.get('title', 'title'),
            'tech_stack': self.field_mappings.get('tech_stack', 'tech_stack'),
            'content_length': self.field_mappings.get('size', 'content_length'),
            'response_time': self.field_mappings.get('time', 'response_time'),
            'discovery_method': self.field_mappings.get('method', 'discovery_method'),
            'response_body': self.field_mappings.get('response', 'response_body'),
            'last_scanned': self.field_mappings.get('timestamp', 'last_scanned'),
            'screenshot_path': self.field_mappings.get('screenshot', 'screenshot_path'),
            'intelligence_score': self.field_mappings.get('intelligence_score', 'intelligence_score'),
            'id': self.field_mappings.get('id', 'id')
        }

    def get_vuln_fields(self):
        """Returns database field names for vulnerabilities based on mapping config"""
        return {
            'id': self.vuln_mappings.get('id', 'id'),
            'asset_id': self.vuln_mappings.get('asset_id', 'asset_id'),
            'type': self.vuln_mappings.get('vuln_type', 'type'),
            'severity': self.vuln_mappings.get('severity', 'severity'),
            'description': self.vuln_mappings.get('description', 'description'),
            'evidence': self.vuln_mappings.get('evidence', 'evidence'),
            'payload': self.vuln_mappings.get('payload', 'payload'),
            'confidence': self.vuln_mappings.get('confidence', 'confidence'),
            'detected_at': self.vuln_mappings.get('discovered_at', 'detected_at'),
            'asset_url': self.vuln_mappings.get('asset_url', 'asset_url')
        }

    def get_activity_fields(self):
        """Returns database field names for activities based on mapping config"""
        return {
            'id': self.activity_mappings.get('id', 'id'),
            'timestamp': self.activity_mappings.get('timestamp', 'timestamp'),
            'action': self.activity_mappings.get('action', 'action'),
            'details': self.activity_mappings.get('details', 'details'),
            'created_at': self.activity_mappings.get('created_at', 'created_at')
        }

    def build_activity_insert_query(self, timestamp, action, details):
        """Builds INSERT query for activities using field mappings"""
        fields = self.get_activity_fields()
        
        query = f"""INSERT INTO activities 
                    ({fields['timestamp']}, {fields['action']}, {fields['details']})
                    VALUES (?, ?, ?)"""
        
        values = (timestamp, action, details)
        return query, values

    def log_activity(self, action, details, timestamp=None):
        """Log activity using field mappings"""
        try:
            if timestamp is None:
                from datetime import datetime
                timestamp = datetime.now().strftime('%m/%d/%y %H:%M:%S')
                
            with self._get_db() as db:
                query, values = self.build_activity_insert_query(timestamp, action, details)
                db.execute(query, values)
                db.commit()
        except Exception as e:
            print(f"Error logging activity: {e}")

    def get_activities(self, limit=50):
        """Get activities using mapped field names"""
        try:
            with self._get_db() as db:
                fields = self.get_activity_fields()
                query = f"""SELECT * FROM activities 
                           ORDER BY {fields['created_at']} DESC 
                           LIMIT ?"""
                cursor = db.execute(query, (limit,))
                activities = [dict(row) for row in cursor.fetchall()]
                return {"activities": activities}
        except Exception as e:
            print(f"Error getting activities: {e}")
            return {"activities": []}

    def get_proxy_stats(self):
        """Get current proxy statistics from recent activity logs using centralized mapping."""
        try:
            with self._get_db() as db:
                fields = self.get_activity_fields()
                
                # Get most recent proxy health check (last hour to be safe)
                query = f"""
                    SELECT {fields['details']} FROM activities 
                    WHERE {fields['action']} = 'PROXY_HEALTH' 
                    ORDER BY {fields['timestamp']} DESC 
                    LIMIT 1
                """
                cursor = db.execute(query)
                
                result = cursor.fetchone()
                if result and result[0]:
                    details = result[0]
                    # Parse "Proxy health check completed: 29/30 proxies operational"
                    if "proxies operational" in details:
                        import re
                        match = re.search(r'(\d+)/(\d+) proxies operational', details)
                        if match:
                            healthy_count = int(match.group(1))
                            total_count = int(match.group(2))
                            return {
                                'healthy_proxies': healthy_count,
                                'total_proxies': total_count,
                                'active_connections': healthy_count
                            }
                            
                # Fallback if no recent proxy health data
                return {
                    'healthy_proxies': 0,
                    'total_proxies': 0,
                    'active_connections': 0
                }
                
        except Exception as e:
            print(f"Error retrieving proxy stats: {e}")
            return {
                'healthy_proxies': 0,
                'total_proxies': 0,
                'active_connections': 0
            }

    def get_scope_domains(self):
        """Get scope domains for enhanced discovery using centralized mapping"""
        try:
            with self._get_db() as db:
                cursor = db.execute("SELECT domain FROM scope WHERE is_active = 1")
                domains = [row[0] for row in cursor.fetchall()]
                return domains
        except Exception as e:
            print(f"Error getting scope domains: {e}")
            return []
    
    def get_scope_targets(self):
        """Get all scope targets for API with proper field mappings"""
        try:
            with self._get_db() as db:
                cursor = db.execute("SELECT id, domain, is_active FROM scope")
                targets = []
                for row in cursor.fetchall():
                    target_id, domain, is_active = row
                    is_wildcard = domain.startswith('*.')
                    targets.append((target_id, domain, is_wildcard))
                return targets
        except Exception as e:
            print(f"Error getting scope targets: {e}")
            return []
    
    def add_scope_target(self, domain, is_active=1):
        """Add a new scope target using centralized mapping"""
        try:
            with self._get_db() as db:
                cursor = db.execute("INSERT INTO scope (domain, is_active) VALUES (?, ?)", 
                                  (domain, is_active))
                db.commit()
                return cursor.lastrowid
        except Exception as e:
            print(f"Error adding scope target: {e}")
            return None
    
    def delete_scope_target(self, target_id):
        """Delete a scope target using centralized mapping"""
        try:
            with self._get_db() as db:
                cursor = db.execute("DELETE FROM scope WHERE id = ?", (target_id,))
                db.commit()
                return cursor.rowcount > 0
        except Exception as e:
            print(f"Error deleting scope target: {e}")
            return False

    def get_existing_urls(self, limit=5000):
        """Get existing asset URLs to avoid duplicates using centralized mapping"""
        try:
            with self._get_db() as db:
                fields = self.get_asset_fields()
                query = f"SELECT {fields['url']} FROM assets LIMIT ?"
                cursor = db.execute(query, (limit,))
                urls = [row[0] for row in cursor.fetchall()]
                return urls
        except Exception as e:
            print(f"Error getting existing URLs: {e}")
            return []

    def get_domain_technologies(self, domain=None):
        """Get technology information for domain(s) using centralized mapping"""
        try:
            with self._get_db() as db:
                fields = self.get_asset_fields()
                
                if domain is None:
                    # Return technologies for all domains (for ML discovery)
                    query = f"""
                        SELECT {fields['host']}, {fields['tech_stack']}, {fields['title']}
                        FROM assets 
                        WHERE {fields['tech_stack']} IS NOT NULL AND {fields['tech_stack']} != ''
                        GROUP BY {fields['host']}
                    """
                    cursor = db.execute(query)
                    results = {}
                    for row in cursor.fetchall():
                        host = row[0] if row[0] else 'unknown'
                        tech_stack = row[1] if row[1] else ''
                        title = row[2] if row[2] else ''
                        
                        # Parse technologies from tech_stack and title
                        technologies = []
                        if tech_stack:
                            technologies.extend([t.strip() for t in tech_stack.split(',') if t.strip()])
                        if title:
                            # Extract tech hints from title
                            title_lower = title.lower()
                            if 'wordpress' in title_lower:
                                technologies.append('WordPress')
                            if 'django' in title_lower:
                                technologies.append('Django')
                        
                        # Extract base domain from host
                        domain_key = host.replace('www.', '') if host.startswith('www.') else host
                        results[domain_key] = technologies
                    return results
                else:
                    # Return technology info string for specific domain (existing behavior)
                    query = f"""
                        SELECT {fields['tech_stack']}, {fields['title']}, {fields['response_body']}
                        FROM assets 
                        WHERE {fields['url']} LIKE ? OR {fields['host']} LIKE ?
                        LIMIT 10
                    """
                    cursor = db.execute(query, (f"%{domain}%", f"%{domain}%"))
                    results = cursor.fetchall()
                    
                    # Aggregate technology information
                    tech_info = ""
                    for row in results:
                        tech_stack = row[0] or ""
                        title = row[1] or ""
                        response_body = row[2] or ""
                        tech_info += f" {tech_stack} {title} {response_body[:200]}"
                
                return tech_info.lower()
        except Exception as e:
            print(f"Error getting domain technologies: {e}")
            return ""
        except Exception as e:
            print(f"Error getting activities: {e}")
            return {"activities": []}

    def build_asset_insert_query(self, url, host, status_code=None, title=None, tech_stack=None, 
                                content_length=None, response_time=None, discovery_method=None,
                                response_body=None, last_scanned=None, screenshot_path=None, intelligence_score=None):
        """Builds INSERT query for assets using field mappings"""
        fields = self.get_asset_fields()
        
        columns = []
        values = []
        placeholders = []
        
        field_data = {
            'url': url,
            'host': host,
            'status_code': status_code,
            'title': title,
            'tech_stack': tech_stack,
            'content_length': content_length,
            'response_time': response_time,
            'discovery_method': discovery_method,
            'response_body': response_body,
            'last_scanned': last_scanned,
            'screenshot_path': screenshot_path,
            'intelligence_score': intelligence_score
        }
        
        for field_key, field_value in field_data.items():
            if field_value is not None:
                columns.append(fields[field_key])
                values.append(field_value)
                placeholders.append('?')
        
        # Use INSERT OR REPLACE to update existing assets with new data
        query = f"INSERT OR REPLACE INTO assets ({', '.join(columns)}) VALUES ({', '.join(placeholders)})"
        return query, values

    def build_vuln_insert_query(self, asset_id, vuln_type, severity, description, 
                               evidence, payload, confidence, detected_at):
        """Builds INSERT query for vulnerabilities using field mappings"""
        fields = self.get_vuln_fields()
        
        query = f"""INSERT INTO vulnerabilities 
                    ({fields['asset_id']}, {fields['type']}, {fields['severity']}, 
                     {fields['description']}, {fields['evidence']}, {fields['payload']}, 
                     {fields['confidence']}, {fields['detected_at']})
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)"""
        
        values = (asset_id, vuln_type, severity, description, evidence, payload, confidence, detected_at)
        return query, values

    def build_vuln_select_query(self, limit=100):
        """Builds SELECT query for vulnerabilities using field mappings"""
        fields = self.get_vuln_fields()
        asset_fields = self.get_asset_fields()
        
        query = f"""SELECT v.*, a.{asset_fields['url']} as {fields['asset_url']} 
                    FROM vulnerabilities v 
                    JOIN assets a ON v.{fields['asset_id']} = a.{asset_fields['id']} 
                    ORDER BY v.{fields['detected_at']} DESC 
                    LIMIT ?"""
        
        return query, (limit,)

    def get_vulnerabilities(self, limit=100):
        """Get vulnerabilities using mapped field names"""
        try:
            with self._get_db() as db:
                query, params = self.build_vuln_select_query(limit)
                cursor = db.execute(query, params)
                vulns = [dict(row) for row in cursor.fetchall()]
                return {"vulnerabilities": vulns}
        except Exception as e:
            print(f"Error loading vulnerabilities: {e}")
            return {"vulnerabilities": []}

    def add_asset(self, url, host, discovery_method):
        """Adds a new asset to the database using field mappings."""
        try:
            with self._get_db() as db:
                # Use field mappings for database columns
                fields = self.get_asset_fields()
                query = f"INSERT OR IGNORE INTO assets ({fields['url']}, {fields['host']}, {fields['discovery_method']}, {fields['last_scanned']}) VALUES (?, ?, ?, ?)"
                cursor = db.execute(query, (url, host, discovery_method, time.strftime('%Y-%m-%d %H:%M:%S')))
                
                # Log activity if new asset was actually added
                if cursor.rowcount > 0:
                    try:
                        from activity_logger import activity_logger
                        activity_logger.log_asset_discovered(url, discovery_method)
                    except Exception:
                        pass  # Don't fail asset addition if logging fails
                        
        except sqlite3.IntegrityError:
            # Asset already exists
            pass
        except Exception as e:
            print(f"Error adding asset {url}: {e}")

    def get_assets(self, search_query='', page=1, per_page=25):
        """Retrieves assets from the database with search and pagination using field mappings."""
        try:
            with self._get_db() as db:
                offset = (page - 1) * per_page
                fields = self.get_asset_fields()
                
                # Handle special filters
                if search_query == 'scanned:true':
                    # Only show assets that have been actually scanned (have status codes)
                    query = f"""
                        SELECT * FROM assets 
                        WHERE {fields['status_code']} IS NOT NULL 
                        ORDER BY 
                            ({fields['screenshot_path']} IS NOT NULL) DESC,
                            ({fields['response_time']} IS NOT NULL) DESC,
                            {fields['status_code']} ASC,
                            {fields['last_scanned']} DESC 
                        LIMIT ? OFFSET ?
                    """
                    assets_cursor = db.execute(query, (per_page, offset))
                elif search_query and search_query != '*':
                    query = f"""
                        SELECT * FROM assets 
                        WHERE {fields['url']} LIKE ? OR {fields['title']} LIKE ? OR {fields['tech_stack']} LIKE ? 
                        ORDER BY 
                            ({fields['status_code']} IS NOT NULL) DESC,
                            ({fields['screenshot_path']} IS NOT NULL) DESC,
                            ({fields['response_time']} IS NOT NULL) DESC,
                            ({fields['discovery_method']} != 'cert_transparency') DESC,
                            {fields['last_scanned']} DESC 
                        LIMIT ? OFFSET ?
                    """
                    assets_cursor = db.execute(query, (f'%{search_query}%', f'%{search_query}%', f'%{search_query}%', per_page, offset))
                else:
                    # Prioritize: 1) Assets with status codes (actually scanned), 2) Assets with screenshots, 3) Non-CT discovery, 4) CT entries last
                    query = f"""
                        SELECT * FROM assets 
                        ORDER BY 
                            ({fields['status_code']} IS NOT NULL) DESC,
                            ({fields['screenshot_path']} IS NOT NULL) DESC,
                            ({fields['response_time']} IS NOT NULL) DESC,
                            ({fields['discovery_method']} != 'cert_transparency') DESC,
                            {fields['last_scanned']} DESC 
                        LIMIT ? OFFSET ?
                    """
                    assets_cursor = db.execute(query, (per_page, offset))
                
                assets = [dict(row) for row in assets_cursor.fetchall()]
                total_assets = db.execute(f"SELECT COUNT({fields['id']}) FROM assets").fetchone()[0]
                
                return {
                    "assets": assets,
                    "total": total_assets,
                    "page": page,
                    "per_page": per_page
                }
        except Exception as e:
            print(f"Error retrieving assets: {e}")
            return {"assets": [], "total": 0, "page": page, "per_page": per_page}

    def get_asset_summary(self):
        """Retrieves a summary of the assets in the database using field mappings."""
        try:
            with self._get_db() as db:
                fields = self.get_asset_fields()
                
                total_assets = db.execute(f"SELECT COUNT({fields['id']}) FROM assets").fetchone()[0]
                scanned_assets = db.execute(f"SELECT COUNT({fields['id']}) FROM assets WHERE {fields['status_code']} IS NOT NULL").fetchone()[0]
                active_assets = db.execute(f"SELECT COUNT({fields['id']}) FROM assets WHERE {fields['status_code']} = 200").fetchone()[0]
                forbidden_assets = db.execute(f"SELECT COUNT({fields['id']}) FROM assets WHERE {fields['status_code']} = 403").fetchone()[0]
                redirect_assets = db.execute(f"SELECT COUNT({fields['id']}) FROM assets WHERE {fields['status_code']} >= 300 AND {fields['status_code']} < 400").fetchone()[0]
                new_today = db.execute(f"SELECT COUNT({fields['id']}) FROM assets WHERE date({fields['last_scanned']}) = date('now')").fetchone()[0]
                screenshots = db.execute(f"SELECT COUNT({fields['id']}) FROM assets WHERE {fields['screenshot_path']} IS NOT NULL").fetchone()[0]
                
                return {
                    "total_assets": total_assets,
                    "scanned_assets": scanned_assets,
                    "active_200": active_assets,
                    "forbidden_403": forbidden_assets,
                    "redirects_3xx": redirect_assets,
                    "new_today": new_today,
                    "screenshots": screenshots
                }
        except Exception as e:
            print(f"Error getting asset summary: {e}")
            return {"total_assets": 0, "scanned_assets": 0, "active_200": 0, "forbidden_403": 0, "redirects_3xx": 0, "new_today": 0, "screenshots": 0}

    def get_existing_urls(self, limit=5000):
        """Get list of existing asset URLs to avoid duplicates"""
        try:
            with self._get_db() as db:
                fields = self.get_asset_fields()
                query = f"SELECT {fields['url']} FROM assets LIMIT ?"
                cursor = db.execute(query, (limit,))
                return set(row[0] for row in cursor.fetchall())
        except Exception as e:
            print(f"Error getting existing URLs: {e}")
            return set()

    def get_progressive_scan_stats(self):
        """Get progressive scanning statistics using field mappings"""
        try:
            with self._get_db() as db:
                fields = self.get_asset_fields()
                
                discovered = db.execute(f"SELECT COUNT({fields['id']}) FROM assets").fetchone()[0]
                
                basic_complete = db.execute(f"SELECT COUNT({fields['id']}) FROM assets WHERE basic_scan_complete = 1").fetchone()[0]
                
                deep_complete = db.execute(f"SELECT COUNT({fields['id']}) FROM assets WHERE deep_scan_complete = 1").fetchone()[0]
                
                return {
                    'discovered': discovered,
                    'basic_complete': basic_complete,
                    'deep_complete': deep_complete
                }
        except Exception as e:
            print(f"Error getting progressive scan stats: {e}")
            return {'discovered': 0, 'basic_complete': 0, 'deep_complete': 0}

    def get_assets_needing_tech_detection(self, limit=100):
        """Get assets that need technology detection using field mappings"""
        try:
            with self._get_db() as db:
                fields = self.get_asset_fields()
                query = f'''
                    SELECT {fields['id']}, {fields['url']}, {fields['status_code']}
                    FROM assets 
                    WHERE {fields['status_code']} = 200 
                    AND basic_scan_complete = 1 
                    AND (technologies_detected IS NULL OR {fields['screenshot_path']} IS NULL)
                    ORDER BY {fields['last_scanned']} DESC 
                    LIMIT ?
                '''
                cursor = db.execute(query, (limit,))
                return [{'id': row[0], 'url': row[1], 'status_code': row[2]} for row in cursor.fetchall()]
        except Exception as e:
            print(f"Error getting assets needing tech detection: {e}")
            return []

    def get_assets_ready_for_deep_scan(self, limit=75):
        """Get assets ready for deep vulnerability scanning - REQUIRES both tech detection AND screenshots"""
        try:
            with self._get_db() as db:
                fields = self.get_asset_fields()
                query = f'''
                    SELECT {fields['id']}, {fields['url']}, {fields['status_code']}, {fields['tech_stack']}
                    FROM assets 
                    WHERE {fields['status_code']} = 200 
                    AND basic_scan_complete = 1 
                    AND technologies_detected IS NOT NULL 
                    AND technologies_detected != ''
                    AND technologies_detected != '[]'
                    AND ({fields['screenshot_path']} IS NOT NULL OR scanning_stage = 'tech_complete')
                    AND deep_scan_complete = 0
                    ORDER BY {fields['intelligence_score']} DESC, {fields['last_scanned']} DESC 
                    LIMIT ?
                '''
                cursor = db.execute(query, (limit,))
                return [{
                    'id': row[0], 'url': row[1], 'status_code': row[2], 'tech_stack': row[3]
                } for row in cursor.fetchall()]
        except Exception as e:
            print(f"Error getting assets ready for deep scan: {e}")
            return []

    def mark_basic_scan_complete(self, url, headers=None):
        """Mark asset as basic scan complete using field mappings"""
        try:
            with self._get_db() as db:
                fields = self.get_asset_fields()
                from datetime import datetime
                timestamp = datetime.now().isoformat()
                
                query = f'''
                    UPDATE assets SET 
                        basic_scan_complete = 1, 
                        last_basic_scan = ?, 
                        scanning_stage = 'basic_complete',
                        headers_collected = ?
                    WHERE {fields['url']} = ?
                '''
                db.execute(query, (timestamp, str(headers)[:500] if headers else None, url))
                db.commit()
                return True
        except Exception as e:
            print(f"Error marking basic scan complete: {e}")
            return False

    def update_asn_information(self, asset_id, asn_info):
        """Update asset with ASN information for better target attribution"""
        try:
            with self._get_db() as db:
                db.execute('UPDATE assets SET asn_info = ? WHERE id = ?', 
                          (json.dumps(asn_info), asset_id))
                return True
        except Exception as e:
            print(f"Error updating ASN info: {e}")
            return False

    def update_technology_detection(self, asset_id, technologies, screenshot_path=None):
        """Update asset with technology detection results and screenshot using field mappings"""
        try:
            with self._get_db() as db:
                fields = self.get_asset_fields()
                
                # Build query dynamically based on whether we have screenshot
                if screenshot_path:
                    query = f'''
                        UPDATE assets SET 
                            technologies_detected = ?,
                            {fields['tech_stack']} = ?,
                            {fields['screenshot_path']} = ?,
                            scanning_stage = 'tech_complete',
                            {fields['intelligence_score']} = {fields['intelligence_score']} + 0.3
                        WHERE {fields['id']} = ?
                    '''
                    tech_list = ', '.join(technologies[:5]) if technologies else ''
                    db.execute(query, (str(technologies)[:500], tech_list, screenshot_path, asset_id))
                else:
                    query = f'''
                        UPDATE assets SET 
                            technologies_detected = ?,
                            {fields['tech_stack']} = ?,
                            scanning_stage = 'tech_complete',
                            {fields['intelligence_score']} = {fields['intelligence_score']} + 0.2
                        WHERE {fields['id']} = ?
                    '''
                    tech_list = ', '.join(technologies[:5]) if technologies else ''
                    db.execute(query, (str(technologies)[:500], tech_list, asset_id))
                    
                db.commit()
                return True
        except Exception as e:
            print(f"Error updating technology detection: {e}")
            return False

    def mark_deep_scan_complete(self, asset_id):
        """Mark asset as deep scan complete using field mappings"""
        try:
            with self._get_db() as db:
                fields = self.get_asset_fields()
                from datetime import datetime
                timestamp = datetime.now().isoformat()
                
                query = f'''
                    UPDATE assets SET 
                        deep_scan_complete = 1,
                        last_deep_scan = ?,
                        scanning_stage = 'complete',
                        {fields['intelligence_score']} = {fields['intelligence_score']} + 0.3
                    WHERE {fields['id']} = ?
                '''
                db.execute(query, (timestamp, asset_id))
                db.commit()
                return True
        except Exception as e:
            print(f"Error marking deep scan complete: {e}")
            return False

    def get_screenshot_path(self, url):
        """Get screenshot path for URL using field mappings"""
        try:
            with self._get_db() as db:
                fields = self.get_asset_fields()
                query = f"SELECT {fields['screenshot_path']} FROM assets WHERE {fields['url']} = ?"
                cursor = db.execute(query, (url,))
                result = cursor.fetchone()
                return result[0] if result and result[0] else None
        except Exception as e:
            print(f"Error getting screenshot path: {e}")
            return None

    def update_screenshot_path(self, asset_id, screenshot_path):
        """Update screenshot path for asset using field mappings"""
        try:
            with self._get_db() as db:
                fields = self.get_asset_fields()
                query = f"UPDATE assets SET {fields['screenshot_path']} = ? WHERE {fields['id']} = ?"
                db.execute(query, (screenshot_path, asset_id))
                db.commit()
                return True
        except Exception as e:
            print(f"Error updating screenshot path: {e}")
            return False

    def get_assets_needing_screenshots(self, limit=50):
        """Get assets that need screenshot capture using field mappings"""
        try:
            with self._get_db() as db:
                fields = self.get_asset_fields()
                query = f'''
                    SELECT {fields['id']}, {fields['url']}, {fields['status_code']}
                    FROM assets 
                    WHERE {fields['status_code']} IN (200, 403)
                    AND basic_scan_complete = 1 
                    AND ({fields['screenshot_path']} IS NULL OR {fields['screenshot_path']} = '')
                    ORDER BY {fields['intelligence_score']} DESC, {fields['last_scanned']} DESC 
                    LIMIT ?
                '''
                cursor = db.execute(query, (limit,))
                return [{'id': row[0], 'url': row[1], 'status_code': row[2]} for row in cursor.fetchall()]
        except Exception as e:
            print(f"Error getting assets needing screenshots: {e}")
            return []

    def is_valid_screenshot(self, screenshot_path):
        """Check if screenshot path points to a valid PNG file using centralized logic"""
        if not screenshot_path or screenshot_path == 'NONE' or screenshot_path == '':
            return False
        
        if 'placeholder' in screenshot_path.lower():
            return False
            
        if not screenshot_path.endswith('.png'):
            return False
            
        # Check if file exists and is actually a PNG
        import os
        if not os.path.exists(screenshot_path):
            return False
            
        try:
            # Check PNG signature
            with open(screenshot_path, 'rb') as f:
                png_signature = f.read(8)
                return png_signature == b'\x89PNG\r\n\x1a\n'
        except Exception:
            return False
