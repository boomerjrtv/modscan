import sqlite3
import json
import time
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
import logging

logger = logging.getLogger(__name__)

# --- CRITICAL: Centralized VulnerabilityFinding Structure ---
# This is the AUTHORITATIVE definition - all vulnerability scanners MUST use this structure
@dataclass
class VulnerabilityFinding:
    """
    AUTHORITATIVE VulnerabilityFinding structure for ModScan platform.
    ALL vulnerability scanners must use these exact field names and types.
    """
    # REQUIRED fields
    url: str                        # Target URL where vulnerability was found
    vuln_type: str                  # Vulnerability type (e.g., 'SQL_INJECTION', 'XSS', 'IDOR')
    severity: str                   # Severity: 'Critical', 'High', 'Medium', 'Low', 'Info'
    confidence: float               # Confidence score 0.0-1.0
    payload: str                    # Attack payload used
    evidence: str                   # Evidence of the vulnerability
    discovered_at: datetime         # When vulnerability was discovered
    
    # OPTIONAL fields (with defaults)
    impact_description: str = ""    # Impact description
    remediation: str = ""           # Remediation advice
    affected_parameter: str = ""    # Parameter that was vulnerable
    raw_request: str = ""           # Raw HTTP request
    raw_response: str = ""          # Raw HTTP response
    bypass_method: str = ""         # HTTP bypass method used (if any)
    screenshot_path: str = ""       # Screenshot path if available

# Database field mapping for vulnerabilities table
VULNERABILITY_DB_MAPPING = {
    'vuln_type': 'type',           # VulnerabilityFinding.vuln_type -> DB.type
    'url': 'url',                  # VulnerabilityFinding.url -> DB.url  
    'severity': 'severity',        # VulnerabilityFinding.severity -> DB.severity
    'confidence': 'confidence',    # VulnerabilityFinding.confidence -> DB.confidence
    'payload': 'payload',          # VulnerabilityFinding.payload -> DB.payload
    'evidence': 'evidence',        # VulnerabilityFinding.evidence -> DB.evidence
    'discovered_at': 'detected_at', # VulnerabilityFinding.discovered_at -> DB.detected_at
    'impact_description': 'description' # VulnerabilityFinding.impact_description -> DB.description
}

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




    def notify_change(self, message: str, payload: Optional[dict] = None, ntype: str = "change") -> None:
        """
        Append a notification event to BASE_DIR/notifications.jsonl for the dashboard to consume later.
        (If you already have a notifications table/API, wire this there.)
        """
        from pathlib import Path
        import json, time
        base_dir = Path(__file__).resolve().parent
        path = base_dir / 'notifications.jsonl'
        event = {'ts': int(time.time()), 'type': ntype or 'change', 'message': message, 'payload': payload or {}}
        with open(path, 'a', encoding='utf-8') as fp:
            fp.write(json.dumps(event, ensure_ascii=False) + "\n")
    def record_scan(self, url: str, content_hash: Optional[str] = None, meta: Optional[dict] = None) -> dict:
        """
        After a scan finishes, persist last_scan_ts and (optional) content_hash.
        Returns {"status": "created"|"updated"|"unchanged", "diff": {...}}.
        """
        from pathlib import Path
        import time, json
        key = self.normalize_url(url)
        base_dir = Path(__file__).resolve().parent
        reg_path = base_dir / 'scan_registry.json'
        reg = {}
        if reg_path.exists():
            try:
                reg = json.loads(reg_path.read_text(encoding='utf-8') or '{}')
            except Exception:
                reg = {}
        now = int(time.time())
        prev = reg.get(key)
        status = 'created'
        diff = {}
        if prev:
            status = 'unchanged'
            if content_hash and content_hash != prev.get('content_hash'):
                status = 'updated'
                diff['old_hash'] = prev.get('content_hash')
                diff['new_hash'] = content_hash
        reg[key] = {
            'last_scan_ts': now,
            'content_hash': content_hash or (prev.get('content_hash') if prev else None),
            'meta': meta or (prev.get('meta') if prev else None),
        }
        reg_path.write_text(json.dumps(reg, ensure_ascii=False, indent=2), encoding='utf-8')
        return {'status': status, 'diff': diff, 'key': key}
    def should_enqueue(self, url: str, ttl_seconds: int = 86400) -> bool:
        """
        Returns True if this URL should be scanned now, based on TTL since last scan.
        Persistent registry at BASE_DIR/scan_registry.json
        """
        try:
            from pathlib import Path
            import time, json
            key = self.normalize_url(url)
            base_dir = Path(__file__).resolve().parent
            reg_path = base_dir / 'scan_registry.json'
            if reg_path.exists():
                reg = json.loads(reg_path.read_text(encoding='utf-8') or '{}')
            else:
                reg = {}
            entry = reg.get(key)
            now = int(time.time())
            if entry and isinstance(entry, dict):
                last = int(entry.get('last_scan_ts', 0))
                if now - last < int(ttl_seconds):
                    return False
            # Allow enqueue; caller should later record_scan()
            return True
        except Exception:
            return True
    def normalize_url(self, url: str) -> str:
        """
        Canonicalize URL for de-dupe. Lowercase host, strip default ports,
        remove fragments, sort query params, drop common tracking params.
        """
        try:
            import re
            from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
            u = str(url).strip()
            if not u:
                return u
            sp = urlsplit(u)
            scheme = (sp.scheme or 'http').lower()
            netloc = sp.netloc or sp.path  # tolerate bare hosts
            path = sp.path if sp.netloc else ''
            # lowercase host, strip default ports
            host, *port = netloc.split(':', 1)
            host = host.lower()
            if port:
                p = port[0]
                if (scheme == 'http' and p == '80') or (scheme == 'https' and p == '443'):
                    netloc = host
                else:
                    netloc = f"{host}:{p}"
            else:
                netloc = host
            # remove fragment
            fragment = ''
            # normalize path: collapse // and strip trailing slash (but keep root '/')
            norm_path = re.sub(r'/+', '/', path or '/')
            if len(norm_path) > 1 and norm_path.endswith('/'):
                norm_path = norm_path.rstrip('/')
            # sort query params, drop trackers
            drop = {'utm_source','utm_medium','utm_campaign','utm_term','utm_content','gclid','fbclid','mc_cid','mc_eid'}
            q = [(k,v) for k,v in parse_qsl(sp.query, keep_blank_values=True) if k not in drop]
            q.sort()
            query = urlencode(q, doseq=True)
            return urlunsplit((scheme, netloc, norm_path, query, fragment))
        except Exception:
            return str(url)
    def __init__(self):
        self.db_path = DB_PATH
        self.field_mappings = ASSET_MAPPING.get('field_mappings', {})
        self.vuln_mappings = ASSET_MAPPING.get('vulnerability_mappings', {})
        self.activity_mappings = ASSET_MAPPING.get('activity_mappings', {})
        
        # Initialize database tables immediately
        self._initialize_database()

    def _initialize_database(self):
        """Initialize all required database tables"""
        try:
            with self._get_db() as db:
                # Create assets table
                db.execute("""
                    CREATE TABLE IF NOT EXISTS assets (
                        id INTEGER PRIMARY KEY,
                        url TEXT,
                        host TEXT,
                        status_code INTEGER,
                        title TEXT,
                        tech_stack TEXT,
                        content_length INTEGER,
                        response_time REAL,
                        response_body TEXT,
                        screenshot_path TEXT,
                        last_scanned TEXT,
                        discovery_method TEXT,
                        discovered_at TEXT
                    )
                """)

                # Ensure critical asset columns exist (SQLite lacks IF NOT EXISTS for columns)
                try:
                    cols = {row[1] for row in db.execute('PRAGMA table_info(assets)').fetchall()}
                except Exception:
                    cols = set()
                # Common scanning state columns
                if 'basic_scan_complete' not in cols:
                    db.execute("ALTER TABLE assets ADD COLUMN basic_scan_complete INTEGER DEFAULT 0")
                if 'deep_scan_complete' not in cols:
                    db.execute("ALTER TABLE assets ADD COLUMN deep_scan_complete INTEGER DEFAULT 0")
                if 'last_basic_scan' not in cols:
                    db.execute("ALTER TABLE assets ADD COLUMN last_basic_scan TEXT")
                if 'last_deep_scan' not in cols:
                    db.execute("ALTER TABLE assets ADD COLUMN last_deep_scan TEXT")
                if 'last_nuclei_scan_at' not in cols:
                    db.execute("ALTER TABLE assets ADD COLUMN last_nuclei_scan_at TEXT")
                if 'intelligence_score' not in cols:
                    db.execute("ALTER TABLE assets ADD COLUMN intelligence_score REAL DEFAULT 0")
                if 'scanning_stage' not in cols:
                    db.execute("ALTER TABLE assets ADD COLUMN scanning_stage TEXT")
                if 'completion_attempts' not in cols:
                    db.execute("ALTER TABLE assets ADD COLUMN completion_attempts INTEGER DEFAULT 0")
                if 'state' not in cols:
                    db.execute("ALTER TABLE assets ADD COLUMN state TEXT")
                if 'asn_info' not in cols:
                    db.execute("ALTER TABLE assets ADD COLUMN asn_info TEXT")
                if 'headers_collected' not in cols:
                    db.execute("ALTER TABLE assets ADD COLUMN headers_collected TEXT")
                if 'technologies_detected' not in cols:
                    db.execute("ALTER TABLE assets ADD COLUMN technologies_detected TEXT")
                
                db.commit()
                
                # Create scope table
                db.execute("""
                    CREATE TABLE IF NOT EXISTS scope (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain TEXT NOT NULL UNIQUE,
                        is_active INTEGER NOT NULL DEFAULT 1
                    )
                """)
                
                # Create vulnerabilities table with canonical_key for proper deduplication
                db.execute("""
                    CREATE TABLE IF NOT EXISTS vulnerabilities (
                        id INTEGER PRIMARY KEY,
                        asset_id INTEGER,
                        type TEXT,
                        description TEXT,
                        severity TEXT,
                        evidence TEXT,
                        payload TEXT,
                        detected_at TEXT,
                        confidence REAL,
                        canonical_key TEXT
                    )
                """)

                # Add canonical_key column if it doesn't exist (for existing databases)
                try:
                    db.execute("ALTER TABLE vulnerabilities ADD COLUMN canonical_key TEXT")
                    db.commit()
                except:
                    pass  # Column already exists

                # Create index on canonical_key for fast deduplication lookups
                try:
                    db.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_canonical_key ON vulnerabilities(canonical_key)")
                    db.commit()
                except:
                    pass
                # Enforce dedup at DB-level for any code path that might bypass AssetManager
                try:
                    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS uniq_vulnerabilities_canonical_key ON vulnerabilities(canonical_key) WHERE canonical_key IS NOT NULL")
                    db.commit()
                except Exception:
                    pass
                
                # Create activities table
                db.execute("""
                    CREATE TABLE IF NOT EXISTS activities (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        action TEXT,
                        details TEXT
                    )
                """)
                
                db.commit()
                logger.info("✅ Database tables initialized successfully")
                
        except Exception as e:
            logger.error(f"❌ Failed to initialize database tables: {e}")
            raise

    # ---- Global Parameter Dictionary (universal, accumulates across targets) ----
    def _ensure_param_dictionary_table(self):
        try:
            with self._get_db() as db:
                db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS param_dictionary (
                        name TEXT PRIMARY KEY,
                        first_seen TEXT,
                        last_seen TEXT,
                        seen_count INTEGER DEFAULT 1,
                        last_source_url TEXT
                    )
                    """
                )
                db.execute("CREATE INDEX IF NOT EXISTS idx_param_dict_seen ON param_dictionary(seen_count DESC, last_seen DESC)")
                db.commit()
        except Exception as e:
            print(f"Error ensuring param_dictionary: {e}")

    def record_observed_param_names(self, names: list[str], source_url: str = ""):
        """Record parameter names observed in forms/URLs globally for future scans."""
        if not names:
            return
        self._ensure_param_dictionary_table()
        from datetime import datetime
        ts = datetime.now().isoformat()
        try:
            with self._get_db() as db:
                for n in names:
                    if not isinstance(n, str) or not n:
                        continue
                    try:
                        db.execute(
                            "INSERT INTO param_dictionary(name, first_seen, last_seen, seen_count, last_source_url) VALUES(?,?,?,?,?)",
                            (n, ts, ts, 1, source_url[:500])
                        )
                    except Exception:
                        # Update existing
                        db.execute(
                            "UPDATE param_dictionary SET last_seen=?, seen_count=seen_count+1, last_source_url=? WHERE name=?",
                            (ts, source_url[:500], n)
                        )
                db.commit()
        except Exception as e:
            print(f"Warning: failed recording param names: {e}")

    def get_param_dictionary(self, limit: int = 500) -> list[str]:
        """Return globally observed parameter names ordered by frequency/time."""
        self._ensure_param_dictionary_table()
        try:
            with self._get_db() as db:
                cur = db.execute(
                    "SELECT name FROM param_dictionary ORDER BY seen_count DESC, last_seen DESC LIMIT ?",
                    (int(limit),)
                )
                return [r[0] for r in cur.fetchall()]
        except Exception as e:
            print(f"Error loading param dictionary: {e}")
            return []

    def _get_db(self):
        conn = sqlite3.connect(self.db_path, timeout=60.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        try:
            conn.execute('PRAGMA busy_timeout=8000')  # wait up to 8s on lock contention
            conn.execute('PRAGMA foreign_keys=ON')
        except Exception:
            pass
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
            'last_scanned': self.field_mappings.get('last_scanned', 'last_scanned'),
            'discovered_at': self.field_mappings.get('discovered_at', 'discovered_at'),
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

    # ---- CVE candidate support ----
    def ensure_cve_candidate_table(self):
        try:
            with self._get_db() as db:
                db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS asset_cve_candidates (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        asset_id INTEGER,
                        cve TEXT,
                        score REAL,
                        matched_tokens TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                db.execute("CREATE INDEX IF NOT EXISTS idx_asset_cve_asset ON asset_cve_candidates(asset_id)")
                db.execute("CREATE INDEX IF NOT EXISTS idx_asset_cve_cve ON asset_cve_candidates(cve)")
        except Exception as e:
            print(f"Error ensuring asset_cve_candidates table: {e}")

    def upsert_asset_cve_candidates(self, asset_id: int, candidates: list[dict]):
        self.ensure_cve_candidate_table()
        try:
            with self._get_db() as db:
                db.execute("DELETE FROM asset_cve_candidates WHERE asset_id=?", (asset_id,))
                for c in candidates:
                    db.execute(
                        "INSERT INTO asset_cve_candidates (asset_id, cve, score, matched_tokens) VALUES (?, ?, ?, ?)",
                        (asset_id, c.get('cve',''), float(c.get('score', 0.0)), json.dumps(c.get('tokens', []), ensure_ascii=False))
                    )
        except Exception as e:
            print(f"Error upserting CVE candidates: {e}")

    def get_asset_cve_candidates(self, asset_id: int, limit: int = 50) -> list[dict]:
        self.ensure_cve_candidate_table()
        try:
            with self._get_db() as db:
                cur = db.execute(
                    "SELECT cve, score, matched_tokens, created_at FROM asset_cve_candidates WHERE asset_id=? ORDER BY score DESC, id DESC LIMIT ?",
                    (asset_id, limit)
                )
                out = []
                for r in cur.fetchall():
                    try:
                        toks = json.loads(r['matched_tokens'] or '[]')
                    except Exception:
                        toks = []
                    out.append({'cve': r['cve'], 'score': float(r['score'] or 0.0), 'tokens': toks, 'created_at': r['created_at']})
                return out
        except Exception as e:
            print(f"Error loading CVE candidates: {e}")
            return []

    def get_recent_assets_for_cve(self, limit: int = 25) -> list[dict]:
        try:
            fields = self.get_asset_fields()
            with self._get_db() as db:
                cur = db.execute(
                    f"""
                    SELECT id, {fields['url']} as url, {fields['title']} as title, IFNULL({fields['tech_stack']}, '') as tech_stack, IFNULL({fields['status_code']},200) as status
                    FROM assets
                    WHERE IFNULL({fields['title']},'') <> '' AND ( {fields['status_code']} IN (200,401,403) OR {fields['status_code']} IS NULL )
                    ORDER BY id DESC LIMIT ?
                    """,
                    (limit,)
                )
                return [dict(r) for r in cur.fetchall()]
        except Exception as e:
            print(f"Error getting recent assets for CVE: {e}")
            return []

    def get_asset_by_id(self, asset_id: int) -> dict:
        try:
            f = self.get_asset_fields()
            with self._get_db() as db:
                r = db.execute(
                    f"SELECT id, {f['url']} as url, {f['title']} as title, {f['tech_stack']} as tech_stack FROM assets WHERE id=?",
                    (asset_id,)
                ).fetchone()
                return dict(r) if r else {}
        except Exception:
            return {}

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
                    VALUES (?, ?, ?)
                    """
        
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
                # Ensure activities table and columns exist; otherwise return zeros quietly
                try:
                    cols = {row[1] for row in db.execute('PRAGMA table_info(activities)').fetchall()}
                except Exception:
                    cols = set()
                if not cols or not {'timestamp', 'action', 'details'} <= cols:
                    return {'healthy_proxies': 0, 'total_proxies': 0, 'active_connections': 0}

                fields = self.get_activity_fields()
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
                return {'healthy_proxies': 0, 'total_proxies': 0, 'active_connections': 0}
        except Exception:
            return {'healthy_proxies': 0, 'total_proxies': 0, 'active_connections': 0}

    def get_scope_domains(self):
        """Get scope domains with schema tolerance (domain/is_active or target/is_wildcard)."""
        try:
            with self._get_db() as db:
                # Detect scope columns
                cols = {row[1] for row in db.execute("PRAGMA table_info(scope)").fetchall()}
                if not cols:
                    return []
                if 'domain' in cols:
                    # Prefer active domains if column exists (is_active or active); else return all
                    if 'is_active' in cols:
                        cursor = db.execute("SELECT domain FROM scope WHERE is_active = 1")
                    elif 'active' in cols:
                        cursor = db.execute("SELECT domain FROM scope WHERE active = 1")
                    else:
                        cursor = db.execute("SELECT domain FROM scope")
                    return [row[0] for row in cursor.fetchall()]
                elif 'target' in cols:
                    cursor = db.execute("SELECT target FROM scope")
                    return [row[0] for row in cursor.fetchall()]
                return []
        except Exception as e:
            print(f"Error getting scope domains: {e}")
            return []
    
    def get_scope_targets(self):
        """Get all scope targets for API (schema tolerant)."""
        try:
            run_scope_hosts = os.environ.get('MODSCAN_RUN_SCOPE_HOSTS')
            if run_scope_hosts:
                return [(None, host.strip(), 1) for host in run_scope_hosts.split(',') if host.strip()]

            with self._get_db() as db:
                cols = {row[1] for row in db.execute("PRAGMA table_info(scope)").fetchall()}
                targets = []
                if 'domain' in cols:
                    # Map 'is_active' or 'active' to the third tuple position
                    if 'is_active' in cols:
                        q = "SELECT id, domain, is_active FROM scope"
                    elif 'active' in cols:
                        q = "SELECT id, domain, active FROM scope"
                    else:
                        q = "SELECT id, domain, 1 as is_active FROM scope"
                    for row in db.execute(q).fetchall():
                        target_id, domain, is_active = row
                        targets.append((target_id, domain, is_active))
                elif 'target' in cols:
                    for row in db.execute("SELECT id, target, is_wildcard FROM scope").fetchall():
                        target_id, domain, is_wildcard = row
                        targets.append((target_id, domain, 1 if is_wildcard else 0))
                return targets
        except Exception as e:
            print(f"Error getting scope targets: {e}")
            return []
    
    def add_scope_target(self, domain, is_active=1):
        """Add a new scope target (handles both schema variants) with de-duplication.

        Returns the new row id if inserted, or None if it already existed or on error.
        """
        try:
            if not domain:
                return None
            domain = str(domain).strip().lstrip('.')
            if domain.startswith('*.'):
                domain = domain[2:]
            if not domain:
                return None

            with self._get_db() as db:
                cols = {row[1] for row in db.execute("PRAGMA table_info(scope)").fetchall()}
                cursor = None
                if 'domain' in cols:
                    if 'is_active' in cols:
                        cursor = db.execute(
                            "INSERT OR IGNORE INTO scope (domain, is_active) VALUES (?, ?)",
                            (domain, is_active)
                        )
                    elif 'active' in cols:
                        cursor = db.execute(
                            "INSERT OR IGNORE INTO scope (domain, active) VALUES (?, ?)",
                            (domain, is_active)
                        )
                    else:
                        cursor = db.execute(
                            "INSERT OR IGNORE INTO scope (domain) VALUES (?)",
                            (domain,)
                        )
                elif 'target' in cols:
                    cursor = db.execute(
                        "INSERT OR IGNORE INTO scope (target, is_wildcard) VALUES (?, 0)",
                        (domain,)
                    )
                else:
                    return None

                db.commit()

                # If INSERT OR IGNORE did not insert, rowcount will be 0 -> already exists
                if cursor and cursor.rowcount and cursor.lastrowid:
                    return cursor.lastrowid
                return None
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
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """
        
        values = (asset_id, vuln_type, severity, description, evidence, payload, confidence, detected_at)
        return query, values

    # --- Canonical vulnerability key support (universal, target-agnostic) ---
    def ensure_canonical_table(self):
        try:
            with self._get_db() as db:
                db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS vulnerability_canonical (
                        id INTEGER PRIMARY KEY,
                        type TEXT,
                        endpoint TEXT,
                        param TEXT,
                        location TEXT,
                        first_vuln_id INTEGER,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                db.execute("CREATE INDEX IF NOT EXISTS idx_vc_key ON vulnerability_canonical(type, endpoint, param, location)")
                db.execute("CREATE UNIQUE INDEX IF NOT EXISTS uniq_vc_key ON vulnerability_canonical(type, endpoint, param, location)")
        except Exception as e:
            print(f"Error ensuring canonical table: {e}")

    @staticmethod
    def _normalize_endpoint(url: str) -> str:
        try:
            from urllib.parse import urlparse
            p = urlparse(str(url or '').strip())
            # scheme://host/path (lower-cased host, strip trailing slash except root)
            path = p.path or '/'
            if len(path) > 1 and path.endswith('/'):
                path = path[:-1]
            host = (p.netloc or '').lower()
            scheme = (p.scheme or 'http').lower()
            return f"{scheme}://{host}{path}"
        except Exception:
            return str(url or '').strip()

    @staticmethod
    def _guess_location(finding_evidence: str, asset_url: str) -> str:
        ev = (finding_evidence or '').lower()
        url = (asset_url or '').lower()
        if 'header parameter' in ev:
            return 'header'
        if 'cookie parameter' in ev or 'set-cookie' in ev:
            return 'cookie'
        if 'body parameter' in ev or 'form field' in ev:
            return 'body'
        if '?' in url:
            return 'query'
        return 'path'

    @staticmethod
    def _extract_param_name(payload: str, evidence: str, asset_url: str) -> str:
        try:
            # 1) Header style: "X-Forwarded-For: value"
            if ':' in (payload or '') and (payload or '').split(':', 1)[0].strip().lower().startswith(('x-','true-','forwarded','content-','accept','client','host','origin','referer','user-agent','cookie')):
                return (payload or '').split(':', 1)[0].strip()
        except Exception:
            pass
        # 2) Prefer URL query param when present (most reliable)
        try:
            from urllib.parse import urlparse, parse_qsl
            qs = urlparse(asset_url or '').query
            params = [name for name, _ in parse_qsl(qs, keep_blank_values=True)]
            if params:
                # If payload mentions any of the URL params explicitly, pick that one
                lp = (payload or '').lower()
                for name in params:
                    if name.lower() in lp:
                        return name
                # Otherwise, choose the first URL param
                return params[0]
        except Exception:
            pass
        try:
            # 3) Evidence phrases like: "Header parameter X-Real-IP ..."
            if 'parameter ' in (evidence or ''):
                after = (evidence or '').split('parameter ', 1)[1].strip()
                # token up to space or affects
                token = after.split()[0].strip().strip(':').strip()
                if token:
                    return token
        except Exception:
            pass
        try:
            # 4) Payload with key=value pattern
            if '=' in (payload or ''):
                left = (payload or '').split('=', 1)[0]
                # Sometimes payload starts with key=..., or contains " account_id=..."
                candidate = left.strip().split()[-1] if left.strip() else left
                # Sanitize common noise like quotes or separators
                candidate = candidate.strip("'\";&:,{}[]()")
                if candidate:
                    return candidate
        except Exception:
            pass
        return ''

    def _compute_canonical_key(self, finding, asset_url: str):
        try:
            endpoint = self._normalize_endpoint(getattr(finding, 'url', '') or asset_url)
            ev = getattr(finding, 'evidence', '') or ''
            payload = getattr(finding, 'payload', '') or ''
            location = self._guess_location(ev, asset_url)
            param = self._extract_param_name(payload, ev, asset_url)
            vtype_raw = str(getattr(finding, 'vuln_type', '') or '').strip().lower()
            # Map to canonical class to reduce label noise
            def _canon_type(t:str)->str:
                t = (t or '').lower()
                if t in {'sql-injection','sql_injection','sqli','sql-injection-error'}: return 'sql_injection'
                if t in {'xss','xss_reflection','blind_xss','blind_xss_probe','dom_xss'}: return 'xss'
                if t in {'file_inclusion','lfi','rfi'}: return 'lfi'
                if t in {'cmd_injection','command_injection','rce','os_command_injection'}: return 'command_injection'
                if t in {'auth_bypass','authentication_bypass'}: return 'auth_bypass'
                if t in {'path_traversal','directory_traversal'}: return 'path_traversal'
                if t in {'open_redirect','redirect'}: return 'open_redirect'
                return t
            vtype = _canon_type(vtype_raw)
            # Return a tuple key used for dedup
            return (vtype, endpoint, (param or ''), (location or ''))
        except Exception:
            fallback = str(getattr(finding,'vuln_type','') or '').strip().lower()
            return (fallback, self._normalize_endpoint(asset_url or ''), '', '')

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

    def get_vulnerabilities(self, query=None, offset=0, size=100, sort=None, filters=None, *args, **kwargs):

        # Back-compat mapping: allow old calls like get_vulnerabilities(q, offset, size)

        if args:

            if len(args) >= 1 and query is None: query = args[0]

            if len(args) >= 2: offset = args[1]

            if len(args) >= 3: size = args[2]

        if isinstance(offset, str):

            try: offset = int(offset)

            except: offset = 0

        if isinstance(size, str):

            try: size = int(size)

            except: size = 100

        # Legacy alias some code paths may still reference
        filter_query = query
        """Get vulnerabilities using mapped field names"""
        try:
            with self._get_db() as db:
                # Simple query to get all vulnerabilities
                cursor = db.execute("""
                    SELECT v.*, a.url as asset_url, a.discovery_method as discovery_method,
                           CASE 
                               WHEN a.discovery_method = 'direct_scan' THEN 'direct'
                               WHEN a.discovery_method LIKE 'authenticated%' THEN 'authenticated'
                               ELSE 'engine'
                           END as source
                    FROM vulnerabilities v 
                    LEFT JOIN assets a ON v.asset_id = a.id 
                    ORDER BY v.detected_at DESC 
                    LIMIT ? OFFSET ?
                """, (size, offset))
                vulns = [dict(row) for row in cursor.fetchall()]
                
                # Get total count
                count_cursor = db.execute("SELECT COUNT(*) FROM vulnerabilities")
                total = count_cursor.fetchone()[0]
                
                return {
                    "vulnerabilities": vulns,
                    "total": total,
                    "page": (offset // size) + 1,
                    "per_page": size
                }
        except Exception as e:
            print(f"Error loading vulnerabilities: {e}")
            return {"vulnerabilities": [], "total": 0}

    def _should_skip_url(self, url):
        """Filter out noise URLs that shouldn't be added as assets."""
        if not url or not isinstance(url, str):
            return True
            
        # SAFETY: Validate URL format before processing
        if not self._is_valid_url_format(url):
            print(f"🚨 REJECTED CORRUPTED URL: {url[:100]}...")
            return True
            
        url_lower = url.lower()
        
        # Skip common noise patterns
        skip_patterns = [
            '/logout', '/signout', '/exit', '/quit',
            '/css/', '/js/', '/images/', '/img/', '/static/', '/assets/', '/fonts/', '/icons/',
            '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.ttf', '.eot',
            '&page=', '&p=', '&start=', '&offset=', '&limit=', '&size=',
            'javascript:', 'mailto:', 'tel:', 'ftp:', '#',
            '/wp-admin/', '/wp-content/', '/wp-includes/',
            '/admin/css/', '/admin/js/', '/admin/images/',
        ]
        
        for pattern in skip_patterns:
            if pattern in url_lower:
                return True
        
        # Skip URLs that are too long (likely have excessive parameters)
        if len(url) > 500:
            return True
            
        # Skip URLs with too many parameters (crawling explosion)
        if url.count('&') > 10 or url.count('=') > 10:
            return True
            
        return False

    def _is_valid_url_format(self, url):
        """SAFETY: Validate URL format to prevent corruption from causing scanner hangs."""
        try:
            import re
            from urllib.parse import urlparse
            
            # Basic format validation
            if not url.startswith(('http://', 'https://')):
                return False
                
            # Check for corruption patterns we've seen
            corruption_patterns = [
                r'M\d{4,}',  # Pattern like M11540, M115411
                r'[a-zA-Z]{10,}[A-Z]{2,}[a-zA-Z]{5,}',  # Patterns like rieilgakM115411
                r',\d+,\d+,\d+,active',  # Patterns like ,1,1813,0,active
                r'http://[^/]*http://',  # Double http://
                r'[^.]\.[^/]*\.[^/]*http://',  # Domain followed by http://
            ]
            
            for pattern in corruption_patterns:
                if re.search(pattern, url):
                    return False
                    
            # Parse URL to validate structure
            parsed = urlparse(url)
            if not parsed.netloc or not parsed.scheme:
                return False
                
            # Check domain format
            if not re.match(r'^[a-zA-Z0-9.-]+$', parsed.netloc.split(':')[0]):
                return False
                
            # Check for reasonable length
            if len(url) > 1000:
                return False
                
            return True
            
        except Exception as e:
            print(f"🚨 URL validation error for {url[:50]}: {e}")
            return False

    def add_asset(self, url, host, discovery_method):
        """Adds or updates an asset and RETURNS its ID (universal helper)."""
        try:
            # Filter out noise URLs
            if self._should_skip_url(url):
                return None
            with self._get_db() as db:
                # Use field mappings for database columns
                fields = self.get_asset_fields()

                # Check if asset already exists first
                check_query = f"SELECT {fields['id']} AS id FROM assets WHERE {fields['url']} = ?"
                existing = db.execute(check_query, (url,)).fetchone()

                asset_id = None

                if existing:
                    asset_id = existing["id"] if isinstance(existing, dict) or hasattr(existing, "keys") else existing[0]
                    # Update existing asset
                    update_query = f"""
                        UPDATE assets SET 
                            {fields['discovery_method']} = ?,
                            {fields['last_scanned']} = ?
                        WHERE {fields['url']} = ?
                    """
                    cursor = db.execute(update_query, (discovery_method, time.strftime('%Y-%m-%d %H:%M:%S'), url))
                else:
                    # Insert new asset with discovered_at timestamp
                    insert_query = f"""
                        INSERT INTO assets ({fields['url']}, {fields['host']}, {fields['discovery_method']}, {fields['last_scanned']}, discovered_at) 
                        VALUES (?, ?, ?, ?, ?)
                    """
                    cursor = db.execute(insert_query, (url, host, discovery_method, time.strftime('%Y-%m-%d %H:%M:%S'), time.strftime('%Y-%m-%d %H:%M:%S')))
                    asset_id = cursor.lastrowid

                db.commit()  # Explicitly commit the transaction

                # Log activity if new asset was actually added
                if cursor.rowcount > 0:
                    try:
                        from activity_logger import activity_logger
                        activity_logger.log_asset_discovered(url, discovery_method)
                    except Exception:
                        pass  # Don't fail asset addition if logging fails

                return asset_id

        except Exception as e:
            print(f"Error adding asset {url}: {e}")
            return None
    
    def add_assets_batch(self, url_list, discovery_method, batch_size=1000):
        """Add multiple assets efficiently with deduplication."""
        try:
            if not url_list:
                return []
                
            # Handle pre-validated assets (already have status codes, titles, etc.)
            processed_assets = []
            for url_data in url_list:
                if isinstance(url_data, dict) and url_data.get('validated'):
                    # Pre-validated asset with status code, title, etc.
                    processed_assets.append(url_data)
                else:
                    # Legacy URL-only format (fallback)
                    if isinstance(url_data, dict):
                        url = url_data.get('url')
                        host = url_data.get('host', '')
                    else:
                        url = str(url_data)
                        from urllib.parse import urlparse
                        host = urlparse(url).netloc
                    
                    # Normalize URL universally (dedup + fix malformed inputs)
                    try:
                        url = self.normalize_url(url)
                    except Exception:
                        url = str(url)
                    
                    if not self._should_skip_url(url):
                        processed_assets.append({'url': url, 'host': host})
            
            if not processed_assets:
                return []
                
            print(f"📊 Processing {len(processed_assets)} validated assets for database storage")
            
            added_ids = []
            with self._get_db() as db:
                fields = self.get_asset_fields()
                
                # Get existing URLs to avoid duplicates
                existing_urls = set()
                if processed_assets:
                    url_placeholders = ','.join('?' * len(processed_assets))
                    urls_only = [asset.get('url', asset) if isinstance(asset, dict) else asset for asset in processed_assets]
                    existing_query = f"SELECT {fields['url']} FROM assets WHERE {fields['url']} IN ({url_placeholders})"
                    existing_urls = set(row[0] for row in db.execute(existing_query, urls_only).fetchall())
                
                # Process in batches
                for i in range(0, len(processed_assets), batch_size):
                    batch = processed_assets[i:i+batch_size]
                    new_assets = [asset for asset in batch if asset.get('url') not in existing_urls]
                    
                    if new_assets:
                        # Handle pre-validated assets with rich data
                        if new_assets[0].get('validated'):
                            # Rich validated assets with status codes, titles, etc.
                            insert_query = f"""
                                INSERT INTO assets ({fields['url']}, {fields['host']}, {fields['discovery_method']}, 
                                                   {fields['status_code']}, {fields['title']}, {fields['tech_stack']},
                                                   {fields['content_length']}, {fields['last_scanned']}, discovered_at) 
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """
                            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                            insert_data = [
                                (asset['url'], asset['host'], discovery_method, 
                                 asset.get('status_code'), asset.get('title'), asset.get('tech_stack'),
                                 asset.get('content_length', 0), timestamp, timestamp)
                                for asset in new_assets
                            ]
                        else:
                            # Legacy URL-only format
                            insert_query = f"""
                                INSERT INTO assets ({fields['url']}, {fields['host']}, {fields['discovery_method']}, 
                                                   {fields['last_scanned']}, discovered_at) 
                                VALUES (?, ?, ?, ?, ?)
                            """
                            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                            insert_data = [
                                (asset.get('url'), asset.get('host'), discovery_method, timestamp, timestamp)
                                for asset in new_assets
                            ]
                        
                        db.executemany(insert_query, insert_data)
                        print(f"✅ Added {len(new_assets)} validated assets (batch {i//batch_size + 1})")

                        # CRITICAL DEBUG: Get the inserted row IDs
                        cursor = db.cursor()
                        for j, asset_data in enumerate(insert_data):
                            cursor.execute("SELECT last_insert_rowid()")
                            row_id = cursor.fetchone()[0] if j == 0 else None
                            if row_id:
                                added_ids.append(row_id)
                                print(f"🔍 DEBUG: Inserted asset with ID {row_id}: {asset_data[0]}")

                db.commit()
                print(f"🔍 DEBUG: Transaction committed. Added IDs: {added_ids}")

                # CRITICAL DEBUG: Verify assets are actually in database
                if added_ids:
                    verification_count = db.execute("SELECT COUNT(*) FROM assets WHERE id IN ({})".format(','.join('?' * len(added_ids))), added_ids).fetchone()[0]
                    print(f"🔍 DEBUG: Verification count after commit: {verification_count}")

                return added_ids
                
        except Exception as e:
            import traceback
            print(f"ERROR in batch asset addition: {e}")
            print(f"Exception type: {type(e).__name__}")
            traceback.print_exc()
            return []

    def get_assets(self, search_query='', page=1, per_page=25):
        """Retrieves assets from the database with search and pagination using field mappings."""
        try:
            with self._get_db() as db:
                offset = (page - 1) * per_page
                fields = self.get_asset_fields()
                
                # Base query
                base_query = "SELECT * FROM assets"
                conditions = []
                params = []

                # Handle special filters
                if search_query:
                    if ':' in search_query:
                        parts = search_query.split(':', 1)
                        field_name = parts[0].strip()
                        field_value = parts[1].strip()

                        if field_name == 'scanned' and field_value == 'true':
                            conditions.append(f"{fields['status_code']} IS NOT NULL")
                        elif field_name in fields:
                            conditions.append(f"{fields[field_name]} = ?")
                            params.append(field_value)
                        else:
                            # Fallback to generic search if field name is invalid
                            conditions.append(f"({self.field_mappings.get('url', 'url')} LIKE ? OR {self.field_mappings.get('title', 'title')} LIKE ? OR {self.field_mappings.get('tech_stack', 'tech_stack')} LIKE ? OR {self.field_mappings.get('discovery_method', 'discovery_method')} LIKE ?)")
                            params.extend([f"%{search_query}%", f"%{search_query}%", f"%{search_query}%", f"%{search_query}%"])
                    elif search_query == 'scanned:true':
                        conditions.append(f"{self.field_mappings.get('status_code', 'status_code')} IS NOT NULL")
                    elif search_query != '*':
                        conditions.append(f"({self.field_mappings.get('url', 'url')} LIKE ? OR {self.field_mappings.get('title', 'title')} LIKE ? OR {self.field_mappings.get('tech_stack', 'tech_stack')} LIKE ? OR {self.field_mappings.get('discovery_method', 'discovery_method')} LIKE ?)")
                        params.extend([f"%{search_query}%", f"%{search_query}%", f"%{search_query}%", f"%{search_query}%"])

                # Construct the final query
                if conditions:
                    query = f"{base_query} WHERE {' AND '.join(conditions)}"
                else:
                    query = base_query

                # Add ordering - prioritize newest discoveries first
                query += f"""
                    ORDER BY 
                        discovered_at DESC,
                        ({fields['status_code']} IS NOT NULL) DESC,
                        ({fields['screenshot_path']} IS NOT NULL) DESC,
                        ({fields['response_time']} IS NOT NULL) DESC,
                        ({fields['discovery_method']} != 'cert_transparency') DESC,
                        {fields['last_scanned']} DESC
                """

                # Get total count
                count_query = f"SELECT COUNT(*) FROM ({query}) as subquery"
                total_assets = db.execute(count_query, params).fetchone()[0]

                # Add pagination
                query += " LIMIT ? OFFSET ?"
                params.extend([per_page, offset])
                
                assets_cursor = db.execute(query, params)
                assets = [dict(row) for row in assets_cursor.fetchall()]
                
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
                new_today = db.execute(f"SELECT COUNT({fields['id']}) FROM assets WHERE date({fields['discovered_at']}) = date('now')").fetchone()[0]
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
                    WHERE {fields['status_code']} IN (200, 401, 403) 
                    AND (tech_stack IS NULL OR tech_stack = '' OR tech_stack = 'Unknown')
                    ORDER BY {fields['last_scanned']} DESC 
                    LIMIT ?
                '''
                cursor = db.execute(query, (limit,))
                return [{'id': row[0], 'url': row[1], 'status_code': row[2]} for row in cursor.fetchall()]
        except Exception as e:
            print(f"Error getting assets needing tech detection: {e}")
            return []

    def get_assets_ready_for_deep_scan(self, limit=75):
        """Universal selection for deep scanning.
        Priority order:
        1) Newly discovered, unscanned in-scope assets (status_code IS NULL, deep_scan_complete=0)
        2) Validated in-scope assets with any status_code that have NOT been deep scanned yet (deep_scan_complete=0)

        This function previously failed to filter by deep_scan_complete for validated assets,
        causing the same endpoints to be re-scanned every cycle. The filter has been added
        to ensure true progress and prevent infinite retesting loops.
        """
        try:
            with self._get_db() as db:
                fields = self.get_asset_fields()
                # CRITICAL FIX: Build in-scope filter using URL field instead of host field
                scope_domains = []
                try:
                    scope_domains = list(self.get_scope_domains() or [])
                except Exception:
                    scope_domains = []

                scope_clause = ""
                scope_params = []
                if scope_domains:
                    # Build OR conditions for each domain in URL field
                    or_parts = []
                    for d in scope_domains:
                        d = (d or "").strip().lower().lstrip('.')
                        if not d:
                            continue
                        # CRITICAL FIX: Use URL field with LIKE patterns for domain matching
                        or_parts.append(f"({fields['url']} LIKE ? OR {fields['url']} LIKE ? OR {fields['url']} LIKE ?)")
                        scope_params.extend([f"%://{d}%", f"%://{d}:%", f"%.{d}%"])
                    if or_parts:
                        scope_clause = " WHERE (" + " OR ".join(or_parts) + ")"

                # PRIORITY 1: Newly discovered in-scope assets
                base_new_query = f"""
                    SELECT {fields['id']}, {fields['url']}, {fields['status_code']}, {fields['tech_stack']}
                    FROM assets
                """
                where_new = f"{fields['status_code']} IS NULL"
                params_new = list(scope_params)
                if scope_clause:
                    # Inject additional AND after existing scope WHERE
                    new_assets_query = base_new_query + scope_clause + f" AND {where_new} " + f"ORDER BY {fields['discovered_at']} DESC LIMIT ?"
                else:
                    new_assets_query = base_new_query + f" WHERE {where_new} ORDER BY {fields['discovered_at']} DESC LIMIT ?"
                params_new.append(limit)

                cursor = db.execute(new_assets_query, tuple(params_new))
                new_assets = [{
                    'id': row[0], 'url': row[1], 'status_code': row[2], 'tech_stack': row[3] or ''
                } for row in cursor.fetchall()]
                
                # If we have enough new assets, return them immediately
                if len(new_assets) >= limit:
                    try:
                        print(f"🎯 Prioritizing {len(new_assets)} newly discovered in-scope assets for scanning")
                    except Exception:
                        pass
                    return new_assets
                
                # PRIORITY 2: Fill remaining slots with ANY assets that have a status code and aren't deep scanned yet
                remaining_limit = limit - len(new_assets)
                base_validated_query = f"""
                    SELECT {fields['id']}, {fields['url']}, {fields['status_code']}, {fields['tech_stack']}
                    FROM assets
                """
                # Only assets that have a status_code AND haven't been deep scanned yet
                where_valid = f"{fields['status_code']} IS NOT NULL AND (deep_scan_complete IS NULL OR deep_scan_complete = 0)"
                params_valid = list(scope_params)
                # CRITICAL FIX: TRUE ROUND-ROBIN - Equal quota per domain to ensure ALL targets get scanned
                # Instead of random selection that still favors large domains, get equal assets from each domain
                combined_assets = []
                assets_per_domain = max(1, remaining_limit // max(1, len(scope_domains))) if scope_domains else remaining_limit

                if scope_domains:
                    for domain in scope_domains:
                        domain_query = f"""
                            SELECT {fields['id']}, {fields['url']}, {fields['status_code']}, {fields['tech_stack']}
                            FROM assets
                            WHERE ({fields['url']} LIKE ? OR {fields['url']} LIKE ? OR {fields['url']} LIKE ?)
                            AND {where_valid}
                            ORDER BY CASE WHEN {fields['status_code']} = 200 THEN 1 WHEN {fields['status_code']} = 302 THEN 2 ELSE 3 END, RANDOM()
                            LIMIT ?
                        """
                        domain_params = [f"%://{domain}%", f"%://{domain}:%", f"%.{domain}%", assets_per_domain]
                        cursor = db.execute(domain_query, tuple(domain_params))
                        domain_assets = cursor.fetchall()
                        combined_assets.extend([{
                            'id': row[0], 'url': row[1], 'status_code': row[2], 'tech_stack': row[3] or ''
                        } for row in domain_assets])

                    # If we still need more assets, fill remaining slots randomly
                    if len(combined_assets) < remaining_limit:
                        remaining_slots = remaining_limit - len(combined_assets)
                        existing_ids = {asset['id'] for asset in combined_assets}

                        fill_query = base_validated_query + scope_clause + f" AND {where_valid} AND {fields['id']} NOT IN ({','.join('?' * len(existing_ids))}) ORDER BY RANDOM() LIMIT ?"
                        fill_params = list(scope_params) + list(existing_ids) + [remaining_slots]
                        cursor = db.execute(fill_query, tuple(fill_params))
                        fill_assets = cursor.fetchall()
                        combined_assets.extend([{
                            'id': row[0], 'url': row[1], 'status_code': row[2], 'tech_stack': row[3] or ''
                        } for row in fill_assets])

                    validated_assets = combined_assets
                else:
                    # Fallback to original query if no scope domains
                    validated_query = base_validated_query + f" WHERE {where_valid} ORDER BY CASE WHEN {fields['status_code']} = 200 THEN 1 WHEN {fields['status_code']} = 302 THEN 2 ELSE 3 END, RANDOM() LIMIT ?"
                    params_valid.append(remaining_limit)
                    cursor = db.execute(validated_query, tuple(params_valid))
                    validated_assets = [{
                        'id': row[0], 'url': row[1], 'status_code': row[2], 'tech_stack': row[3] or ''
                    } for row in cursor.fetchall()]
                
                combined_assets = new_assets + validated_assets
                try:
                    print(f"🎯 Selected {len(new_assets)} new + {len(validated_assets)} validated in-scope assets = {len(combined_assets)} total")
                except Exception:
                    pass
                return combined_assets
                
        except Exception as e:
            print(f"Error getting assets ready for deep scan: {e}")
            return []

    def get_unscanned_assets(self, limit=1000):
        """Get all assets that haven't been scanned yet (status_code is NULL)."""
        try:
            with self._get_db() as db:
                fields = self.get_asset_fields()
                query = f'''
                    SELECT {fields['id']}, {fields['url']}
                    FROM assets
                    WHERE {fields['status_code']} IS NULL
                    ORDER BY {fields['id']} DESC
                    LIMIT ?
                '''
                cursor = db.execute(query, (limit,))
                assets = [{'id': row[0], 'url': row[1]} for row in cursor.fetchall()]
                return assets
        except Exception as e:
            logger.error(f"Error getting unscanned assets: {e}")
            return []

    def get_assets_for_vulnerability_scan(self, limit=1000):
        """Get assets that are ready for vulnerability scanning (same as deep scan ready assets)."""
        try:
            # Reuse the existing deep scan logic since it's the same selection criteria
            return self.get_assets_ready_for_deep_scan(limit=limit)
        except Exception as e:
            logger.error(f"Error getting assets for vulnerability scan: {e}")
            return []

    def get_unscanned_assets_for_domain(self, domain, limit=100):
        """Get assets for a specific domain that have not been scanned yet (status_code is NULL)."""
        try:
            logger.info(f"Searching for unscanned assets in domain: {domain}")
            with self._get_db() as db:
                fields = self.get_asset_fields()
                query = f'''
                    SELECT {fields['id']}, {fields['url']}
                    FROM assets 
                    WHERE {fields['host']} = ? AND {fields['status_code']} IS NULL
                    ORDER BY {fields['id']} DESC
                    LIMIT ?
                '''
                cursor = db.execute(query, (domain, limit))
                assets = [{'id': row[0], 'url': row[1]} for row in cursor.fetchall()]
                logger.info(f"Found {len(assets)} unscanned assets.")
                return assets
        except Exception as e:
            logger.error(f"Error getting unscanned assets for domain: {e}")
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
        """AGGRESSIVE: Get ANY assets with 200/403 status that need screenshots - no dependencies"""
        try:
            with self._get_db() as db:
                fields = self.get_asset_fields()
                query = f'''
                    SELECT {fields['id']}, {fields['url']}, {fields['status_code']}
                    FROM assets 
                    WHERE {fields['status_code']} IN (200, 403)
                    AND ({fields['screenshot_path']} IS NULL OR {fields['screenshot_path']} = '' OR {fields['screenshot_path']} = 'NONE')
                    ORDER BY {fields['intelligence_score']} DESC, {fields['last_scanned']} ASC 
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

    def get_assets_by_state(self, state: str, limit: int = 100):
        """Retrieves assets from the database by state."""
        try:
            with self._get_db() as db:
                fields = self.get_asset_fields()
                query = f"SELECT * FROM assets WHERE state = ? ORDER BY {fields['id']} DESC LIMIT ?"
                cursor = db.execute(query, (state, limit))
                assets = [dict(row) for row in cursor.fetchall()]
                return assets
        except Exception as e:
            print(f"Error retrieving assets by state: {e}")
            return []

    def update_asset_state(self, asset_id: int, state: str):
        """Updates the state of an asset."""
        try:
            with self._get_db() as db:
                query = f"UPDATE assets SET state = ? WHERE id = ?"
                db.execute(query, (state, asset_id))
                db.commit()
                return True
        except Exception as e:
            print(f"Error updating asset state: {e}")
            return False

    def get_assets_with_missing_data(self, limit: int = 100):
        """Get assets that are missing critical data for intelligent completion"""
        try:
            with self._get_db() as db:
                fields = self.get_asset_fields()
                # Find assets missing status_code, title, or content_length
                query = f'''
                    SELECT {fields['id']}, {fields['url']}, {fields['status_code']}, 
                           {fields['title']}, {fields['content_length']}, {fields['tech_stack']}, {fields['last_scanned']}
                    FROM assets 
                    WHERE {fields['status_code']} IS NULL 
                       OR {fields['title']} IS NULL 
                       OR {fields['title']} = '' 
                       OR {fields['title']} = 'Unknown'
                       OR {fields['content_length']} IS NULL
                       OR {fields['tech_stack']} IS NULL
                       OR {fields['tech_stack']} = ''
                       OR {fields['tech_stack']} = '-'
                       OR (
                           {fields['last_scanned']} IS NULL OR 
                           datetime({fields['last_scanned']}) < datetime('now', '-2 minutes')
                       )
                    ORDER BY {fields['last_scanned']} ASC
                    LIMIT ?
                '''
                cursor = db.execute(query, (limit,))
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"Error getting assets with missing data: {e}")
            return []

    def get_asset_by_url(self, url: str):
        """Get a single asset by URL"""
        try:
            with self._get_db() as db:
                fields = self.get_asset_fields()
                query = f"SELECT * FROM assets WHERE {fields['url']} = ? LIMIT 1"
                cursor = db.execute(query, (url,))
                result = cursor.fetchone()
                return dict(result) if result else None
        except Exception as e:
            print(f"Error getting asset by URL: {e}")
            return None

    def get_asset_id_by_url(self, url: str) -> Optional[int]:
        """Get asset ID by URL for vulnerability linking"""
        try:
            with self._get_db() as db:
                fields = self.get_asset_fields()
                # Try exact match first
                cursor = db.execute(f"SELECT {fields['id']} FROM assets WHERE {fields['url']} = ? LIMIT 1", (url,))
                result = cursor.fetchone()
                if result:
                    return result[0]
                
                # Try base URL match (strip parameters)
                from urllib.parse import urlparse
                parsed = urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                cursor = db.execute(f"SELECT {fields['id']} FROM assets WHERE {fields['url']} = ? LIMIT 1", (base_url,))
                result = cursor.fetchone()
                if result:
                    return result[0]
                
                # Create asset if not found
                logger.info(f"Creating new asset for vulnerability: {url}")
                asset_id = self.add_asset(
                    url=url,
                    host=parsed.netloc,
                    status_code=0,
                    tech_stack='',
                    discovered_at=None,
                    force=True
                )
                return asset_id
        except Exception as e:
            logger.error(f"Error getting asset ID by URL {url}: {e}")
            return None

    def update_asset_fields(self, asset_id: int, update_fields: dict):
        """Update multiple fields for an asset"""
        try:
            if not update_fields:
                return True
                
            with self._get_db() as db:
                fields = self.get_asset_fields()
                
                # Build UPDATE query with field mappings
                set_clauses = []
                values = []
                
                for field_key, value in update_fields.items():
                    if field_key in fields:
                        db_field = fields[field_key]
                        set_clauses.append(f"{db_field} = ?")
                        values.append(value)
                
                if not set_clauses:
                    return True
                    
                query = f"UPDATE assets SET {', '.join(set_clauses)} WHERE {fields['id']} = ?"
                values.append(asset_id)
                
                db.execute(query, values)
                db.commit()
                return True
        except Exception as e:
            print(f"Error updating asset fields: {e}")
            return False

    def get_asset_by_id(self, asset_id: int):
        """Get a single asset by ID"""
        try:
            with self._get_db() as db:
                fields = self.get_asset_fields()
                query = f"SELECT * FROM assets WHERE {fields['id']} = ? LIMIT 1"
                cursor = db.execute(query, (asset_id,))
                result = cursor.fetchone()
                return dict(result) if result else None
        except Exception as e:
            print(f"Error getting asset by ID: {e}")
            return None

    def increment_completion_attempts(self, asset_id: int):
        """Increment the completion attempts for an asset."""
        try:
            with self._get_db() as db:
                db.execute("UPDATE assets SET completion_attempts = completion_attempts + 1 WHERE id = ?", (asset_id,))
                db.commit()
        except Exception as e:
            print(f"Error incrementing completion attempts: {e}")

    def get_asset_by_id(self, asset_id: int):
        """Get a single asset by ID"""
        try:
            with self._get_db() as db:
                fields = self.get_asset_fields()
                query = f"SELECT * FROM assets WHERE {fields['id']} = ? LIMIT 1"
                cursor = db.execute(query, (asset_id,))
                result = cursor.fetchone()
                return dict(result) if result else None
        except Exception as e:
            print(f"Error getting asset by ID: {e}")
            return None

    def increment_completion_attempts(self, asset_id: int):
        """Increment the completion attempts for an asset."""
        try:
            with self._get_db() as db:
                db.execute("UPDATE assets SET completion_attempts = completion_attempts + 1 WHERE id = ?", (asset_id,))
                db.commit()
        except Exception as e:
            print(f"Error incrementing completion attempts: {e}")

    def get_stuck_assets(self, hours_threshold: int = 1):
        """Get assets that have been stuck without progression for specified hours"""
        try:
            with self._get_db() as db:
                fields = self.get_asset_fields()
                # Find assets that were discovered but haven't been updated recently
                # and are missing critical data indicating they're stuck
                query = f'''
                    SELECT {fields['id']}, {fields['url']}, {fields['status_code']}, 
                           {fields['title']}, {fields['discovered_at']}
                    FROM assets 
                    WHERE ({fields['status_code']} IS NULL 
                           OR {fields['title']} IS NULL 
                           OR {fields['title']} = '' 
                           OR {fields['title']} = 'Unknown')
                      AND datetime({fields['discovered_at']}) < datetime('now', '-{hours_threshold} hours')
                    ORDER BY {fields['discovered_at']} ASC
                    LIMIT 50
                '''
                cursor = db.execute(query)
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"Error getting stuck assets: {e}")
            return []

    def get_assets_by_tier_status(self):
        """Get assets grouped by their current tier for intelligent progression"""
        try:
            with self._get_db() as db:
                fields = self.get_asset_fields()
                
                # Query assets with their tier information
                query = f'''
                    SELECT {fields['id']}, {fields['url']}, {fields['status_code']}, 
                           {fields['title']}, tier_attempted, scan_stage, {fields['discovered_at']}
                    FROM assets 
                    ORDER BY tier_attempted ASC, {fields['discovered_at']} ASC
                '''
                cursor = db.execute(query)
                results = [dict(row) for row in cursor.fetchall()]
                
                # Group by tier
                assets_by_tier = {}
                for asset in results:
                    tier = asset.get('tier_attempted', 0) or 0
                    if tier not in assets_by_tier:
                        assets_by_tier[tier] = []
                    assets_by_tier[tier].append(asset)
                
                return assets_by_tier
                
        except Exception as e:
            print(f"Error getting assets by tier status: {e}")
            return {}

    def get_vulnerabilities_by_category(self, category='all', search_query='', offset=0, limit=25):
        """Get vulnerabilities by category with pagination"""
        try:
            with self._get_db() as db:
                # Base query
                base_query = '''
                    SELECT v.id, v.asset_id, v.type, v.description, v.severity,
                           v.evidence, v.payload, v.detected_at, v.confidence,
                           a.url as asset_url, a.host as asset_host,
                           a.discovery_method as discovery_method,
                           CASE 
                               WHEN a.discovery_method = 'direct_scan' THEN 'direct'
                               WHEN a.discovery_method LIKE 'authenticated%' THEN 'authenticated'
                               ELSE 'engine'
                           END as source,
                           lv.method as verification_method,
                           lv.marker as verification_marker,
                           lv.details as verification_details
                    FROM vulnerabilities v
                    JOIN assets a ON v.asset_id = a.id
                    LEFT JOIN (
                        SELECT vv.vulnerability_id, vv.method, vv.marker, vv.details
                        FROM vulnerability_verifications vv
                        JOIN (
                            SELECT vulnerability_id, MAX(id) as max_id
                            FROM vulnerability_verifications
                            GROUP BY vulnerability_id
                        ) latest ON latest.vulnerability_id = vv.vulnerability_id AND latest.max_id = vv.id
                    ) lv ON lv.vulnerability_id = v.id
                '''
                
                conditions = []
                params = []
                
                # Filter by category
                if category != 'all':
                    conditions.append("v.type = ?")
                    params.append(category)
                
                # Filter by search query
                if search_query:
                    conditions.append("(a.url LIKE ? OR v.description LIKE ? OR v.type LIKE ?)")
                    search_param = f"%{search_query}%"
                    params.extend([search_param, search_param, search_param])
                
                # Build final query
                if conditions:
                    query = base_query + " WHERE " + " AND ".join(conditions)
                else:
                    query = base_query
                
                # Get total count
                count_query = f"SELECT COUNT(*) FROM ({query}) as subquery"
                total = db.execute(count_query, params).fetchone()[0]
                
                # Add ordering and pagination
                query += " ORDER BY v.detected_at DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])
                
                cursor = db.execute(query, params)
                vulnerabilities = [dict(row) for row in cursor.fetchall()]
                
                return {
                    "vulnerabilities": vulnerabilities,
                    "total": total,
                    "page": (offset // limit) + 1,
                    "per_page": limit
                }
                
        except Exception as e:
            print(f"Error getting vulnerabilities by category: {e}")
            return {"vulnerabilities": [], "total": 0, "page": 1, "per_page": limit}

    def get_vulnerability_categories(self):
        """Get vulnerability categories with counts"""
        try:
            with self._get_db() as db:
                query = '''
                    SELECT v.type, v.severity, COUNT(*) as count
                    FROM vulnerabilities v
                    GROUP BY v.type, v.severity
                    ORDER BY count DESC, v.severity DESC
                '''
                cursor = db.execute(query)
                results = cursor.fetchall()
                
                categories = []
                for row in results:
                    categories.append({
                        "name": row[0],
                        "severity": row[1],
                        "count": row[2]
                    })
                
                return categories
                
        except Exception as e:
            print(f"Error getting vulnerability categories: {e}")
            return []

    def has_vulnerability_test_been_conducted(self, url: str, vuln_type: str, payload: str = None) -> bool:
        """
        Check if a specific vulnerability test has already been conducted on a URL.
        This prevents duplicate testing of the same vulnerability type + payload combination.

        Args:
            url: The target URL
            vuln_type: The vulnerability type (e.g., 'SQL_INJECTION', 'XSS')
            payload: Optional specific payload (for more granular deduplication)

        Returns:
            True if the test has already been conducted, False otherwise
        """
        try:
            # Global bypass for full re-test runs
            try:
                import os as _os
                if str(_os.environ.get('MODSCAN_FORCE_RETEST', '0')).lower() in ('1','true','yes','on'):
                    return False
            except Exception:
                pass
            # Ensure auxiliary table exists
            self._ensure_vuln_test_history_table()

            with self._get_db() as db:
                # Normalize URL for comparison (remove query params and fragments for base comparison)
                from urllib.parse import urlparse
                parsed = urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                # 1) Positive finding dedupe (strongest) — if we've found this vuln type already on this endpoint
                if payload:
                    q1 = """
                        SELECT COUNT(*) FROM vulnerabilities v
                        JOIN assets a ON v.asset_id = a.id
                        WHERE v.type = ? AND v.payload = ?
                        AND (a.url LIKE ? OR a.url = ?)
                    """
                    c1 = db.execute(q1, (vuln_type, payload, f"{base_url}%", url)).fetchone()[0]
                else:
                    q1 = """
                        SELECT COUNT(*) FROM vulnerabilities v
                        JOIN assets a ON v.asset_id = a.id
                        WHERE v.type = ?
                        AND (a.url LIKE ? OR a.url = ?)
                    """
                    c1 = db.execute(q1, (vuln_type, f"{base_url}%", url)).fetchone()[0]
                if c1 > 0:
                    print(f"⚡ SKIP: {vuln_type} already tested on {base_url} ({c1} existing findings)")
                    return True

                # 2) Recent test-history dedupe (prevents re-testing when no vuln found)
                # TTL defaults to 120 minutes unless overridden via env MODSCAN_TEST_TTL_MIN
                import os as _os
                try:
                    ttl_min = int(_os.environ.get('MODSCAN_TEST_TTL_MIN', '120'))
                except Exception:
                    ttl_min = 120
                q2 = """
                    SELECT COUNT(*) FROM vulnerability_test_history
                    WHERE vuln_type = ?
                    AND (base_url = ? OR full_url = ?)
                    AND tested_at > datetime('now', ?)
                """
                since = f"-{ttl_min} minutes"
                c2 = db.execute(q2, (vuln_type, base_url, url, since)).fetchone()[0]
                if c2 > 0:
                    print(f"⚡ SKIP: {vuln_type} recently tested on {base_url} (<= {ttl_min} min)")
                    return True

                return False

        except Exception as e:
            print(f"Error checking vulnerability test history: {e}")
            # On error, don't skip the test (fail safe)
            return False

    def _ensure_vuln_test_history_table(self):
        """Create vulnerability_test_history table if missing (universal test dedupe)."""
        try:
            with self._get_db() as db:
                db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS vulnerability_test_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        base_url TEXT,
                        full_url TEXT,
                        vuln_type TEXT,
                        payload TEXT,
                        result TEXT,
                        tested_at TEXT
                    )
                    """
                )
                db.execute("CREATE INDEX IF NOT EXISTS idx_vth_base ON vulnerability_test_history(base_url, vuln_type, tested_at)")
        except Exception:
            pass

    def record_vulnerability_test(self, url: str, vuln_type: str, payload: str = None, result: str = "unknown"):
        """Record that a vulnerability test was conducted. Universal, target-agnostic dedupe.

        Args:
            url: Target URL
            vuln_type: "SQL_INJECTION", "XSS", etc.
            payload: Optional payload string
            result: Optional result marker (e.g., "found", "not_found", "unknown")
        """
        try:
            self._ensure_vuln_test_history_table()
            from urllib.parse import urlparse
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            with self._get_db() as db:
                db.execute(
                    """
                    INSERT INTO vulnerability_test_history(base_url, full_url, vuln_type, payload, result, tested_at)
                    VALUES(?,?,?,?,?,datetime('now'))
                    """,
                    (base_url, url, vuln_type, payload or '', result or 'unknown')
                )
        except Exception as e:
            print(f"Warning: failed to record test for {vuln_type} on {url}: {e}")

    def has_vulnerability_been_found_on_endpoint(self, url: str, vuln_type: str) -> bool:
        """
        Check if we've already FOUND a vulnerability of this type on this endpoint.
        For bug bounty efficiency: once you find ANY vuln on an endpoint, move on!

        Args:
            url: The target URL
            vuln_type: The vulnerability type (e.g., 'SQL_INJECTION', 'XSS')

        Returns:
            True if we've already found this vuln type on this endpoint, False otherwise
        """
        try:
            # Global bypass for full re-test runs
            try:
                import os as _os
                if str(_os.environ.get('MODSCAN_FORCE_RETEST', '0')).lower() in ('1','true','yes','on'):
                    return False
            except Exception:
                pass
            with self._get_db() as db:
                # Normalize URL for comparison
                from urllib.parse import urlparse
                parsed = urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                # Check if we've FOUND (not just tested) vulnerabilities of this type
                check_query = """
                    SELECT COUNT(*) FROM vulnerabilities v
                    JOIN assets a ON v.asset_id = a.id
                    WHERE v.type = ?
                    AND (a.url LIKE ? OR a.url = ?)
                    AND (v.confidence > 0.7 OR v.severity IN ('Critical', 'High'))
                """
                cursor = db.execute(check_query, (vuln_type, f"{base_url}%", url))
                count = cursor.fetchone()[0]

                if count > 0:
                    print(f"💰 BUG BOUNTY SKIP: {vuln_type} already found on {base_url} - move on to maximize earnings!")
                    return True

                return False

        except Exception as e:
            print(f"Error checking vulnerability found history: {e}")
            return False

    def _generate_canonical_vuln_key(self, finding: VulnerabilityFinding, asset_url: str = None) -> str:
        """
        Generate canonical vulnerability key for database-level deduplication.
        Format aligned with vulnerability_canonical: canonical_type|endpoint|param|location
        - canonical_type normalizes label variants (e.g., file_inclusion -> lfi)
        - endpoint is scheme://host/path (no query)
        - location is one of: query|body|header|cookie|path
        """
        try:
            vtype, endpoint, param, location = self._compute_canonical_key(finding, getattr(finding, 'url', '') or (asset_url or ''))
            return f"{vtype}|{endpoint}|{param}|{location}"
        except Exception:
            # Fallback to a minimal but stable key
            from urllib.parse import urlparse
            u = getattr(finding, 'url', '') or (asset_url or '')
            try:
                p = urlparse(u)
                ep = f"{p.scheme}://{p.netloc}{p.path}" if p.netloc else (u or '')
            except Exception:
                ep = u or ''
            vt = str(getattr(finding, 'vuln_type', '') or '').strip().lower()
            return f"{vt}|{ep}||"

    def add_vulnerability_finding(self, finding: VulnerabilityFinding, asset_id: int):
        """
        Add a VulnerabilityFinding object to the database with proper field mapping.
        This is the AUTHORITATIVE method for storing vulnerability findings.
        Prevents duplicates based on asset_id + type + payload combination.
        """
        try:
            with self._get_db() as db:
                # Persistence policy
                persistence = (CONFIG.get('persistence') or {}) if isinstance(CONFIG, dict) else {}
                min_conf = float(persistence.get('min_confidence', 0.0))
                suppress_infra = bool(persistence.get('suppress_infra', False))
                allow_upgrade = bool(persistence.get('allow_upgrade_duplicates', True))

                # Optional suppression of infrastructure findings
                if suppress_infra:
                    infra_types = { 'weak-cipher-suites', 'insecure_transport', 'Missing Security Header' }
                    if str(getattr(finding, 'vuln_type', '')).strip() in infra_types:
                        return None

                # Optional minimum confidence gate
                if getattr(finding, 'confidence', 0.0) < min_conf:
                    return None

                # Generate canonical key for deduplication
                asset_url = db.execute("SELECT url FROM assets WHERE id = ?", (asset_id,)).fetchone()
                asset_url = asset_url[0] if asset_url else ""
                canonical_key = self._generate_canonical_vuln_key(finding, asset_url)

                # Check for existing duplicate (canonical key-based)
                duplicate_check = '''
                    SELECT COUNT(*) FROM vulnerabilities
                    WHERE canonical_key = ?
                '''
                cursor = db.execute(duplicate_check, (canonical_key,))
                
                if cursor.fetchone()[0] > 0:
                    # Allow upgrading existing row if new finding is stronger
                    if allow_upgrade:
                        row = db.execute(
                            "SELECT id, severity, confidence FROM vulnerabilities WHERE canonical_key=? ORDER BY id DESC LIMIT 1",
                            (canonical_key,)
                        ).fetchone()
                        if row:
                            vid, sev_old, conf_old = row[0], str(row[1] or ''), float(row[2] or 0.0)
                            def sev_rank(s:str)->int:
                                m = {'info':0,'low':1,'medium':2,'high':3,'critical':4}
                                return m.get(str(s or '').lower(), 0)
                            if sev_rank(finding.severity) > sev_rank(sev_old) or float(finding.confidence or 0.0) > conf_old:
                                # Normalize values then update
                                def _s(x):
                                    try:
                                        if x is None: return ''
                                        if isinstance(x,(str,bytes)): return x if isinstance(x,str) else x.decode('utf-8','ignore')
                                        if isinstance(x,(dict,list,tuple)): return json.dumps(x, ensure_ascii=False)[:100000]
                                        return str(x)
                                    except Exception:
                                        return ''
                                ts = finding.discovered_at.isoformat() if isinstance(finding.discovered_at, datetime) else _s(finding.discovered_at)
                                db.execute(
                                    """
                                    UPDATE vulnerabilities SET description=?, severity=?, evidence=?, detected_at=?, confidence=?
                                    WHERE id=?
                                    """,
                                    (
                                        _s(finding.impact_description or finding.evidence),
                                        _s(finding.severity),
                                        _s(finding.evidence),
                                        ts,
                                        float(finding.confidence or 0.0),
                                        int(vid)
                                    )
                                )
                                db.commit()
                                print(f"🔁 Upgraded existing vulnerability {vid}: {finding.vuln_type}")
                                return vid
                    # Otherwise skip duplicate
                    print(f"🔄 Deduplication: Skipping duplicate {finding.vuln_type} (payload: '{finding.payload[:50]}...') for asset {asset_id}")
                    return
                
                # Canonical dedup across assets: type + endpoint + param + location
                try:
                    self.ensure_canonical_table()
                    vtype, endpoint, param, location = self._compute_canonical_key(finding, getattr(finding, 'url', '') or '')
                    # If we already have a canonical entry for this key, skip inserting new vuln row
                    c = db.execute(
                        "SELECT first_vuln_id FROM vulnerability_canonical WHERE type=? AND endpoint=? AND param=? AND location=?",
                        (vtype, endpoint, param, location)
                    ).fetchone()
                    if c is not None:
                        print(f"💰 Canonical skip: {vtype} at {endpoint} [{location}:{param or '-'}]")
                        return c[0]
                except Exception:
                    pass
                # Additional de-dupe: same type+URL+evidence prefix
                try:
                    dupe2 = db.execute(
                        """
                        SELECT COUNT(*) FROM vulnerabilities
                        WHERE asset_id=? AND type=?
                          AND substr(evidence,1,80)=substr(?,1,80)
                        """,
                        (asset_id, finding.vuln_type, finding.evidence)
                    ).fetchone()[0]
                    if dupe2 and dupe2 > 0:
                        print(f"🔄 Skipping near-duplicate: {finding.vuln_type} at {finding.url}")
                        return
                except Exception:
                    pass
                
                # Insert new vulnerability with canonical_key for deduplication
                query = '''
                    INSERT INTO vulnerabilities
                    (asset_id, type, description, severity, evidence, payload, detected_at, confidence, canonical_key)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                '''
                # Normalize types for SQLite binding
                def _s(x):
                    try:
                        if x is None:
                            return ''
                        if isinstance(x, (str, bytes)):
                            return x if isinstance(x, str) else x.decode('utf-8', 'ignore')
                        # Dataclass or dict to JSON
                        if isinstance(x, (dict, list, tuple)):
                            return json.dumps(x, ensure_ascii=False)[:100000]
                        return str(x)
                    except Exception:
                        return ''
                ts = finding.discovered_at.isoformat() if isinstance(finding.discovered_at, datetime) else _s(finding.discovered_at)
                cur = db.execute(query, (
                    int(asset_id or 0),
                    _s(finding.vuln_type),
                    _s(finding.impact_description or finding.evidence),
                    _s(finding.severity),
                    _s(finding.evidence),
                    _s(finding.payload),
                    ts,
                    float(finding.confidence or 0.0),
                    canonical_key
                ))
                vuln_id = cur.lastrowid
                # Record canonical key for future dedup
                try:
                    vtype, endpoint, param, location = self._compute_canonical_key(finding, getattr(finding, 'url', '') or '')
                    db.execute(
                        "INSERT OR IGNORE INTO vulnerability_canonical(type, endpoint, param, location, first_vuln_id) VALUES(?,?,?,?,?)",
                        (vtype, endpoint, param, location, int(vuln_id))
                    )
                except Exception:
                    pass
                print(f"✅ Added vulnerability: {finding.vuln_type} ({finding.severity}) for asset {asset_id}")
                try:
                    # Opportunistic structured verification logging from evidence
                    self._maybe_store_verification_from_evidence(vuln_id, finding)
                except Exception:
                    pass
                return vuln_id
        except Exception as e:
            try:
                # Detailed diagnostics to pinpoint bad parameter types
                dbg = {
                    'asset_id': type(asset_id).__name__,
                    'vuln_type': type(getattr(finding, 'vuln_type', None)).name if hasattr(type(getattr(finding,'vuln_type',None)), 'name') else str(type(getattr(finding,'vuln_type',None))),
                    'impact_description': type(getattr(finding, 'impact_description', None)).__name__ if hasattr(type(getattr(finding,'impact_description',None)), '__name__') else str(type(getattr(finding,'impact_description',None))),
                    'severity': type(getattr(finding, 'severity', None)).__name__ if hasattr(type(getattr(finding,'severity',None)), '__name__') else str(type(getattr(finding,'severity',None))),
                    'evidence': type(getattr(finding, 'evidence', None)).__name__ if hasattr(type(getattr(finding,'evidence',None)), '__name__') else str(type(getattr(finding,'evidence',None))),
                    'payload': type(getattr(finding, 'payload', None)).__name__ if hasattr(type(getattr(finding,'payload',None)), '__name__') else str(type(getattr(finding,'payload',None))),
                    'detected_at': type(getattr(finding, 'discovered_at', None)).__name__ if hasattr(type(getattr(finding,'discovered_at',None)), '__name__') else str(type(getattr(finding,'discovered_at',None))),
                    'confidence': type(getattr(finding, 'confidence', None)).__name__ if hasattr(type(getattr(finding,'confidence',None)), '__name__') else str(type(getattr(finding,'confidence',None))),
                    'asset_url': type(getattr(finding, 'url', None)).__name__ if hasattr(type(getattr(finding,'url',None)), '__name__') else str(type(getattr(finding,'url',None))),
                }
                print(f"Error adding vulnerability finding: {e} | param types: {dbg}")
            except Exception:
                print(f"Error adding vulnerability finding: {e}")
            return None

    def should_test_param(self, url: str, vuln_type: str, param: str = '', location: str = '') -> bool:
        """Return False if a canonical finding already exists for type+endpoint+param+location.
        Keeps scanning universal while avoiding redundant payload variation tests.
        """
        try:
            # Global bypass for full re-test runs
            try:
                import os as _os
                if str(_os.environ.get('MODSCAN_FORCE_RETEST', '0')).lower() in ('1','true','yes','on'):
                    return True
            except Exception:
                pass
            self.ensure_canonical_table()
            endpoint = self._normalize_endpoint(url)
            # Canonicalize vuln type similar to storage logic
            def _canon_type(t:str)->str:
                t = (t or '').lower()
                if t in {'sql-injection','sql_injection','sqli','sql-injection-error'}: return 'sql_injection'
                if t in {'xss','xss_reflection','blind_xss','blind_xss_probe','dom_xss'}: return 'xss'
                if t in {'file_inclusion','lfi','rfi'}: return 'lfi'
                if t in {'cmd_injection','command_injection','rce','os_command_injection'}: return 'command_injection'
                if t in {'auth_bypass','authentication_bypass'}: return 'auth_bypass'
                if t in {'path_traversal','directory_traversal'}: return 'path_traversal'
                if t in {'open_redirect','redirect'}: return 'open_redirect'
                return t
            vtype = _canon_type(vuln_type)
            # Default unknown location to 'query' if URL has query
            if not location:
                location = 'query' if '?' in (url or '') else 'path'
            with self._get_db() as db:
                row = db.execute(
                    "SELECT 1 FROM vulnerability_canonical WHERE type=? AND endpoint=? AND param=? AND location=? LIMIT 1",
                    (vtype, endpoint, param or '', location or '')
                ).fetchone()
            return row is None
        except Exception:
            # Fail open to keep scanning universal
            return True

    def ensure_verification_table(self):
        try:
            with self._get_db() as db:
                db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS vulnerability_verifications (
                        id INTEGER PRIMARY KEY,
                        vulnerability_id INTEGER,
                        method TEXT,
                        marker TEXT,
                        details TEXT,
                        screenshot_path TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        oob_event_id TEXT
                    )
                    """
                )
        except Exception as e:
            print(f"Error ensuring verification table: {e}")

    def add_verification_record(self, vulnerability_id: int, method: str, marker: str = "", details: str = "", screenshot_path: str = "", oob_event_id: str = ""):
        import time
        self.ensure_verification_table()
        attempts = 0
        last_err = None
        while attempts < 10:
            try:
                with self._get_db() as db:
                    db.execute(
                        """
                        INSERT INTO vulnerability_verifications (vulnerability_id, method, marker, details, screenshot_path, oob_event_id)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (vulnerability_id, method, marker, details, screenshot_path, oob_event_id)
                    )
                return
            except Exception as e:
                last_err = e
                # Retry on transient locking
                if 'locked' in str(e).lower():
                    # Exponential backoff with cap ~1.2s
                    delay = min(1.2, 0.12 * (2 ** attempts))
                    time.sleep(delay)
                    attempts += 1
                    continue
                break
        print(f"Error adding verification record: {last_err}")

    def _maybe_store_verification_from_evidence(self, vulnerability_id: int, finding: VulnerabilityFinding):
        try:
            ev = finding.evidence or ""
            if "Verification:" not in ev:
                return
            # Extract method after 'Verification:' up to '|' or end
            method = ev.split("Verification:", 1)[1].strip()
            if '|' in method:
                method = method.split('|', 1)[0].strip()
            # Try to extract marker token text
            marker = ""
            for token in ["marker", "Marker", "MODSCAN", "XSS_", "CMD_", "SSRF_"]:
                if token in ev:
                    # crude capture
                    try:
                        part = ev.split(token, 1)[1]
                        marker = token + part.split()[0]
                        break
                    except Exception:
                        continue
            self.add_verification_record(
                vulnerability_id,
                method=method,
                marker=marker,
                details=ev[:500],
                screenshot_path=getattr(finding, 'screenshot_path', '') or ''
            )
        except Exception:
            pass
    
    def add_vulnerability(self, vuln_data: dict):
        """
        DEPRECATED: Use add_vulnerability_finding() with VulnerabilityFinding objects instead.
        Legacy method for backward compatibility with duplicate prevention.
        """
        try:
            with self._get_db() as db:
                # Check for existing duplicate
                duplicate_check = '''
                    SELECT COUNT(*) FROM vulnerabilities 
                    WHERE asset_id = ? AND type = ? AND payload = ?
                '''
                cursor = db.execute(duplicate_check, (
                    vuln_data['asset_id'],
                    vuln_data['type'],
                    vuln_data.get('payload', '')
                ))
                
                if cursor.fetchone()[0] > 0:
                    print(f"🔄 Skipping duplicate vulnerability: {vuln_data['type']} with payload '{vuln_data.get('payload', '')}' for asset {vuln_data['asset_id']}")
                    return
                
                # Insert new vulnerability
                query = '''
                    INSERT INTO vulnerabilities 
                    (asset_id, type, description, severity, evidence, payload, detected_at, confidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                '''
                db.execute(query, (
                    vuln_data['asset_id'],
                    vuln_data['type'], 
                    vuln_data['description'],
                    vuln_data['severity'],
                    vuln_data['evidence'],
                    vuln_data.get('payload', ''),
                    vuln_data['detected_at'],
                    vuln_data.get('confidence', 0.5)
                ))
                print(f"✅ Added vulnerability: {vuln_data['type']} for asset {vuln_data['asset_id']}")
        except Exception as e:
            print(f"Error adding vulnerability: {e}")

# --- Safe post-init base_dir shim (non-destructive) ---
try:
    _AM_ORIG_INIT = AssetManager.__init__
except Exception:
    _AM_ORIG_INIT = None

if _AM_ORIG_INIT is not None:
    def __asset_manager_init_shim__(self, *args, **kwargs):
        _AM_ORIG_INIT(self, *args, **kwargs)
        import os
        if not getattr(self, "base_dir", None):
            self.base_dir = os.environ.get("MODSCAN_BASE_DIR", "./data")
        try:
            os.makedirs(self.base_dir, exist_ok=True)
        except Exception:
            pass
    AssetManager.__init__ = __asset_manager_init_shim__
# --- end shim ---

# --- Compat shim: add helpers if older AssetManager lacks them ---
try:
    from types import MethodType
except Exception:
    MethodType = None  # very old Pythons; not expected

def _am_get_recent_discoveries(self, minutes: int = 5):
    """
    Return assets discovered in the last N minutes.
    Falls back to last_scanned if discovered_at isn't present.
    """
    try:
        with self._get_db() as db:
            # Prefer discovered_at if present; else fallback to last_scanned
            use_discovered = False
            try:
                db.execute("SELECT discovered_at FROM assets LIMIT 1")
                use_discovered = True
            except Exception:
                use_discovered = False

            if use_discovered:
                query = f"""
                    SELECT * FROM assets
                    WHERE discovered_at > datetime('now', '-{int(minutes)} minutes')
                    ORDER BY discovered_at DESC
                """
            else:
                # fallback using mapped field names
                fields = self.get_asset_fields()
                query = f"""
                    SELECT * FROM assets
                    WHERE {fields['last_scanned']} > datetime('now', '-{int(minutes)} minutes')
                    ORDER BY {fields['last_scanned']} DESC
                """
            cur = db.execute(query)
            return [dict(row) for row in cur.fetchall()]
    except Exception as e:
        print(f"get_recent_discoveries error: {e}")
        return []

def _am_get_recent_vulnerabilities(self, minutes: int = 5):
    """
    Return vulnerabilities detected in the last N minutes.
    Uses mapped detected_at column name.
    """
    try:
        with self._get_db() as db:
            vf = self.get_vuln_fields() if hasattr(self, 'get_vuln_fields') else {
                'detected_at': 'detected_at'
            }
            query = f"""
                SELECT * FROM vulnerabilities
                WHERE {vf['detected_at']} > datetime('now', '-{int(minutes)} minutes')
                ORDER BY {vf['detected_at']} DESC
            """
            cur = db.execute(query)
            return [dict(row) for row in cur.fetchall()]
    except Exception as e:
        print(f"get_recent_vulnerabilities error: {e}")
        return []

# Bind only if missing (non-destructive)
try:
    if not hasattr(AssetManager, "get_recent_discoveries"):
        AssetManager.get_recent_discoveries = _am_get_recent_discoveries if MethodType is None else MethodType(_am_get_recent_discoveries, AssetManager)
        # If bound unbound, rebind properly on instances:
        if MethodType is not None:
            def __bind_discoveries(self, *a, **k):
                return _am_get_recent_discoveries(self, *a, **k)
            AssetManager.get_recent_discoveries = __bind_discoveries
    if not hasattr(AssetManager, "get_recent_vulnerabilities"):
        AssetManager.get_recent_vulnerabilities = _am_get_recent_vulnerabilities if MethodType is None else MethodType(_am_get_recent_vulnerabilities, AssetManager)
        if MethodType is not None:
            def __bind_vulns(self, *a, **k):
                return _am_get_recent_vulnerabilities(self, *a, **k)
            AssetManager.get_recent_vulnerabilities = __bind_vulns
except Exception as _e:
    print(f"[compat] could not bind AssetManager shims: {_e}")
# --- end compat shim ---

# --- Compat helpers (added only if missing) -----------------------------------
def _am_get_all_assets(self):
    """Return all assets as a list of dicts."""
    try:
        with self._get_db() as db:
            cur = db.execute("SELECT * FROM assets")
            return [dict(row) for row in cur.fetchall()]
    except Exception as e:
        print(f"get_all_assets error: {e}")
        return []

def _am_get_existing_urls(self, limit: int = 5000):
    """Return list of existing asset URLs to avoid duplicates (uses mappings)."""
    try:
        run_scope_hosts = os.environ.get('MODSCAN_RUN_SCOPE_HOSTS')
        allowed_hosts = None
        if run_scope_hosts:
            allowed_hosts = {
                host.strip().lower().lstrip('.')
                for host in run_scope_hosts.split(',') if host.strip()
            }
        with self._get_db() as db:
            fields = self.get_asset_fields() if hasattr(self, "get_asset_fields") else {"url": "url"}
            cur = db.execute(f"SELECT {fields['url']} FROM assets LIMIT ?", (limit,))
            urls = []
            for row in cur.fetchall():
                url = row[0]
                if not url:
                    continue
                if allowed_hosts:
                    try:
                        from urllib.parse import urlparse
                        host = (urlparse(url).hostname or '').lower().lstrip('.')
                    except Exception:
                        host = ''
                    if host not in allowed_hosts:
                        continue
                urls.append(url)
            return urls
    except Exception as e:
        print(f"get_existing_urls error: {e}")
        return []

try:
    if not hasattr(AssetManager, "get_all_assets"):
        AssetManager.get_all_assets = _am_get_all_assets
    if not hasattr(AssetManager, "get_existing_urls"):
        AssetManager.get_existing_urls = _am_get_existing_urls
except Exception as _e:
    print(f"[compat] could not bind AssetManager compat helpers: {_e}")
# -----------------------------------------------------------------------------

# --- Dedup shim: skip re-scans within TTL (non-destructive) -------------------
def _am__registry_path():
    try:
        from pathlib import Path
        return Path(__file__).resolve().parent / "scan_registry.json"
    except Exception:
        import os
        return os.path.join(".", "scan_registry.json")

def _am__load_registry():
    import json, os
    p = _am__registry_path()
    try:
        if hasattr(p, "exists") and p.exists():
            return json.loads(p.read_text(encoding="utf-8") or "{}")
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f) or {}
    except Exception:
        pass
    return {}

def _am__save_registry(reg):
    import json, os, io
    p = _am__registry_path()
    try:
        # atomic-ish write
        tmp = str(p) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(reg, f, ensure_ascii=False, indent=2)
        os.replace(tmp, str(p))
    except Exception as e:
        print(f"[dedup] save_registry failed: {e}")

def _am__now_ts():
    import time
    return int(time.time())

def _am__normalize_host(host: str) -> str:
    try:
        host = (host or "").strip().lower()
        if host.startswith("http://") or host.startswith("https://"):
            from urllib.parse import urlparse
            host = (urlparse(host).hostname or "").lower()
        return host.lstrip(".")
    except Exception:
        return (host or "").strip().lower()

def _am_should_scan_host(self, host: str, ttl_hours: int = 24) -> bool:
    """
    Return True if the host should be scanned now; False if a recent scan exists.
    - Uses scan_registry.json (persistent across runs)
    - TTL in hours (default 24). Override via env MODSCAN_TTL_HOURS.
    """
    import os
    try:
        ttl = int(os.environ.get("MODSCAN_TTL_HOURS", ttl_hours))
    except Exception:
        ttl = ttl_hours

    reg = _am__load_registry()
    bucket = reg.setdefault("hosts", {})
    key = _am__normalize_host(host)
    if not key:
        return True

    now = _am__now_ts()
    last = int(bucket.get(key, {}).get("last_scan_ts", 0))
    if last and (now - last) < ttl * 3600:
        return False

    # mark as in-progress to block duplicates in same run
    bucket[key] = {"last_scan_ts": now}
    _am__save_registry(reg)
    return True

def _am_should_scan_url(self, url: str, ttl_hours: int = 24) -> bool:
    """
    URL-level dedup using normalized URL (uses AssetManager.normalize_url if present).
    """
    import os
    try:
        ttl = int(os.environ.get("MODSCAN_TTL_HOURS", ttl_hours))
    except Exception:
        ttl = ttl_hours

    # normalize
    try:
        if hasattr(self, "normalize_url"):
            norm = self.normalize_url(url)
        else:
            norm = str(url).strip()
    except Exception:
        norm = str(url).strip()

    reg = _am__load_registry()
    bucket = reg.setdefault("urls", {})
    key = norm
    now = _am__now_ts()
    last = int(bucket.get(key, {}).get("last_scan_ts", 0))
    if last and (now - last) < ttl * 3600:
        return False

    bucket[key] = {"last_scan_ts": now}
    _am__save_registry(reg)
    return True

def _am_record_scan_host(self, host: str):
    reg = _am__load_registry()
    bucket = reg.setdefault("hosts", {})
    key = _am__normalize_host(host)
    if key:
        bucket[key] = {"last_scan_ts": _am__now_ts()}
        _am__save_registry(reg)

def _am_record_scan_url(self, url: str):
    try:
        if hasattr(self, "normalize_url"):
            key = self.normalize_url(url)
        else:
            key = str(url).strip()
    except Exception:
        key = str(url).strip()
    reg = _am__load_registry()
    bucket = reg.setdefault("urls", {})
    if key:
        bucket[key] = {"last_scan_ts": _am__now_ts()}
        _am__save_registry(reg)

# bind if missing (don’t override any existing project methods)
try:
    if not hasattr(AssetManager, "should_scan_host"):
        AssetManager.should_scan_host = _am_should_scan_host
    if not hasattr(AssetManager, "should_scan_url"):
        AssetManager.should_scan_url = _am_should_scan_url
    if not hasattr(AssetManager, "record_scan_host"):
        AssetManager.record_scan_host = _am_record_scan_host
    if not hasattr(AssetManager, "record_scan_url"):
        AssetManager.record_scan_url = _am_record_scan_url
except Exception as _e:
    print(f"[dedup] bind helpers failed: {_e}")
# -----------------------------------------------------------------------------


# --- Scope filter shim (dedup-aware & tier-aware) -----------------------------
def _am__peek_host_recent(host, ttl_hours=24):
    """Check registry without mutating it. True if host scanned within TTL."""
    import json, time
    from pathlib import Path
    try:
        ttl = int(os.environ.get("MODSCAN_TTL_HOURS", ttl_hours))
    except Exception:
        ttl = ttl_hours
    p = Path(__file__).resolve().parent / "scan_registry.json"
    try:
        reg = json.loads(p.read_text(encoding="utf-8") or "{}") if p.exists() else {}
    except Exception:
        reg = {}
    bucket = reg.get("hosts", {})
    key = (host or "").strip().lower().lstrip(".")
    last = int(bucket.get(key, {}).get("last_scan_ts", 0))
    return bool(last and (int(time.time()) - last) < ttl * 3600)

def _am__has_pending_deep(self, host):
    """True if any asset for host has deep_scan_complete NULL/0 (i.e., needs deeper tiers)."""
    try:
        f = self.get_asset_fields()
        with self._get_db() as db:
            q = f"SELECT 1 FROM assets WHERE {f['host']}=? AND (deep_scan_complete IS NULL OR deep_scan_complete=0) LIMIT 1"
            return db.execute(q, (host,)).fetchone() is not None
    except Exception:
        # Fail-open so we don't miss deep work if DB/mappings differ.
        return True

# Preserve the original
if not hasattr(AssetManager, "_orig_get_scope_domains"):
    AssetManager._orig_get_scope_domains = AssetManager.get_scope_domains

def _am_get_scope_domains_filtered(self):
    """Return scope seeds, filtered by run-scope isolation and TTL."""
    # Check for run-scope isolation first
    run_scope_hosts = os.environ.get('MODSCAN_RUN_SCOPE_HOSTS')
    if run_scope_hosts:
        # Return only CLI targets for this run
        return run_scope_hosts.split(',')

    try:
        seeds = list(AssetManager._orig_get_scope_domains(self) or [])
    except Exception:
        # If anything odd, fall back to original behavior.
        return AssetManager._orig_get_scope_domains(self)

    try:
        ttl = int(os.environ.get("MODSCAN_TTL_HOURS", "24"))
    except Exception:
        ttl = 24

    out = []
    for d in seeds:
        h = (d or "").strip().lower().lstrip(".")
        if not h:
            continue
        recent = _am__peek_host_recent(h, ttl_hours=ttl)
        if recent and not _am__has_pending_deep(self, h):
            try:
                print(f"[scope] ⏭️  Skipping {h}: scanned within {ttl}h (no deep pending)")
            except Exception:
                pass
            continue
        out.append(h)
    return out

# Monkey-patch
AssetManager.get_scope_domains = _am_get_scope_domains_filtered
# -----------------------------------------------------------------------------
