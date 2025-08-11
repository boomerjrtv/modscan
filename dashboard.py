import sqlite3
import os
import json
import sys
from pathlib import Path
from flask import Flask, jsonify, render_template, g, request
try:
    from flask_socketio import SocketIO, emit
    SOCKETIO_AVAILABLE = True
except ImportError:
    SOCKETIO_AVAILABLE = False
import logging
from logging.handlers import RotatingFileHandler
import psutil

# --- Path Setup ---
sys.path.append('/home/michael/recon-platform/lean_scanner')

# --- Configuration ---
BASE_DIR = Path(__file__).resolve().parent
ASSET_MAPPING_PATH = BASE_DIR / 'asset_mapping.json'
CONFIG_PATH = BASE_DIR / 'config.json'

with open(CONFIG_PATH, 'r') as f:
    CONFIG = json.load(f)
with open(ASSET_MAPPING_PATH, 'r') as f:
    ASSET_MAPPING = json.load(f)

# --- Flask App Initialization ---
app = Flask(__name__, template_folder=os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates')))
app.config.update(CONFIG)

# --- Logging ---
log_dir = app.config['log_directory']
os.makedirs(log_dir, exist_ok=True)
log_handler = RotatingFileHandler(
    os.path.join(log_dir, app.config['log_file']),
    maxBytes=1024000,
    backupCount=5
)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[log_handler, logging.StreamHandler()]
)
app.logger.addHandler(log_handler)

# Security headers middleware
@app.after_request
def after_request(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    return response

# --- Database ---
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['database_path'], timeout=30.0, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA journal_mode=WAL')
        g.db.execute('PRAGMA synchronous=NORMAL')
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# --- API Endpoints ---
from asset_manager import AssetManager

# Initialize AssetManager for centralized data operations
asset_manager = AssetManager()

# Removed - asset mapping now handled entirely by global config in frontend

@app.route('/api/assets', methods=['GET'])
def get_assets():
    try:
        manager = AssetManager()
        search_query = request.args.get('q', '')
        # Handle both page/limit and from/size parameters
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('limit', request.args.get('size', 25)))
        from_param = request.args.get('from')
        if from_param is not None:
            page = int(from_param) // per_page + 1
        assets_data = manager.get_assets(search_query, page, per_page)
        # Don't map - let frontend use raw database fields with asset_mapping.json
        app.logger.debug(f"Returning {len(assets_data['assets'])} raw assets (query: '{search_query}')")
        return jsonify(assets_data)
    except Exception as e:
        app.logger.error(f"Error in get_assets: {e}")
        return jsonify({"error": "Failed to load assets", "assets": [], "total": 0})

@app.route('/api/assets/summary', methods=['GET'])
def get_assets_summary():
    try:
        manager = AssetManager()
        summary = manager.get_asset_summary()
        app.logger.debug(f"Assets summary: {summary['total_assets']} total assets")
        return jsonify(summary)
    except Exception as e:
        app.logger.error(f"Error in get_assets_summary: {e}")
        return jsonify({"total_assets": 0, "active_200": 0, "forbidden_403": 0, "redirects_3xx": 0, "new_today": 0, "screenshots": 0})

@app.route('/api/vulns', methods=['GET'])
def get_vulns():
    try:
        manager = AssetManager()
        search_query = request.args.get('q', '')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('limit', request.args.get('size', 25)))
        
        vulns_data = manager.get_vulnerabilities(search_query, page, per_page)
        return jsonify(vulns_data)
    except Exception as e:
        app.logger.error(f"Error loading vulnerabilities: {e}")
        return jsonify({"vulnerabilities": [], "total": 0, "page": 1, "per_page": 25})

# Individual tab APIs for URL persistence
@app.route('/api/tabs/assets')
def get_assets_tab():
    """API for Asset Inventory tab with tab persistence."""
    return get_assets()

@app.route('/api/tabs/scope')
def get_scope_tab():
    """API for Scope Management tab with tab persistence."""
    return get_scope()

@app.route('/api/tabs/vulnerabilities')
def get_vulnerabilities_tab():
    """API for Vulnerabilities tab with tab persistence."""
    return get_vulns()

@app.route('/api/tabs/ml-xss')
@app.route('/api/ml_xss_results')
def get_mlxss_tab():
    """API for ML XSS Results tab with tab persistence."""
    try:
        # Get vulnerabilities with XSS type using centralized AssetManager
        manager = AssetManager()
        vulns_data = manager.get_vulnerabilities(100)
        xss_vulns = [v for v in vulns_data.get('vulnerabilities', []) if 'xss' in v.get('type', '').lower()]
        return jsonify({"vulnerabilities": xss_vulns, "total": len(xss_vulns)})
    except Exception as e:
        return jsonify({"vulnerabilities": [], "error": str(e)})

@app.route('/api/tabs/bypasses')
def get_bypasses_tab():
    """API for 403 Bypasses tab with tab persistence."""
    try:
        manager = AssetManager()
        # Get assets with 403 status codes
        assets_data = manager.get_assets('status_code:403', 1, 100)
        return jsonify(assets_data)
    except Exception as e:
        return jsonify({"assets": [], "error": str(e)})

@app.route('/api/tabs/system')
def get_system_tab():
    """API for System Monitor tab with tab persistence."""
    return get_system_metrics()

# Cache CPU readings to avoid rapid successive calls causing 0% readings
_cpu_cache = {'value': 0.0, 'timestamp': 0}
_scanner_cpu_cache = {}

@app.route('/api/system_metrics', methods=['GET'])
def get_system_metrics():
    try:
        import time
        current_time = time.time()
        
        # Cache CPU reading for 2 seconds to avoid 0% bouncing
        if current_time - _cpu_cache['timestamp'] > 2:
            _cpu_cache['value'] = psutil.cpu_percent(interval=1.0)  # Use 1 second interval
            _cpu_cache['timestamp'] = current_time
        cpu_percent = _cpu_cache['value']
        
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Count running scanner processes and active threads
        scanner_processes = 0
        python_processes = 0
        scanner_cpu = 0.0
        scanner_memory = 0.0
        active_threads = 0
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'memory_percent', 'num_threads']):
            try:
                if proc.info['name'] == 'python3' and proc.info['cmdline']:
                    cmdline = ' '.join(proc.info['cmdline'])
                    python_processes += 1
                    if any(keyword in cmdline.lower() for keyword in ['engine.py', 'scanner', 'recon', 'vuln', 'discovery', 'asset']):
                        scanner_processes += 1
                        pid = proc.info['pid']
                        
                        # Cache per-process CPU readings to avoid 0% bouncing
                        if pid not in _scanner_cpu_cache or current_time - _scanner_cpu_cache[pid]['timestamp'] > 2:
                            try:
                                p = psutil.Process(pid)
                                proc_cpu = p.cpu_percent(interval=None)  # Non-blocking call
                                _scanner_cpu_cache[pid] = {'value': proc_cpu, 'timestamp': current_time}
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                _scanner_cpu_cache[pid] = {'value': 0, 'timestamp': current_time}
                        
                        scanner_cpu += _scanner_cpu_cache[pid]['value']
                        scanner_memory += proc.info['memory_percent'] or 0
                        active_threads += proc.info['num_threads'] or 0
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Get network connections  
        network_connections = len(psutil.net_connections())
        
        # Get proxy stats using centralized AssetManager
        proxy_stats = asset_manager.get_proxy_stats()
        proxy_connections = proxy_stats.get('total_proxies', 0)
        active_proxy_connections = proxy_stats.get('active_connections', 0)
        
        # Fallback to config if AssetManager doesn't have data
        if proxy_connections == 0:
            proxy_list = CONFIG.get("proxy_list", [])
            proxy_connections = len(proxy_list)
            active_proxy_connections = min(proxy_connections, 5)
        
        metrics = {
            'cpu_percent': round(cpu_percent, 1),
            'memory_percent': round(memory.percent, 1),
            'disk_percent': round((disk.used / disk.total) * 100, 1),
            'memory_used_gb': round(memory.used / (1024**3), 1),
            'memory_total_gb': round(memory.total / (1024**3), 1),
            'disk_used_gb': round(disk.used / (1024**3), 1),
            'disk_total_gb': round(disk.total / (1024**3), 1),
            'scanner_processes': scanner_processes,
            'python_processes': python_processes,
            'scanner_cpu': round(scanner_cpu, 1),
            'scanner_memory': round(scanner_memory, 1),
            'active_threads': active_threads,
            'proxy_connections': active_proxy_connections,
            'total_proxies': proxy_connections,
            'network_connections': min(network_connections, 999),  # Cap display
            'scanner_status': {
                'high_performance_scanner': 'active' if scanner_processes > 0 else 'idle',
                'bypass_scanner': 'unknown',
                'screenshot_queue': 'idle', 
                'openvpn_proxies': f'{active_proxy_connections}/{proxy_connections} active' if proxy_connections > 0 else 'none configured',
                'wireguard_proxies': 'idle'
            }
        }
        
        return jsonify(metrics)
    except Exception as e:
        app.logger.error(f"Error getting system metrics: {e}")
        return jsonify({
            'cpu_percent': 0,
            'memory_percent': 0,
            'disk_percent': 0,
            'scanner_processes': 0,
            'proxy_connections': 0,
            'total_proxies': 0,
            'network_connections': 0,
            'scanner_status': {
                'high_performance_scanner': 'idle',
                'openvpn_proxies': 'error'
            }
        })

@app.route('/api/activity', methods=['GET'])
def get_activity():
    try:
        manager = AssetManager()
        limit = int(request.args.get('limit', 50))
        return jsonify(manager.get_activities(limit))
    except Exception as e:
        app.logger.error(f"Error getting activities: {e}")
        return jsonify({"activities": []})

@app.route('/api/scope', methods=['GET'])
def get_scope():
    try:
        targets = asset_manager.get_scope_targets()
        
        authorized_domains = []
        wildcard_domains = []
        
        for target_id, target, is_wildcard in targets:
            if is_wildcard:
                wildcard_domains.append(target)
            else:
                authorized_domains.append(target)
        
        return jsonify({
            "authorized_domains": authorized_domains,
            "wildcard_domains": wildcard_domains,
            "scope": [{ # Keep both for compatibility
                'id': target_id,
                'target': target, 
                'is_wildcard': bool(is_wildcard),
                'display_name': target
            } for target_id, target, is_wildcard in targets]
        })
    except Exception as e:
        app.logger.error(f"Error getting scope: {e}")
        return jsonify({
            "authorized_domains": [],
            "wildcard_domains": [],
            "scope": []
        })

@app.route('/api/scope', methods=['POST'])
def add_scope():
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        
        if not target:
            return jsonify({"error": "Target is required"}), 400
            
        success = asset_manager.add_scope_target(target)
        
        if success:
            return jsonify({"message": "Target added successfully"})
        else:
            return jsonify({"error": "Failed to add target"}), 400
    except Exception as e:
        app.logger.error(f"Error adding scope: {e}")
        return jsonify({"error": "Failed to add target"}), 500

@app.route('/api/scope/<int:target_id>', methods=['DELETE'])
def delete_scope(target_id):
    try:
        success = asset_manager.delete_scope_target(target_id)
        
        if success:
            return jsonify({"message": "Target removed successfully"})
        else:
            return jsonify({"error": "Failed to remove target"}), 400
    except Exception as e:
        app.logger.error(f"Error removing scope: {e}")
        return jsonify({"error": "Failed to remove target"}), 500

@app.route('/api/notifications', methods=['GET'])  
def get_notifications():
    try:
        # Return empty for now - notifications system placeholder
        return jsonify({"notifications": []})
    except Exception as e:
        app.logger.error(f"Error getting notifications: {e}")
        return jsonify({"notifications": []})

@app.route('/api/asset_mapping', methods=['GET'])
def get_asset_mapping():
    import time
    mapping_with_cache_bust = ASSET_MAPPING.copy()
    mapping_with_cache_bust['_cache_bust'] = int(time.time())
    return jsonify(mapping_with_cache_bust)

@app.route('/api/screenshots/<path:filename>', methods=['GET'])
def serve_screenshot(filename):
    try:
        from flask import send_file
        import os
        import urllib.parse
        
        # Decode URL-encoded filename and remove .png extension if present
        decoded_filename = urllib.parse.unquote(filename)
        if decoded_filename.endswith('.png'):
            decoded_filename = decoded_filename[:-4]
        
        # Find screenshot using AssetManager (centralized mapping)
        manager = AssetManager()
        screenshot_path = manager.get_screenshot_path(decoded_filename)
        
        if screenshot_path and os.path.exists(screenshot_path):
            return send_file(screenshot_path, mimetype='image/png')
        
        # Return 404 if not found
        from flask import abort
        abort(404)
    except Exception as e:
        app.logger.error(f"Error serving screenshot {filename}: {e}")
        from flask import abort
        abort(404)

# --- Frontend Route ---
@app.route('/')
def index():
    return render_template('FINAL_COMPLETE_ENTERPRISE_SIEM.html')

def init_db_and_scope():
    with app.app_context():
        db = sqlite3.connect(app.config['database_path'])
        with db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY, url TEXT, host TEXT, status_code INTEGER, title TEXT,
                    tech_stack TEXT, content_length INTEGER, response_time REAL, response_body TEXT,
                    screenshot_path TEXT, last_scanned TEXT, discovery_method TEXT
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY, asset_id INTEGER, type TEXT, description TEXT,
                    severity TEXT, evidence TEXT, payload TEXT, detected_at TEXT
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS scope (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL UNIQUE,
                    is_wildcard BOOLEAN NOT NULL
                );
            """)
        print("Database initialized.")

        print("Scope table ready - use setup_scope.py to add targets if needed.")

def kill_existing_dashboards():
    """Kill any existing dashboard processes before starting"""
    import subprocess
    import os
    import signal
    
    try:
        print("🔍 Checking for existing dashboard processes...")
        
        # Find existing dashboard processes
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        dashboard_processes = []
        
        for line in result.stdout.split('\n'):
            if 'dashboard.py' in line and 'python' in line and str(os.getpid()) not in line:
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        pid = int(parts[1])
                        dashboard_processes.append(pid)
                        print(f"📍 Found existing dashboard process: PID {pid}")
                    except ValueError:
                        continue
        
        # Kill existing processes
        for pid in dashboard_processes:
            try:
                os.kill(pid, signal.SIGTERM)
                print(f"💀 Killed existing dashboard process: PID {pid}")
                time.sleep(1)
                
                # Force kill if still running
                try:
                    os.kill(pid, signal.SIGKILL)
                    print(f"🔨 Force killed stubborn process: PID {pid}")
                except ProcessLookupError:
                    pass  # Process already dead
                    
            except ProcessLookupError:
                print(f"✅ Process {pid} already terminated")
            except Exception as e:
                print(f"❌ Failed to kill process {pid}: {e}")
        
        # Wait and verify all processes are dead
        time.sleep(2)
        
        # Double-check no dashboard processes remain
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        remaining = []
        for line in result.stdout.split('\n'):
            if 'dashboard.py' in line and 'python' in line and str(os.getpid()) not in line:
                remaining.append(line)
        
        if remaining:
            print(f"⚠️  {len(remaining)} dashboard processes still running after cleanup!")
            for proc in remaining:
                print(f"   Still running: {proc}")
            return False
        else:
            print("✅ All existing dashboard processes successfully terminated")
            return True
            
    except Exception as e:
        print(f"❌ Error during dashboard process cleanup: {e}")
        return False

if __name__ == '__main__':
    with app.app_context():
        init_db_and_scope()
    app.run(host=app.config['dashboard_host'], port=app.config['dashboard_port'], debug=True)