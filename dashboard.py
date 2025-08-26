import sqlite3
import os
import json
import sys
import time
from pathlib import Path
from flask import Flask, jsonify, render_template, g, request, make_response
try:
    from flask_socketio import SocketIO, emit
    SOCKETIO_AVAILABLE = True
except ImportError:
    SOCKETIO_AVAILABLE = False
import logging
import subprocess
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
        per_page = int(request.args.get('limit', request.args.get('size', 100)))
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
        per_page = int(request.args.get('limit', request.args.get('size', 100)))
        
        offset = (page - 1) * per_page
        vulns_data = manager.get_vulnerabilities(search_query, offset, per_page)
        return jsonify(vulns_data)
    except Exception as e:
        app.logger.error(f"Error loading vulnerabilities: {e}")
        return jsonify({"vulnerabilities": [], "total": 0, "page": 1, "per_page": 25})

@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """Main vulnerabilities API endpoint with category support."""
    try:
        manager = AssetManager()
        search_query = request.args.get('q', '')
        category = request.args.get('category', 'all')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('limit', request.args.get('size', 100)))
        
        offset = (page - 1) * per_page
        vulns_data = manager.get_vulnerabilities_by_category(category, search_query, offset, per_page)
        
        # Add cache-busting headers to ensure fresh data
        response = jsonify(vulns_data)
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    except Exception as e:
        app.logger.error(f"Error in get_vulnerabilities: {e}")
        return jsonify({"vulnerabilities": [], "total": 0, "page": 1, "per_page": 25})

@app.route('/api/vulnerabilities/categories', methods=['GET'])
def get_vulnerability_categories():
    """Get vulnerability categories with counts."""
    try:
        manager = AssetManager()
        categories = manager.get_vulnerability_categories()
        return jsonify({"categories": categories})
    except Exception as e:
        app.logger.error(f"Error getting vulnerability categories: {e}")
        return jsonify({"categories": []})

@app.route('/vuln_test.html')
def vulnerability_test_page():
    """Serve cache-busting vulnerability test page."""
    try:
        with open('vuln_test.html', 'r') as f:
            content = f.read()
        response = make_response(content)
        response.headers['Content-Type'] = 'text/html'
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    except Exception as e:
        return f"Test page not found: {e}"

@app.route('/api/vulnerabilities/refresh', methods=['POST'])
def refresh_vulnerabilities():
    """Force refresh vulnerabilities data."""
    try:
        manager = AssetManager()
        vulns_data = manager.get_vulnerabilities_by_category('all', '', 0, 10)
        
        response = jsonify({
            "status": "refreshed",
            "total": vulns_data.get('total', 0),
            "sample": vulns_data.get('vulnerabilities', [])[:3],
            "timestamp": datetime.now().isoformat()
        })
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        return response
    except Exception as e:
        return jsonify({"error": str(e), "status": "failed"})

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

@app.route('/api/vulnerability-explanations')
def get_vulnerability_explanations():
    """Get detailed explanations of how vulnerabilities work"""
    explanations = {
        "Reflected XSS": {
            "description": "User input is immediately reflected back in the response without proper encoding",
            "how_it_works": [
                "1. Attacker crafts malicious script in URL parameter (e.g., ?search=<script>alert('XSS')</script>)",
                "2. Application processes the request and includes user input in HTML response",
                "3. Browser receives HTML with unescaped script and executes it",
                "4. Malicious JavaScript runs in victim's browser with full site privileges"
            ],
            "example_payload": "<script>alert('XSS')</script>",
            "technical_details": "The vulnerability occurs when user input is directly embedded into HTML without HTML encoding. The browser interprets <script> tags as executable code.",
            "impact": "Session hijacking, credential theft, defacement, redirects to malicious sites",
            "prevention": "HTML encode all user input before displaying, use Content Security Policy (CSP)"
        },
        "DOM XSS (Fragment)": {
            "description": "JavaScript processes URL fragments/hash values and manipulates DOM unsafely",
            "how_it_works": [
                "1. Malicious payload placed in URL fragment (#payload)",
                "2. Client-side JavaScript reads location.hash value",
                "3. Script uses innerHTML or similar to insert fragment content into page",
                "4. Browser executes the injected script within the fragment"
            ],
            "example_payload": "#2' onerror='alert(1)' x='",
            "technical_details": "DOM-based XSS occurs entirely in the browser. JavaScript functions like chooseTab() read URL fragments and use innerHTML to insert content, creating XSS when fragments contain malicious code.",
            "impact": "Same as reflected XSS but harder to detect as payload never reaches server",
            "prevention": "Validate and sanitize all DOM manipulations, avoid innerHTML with user data"
        },
        "JavaScript Context XSS": {
            "description": "User input breaks out of JavaScript string context to execute arbitrary code",
            "how_it_works": [
                "1. User input injected into JavaScript variable or function call",
                "2. Attacker uses quotes/semicolons to break out of string context",
                "3. Malicious JavaScript code appended after string termination",
                "4. Browser executes the injected code as part of the script"
            ],
            "example_payload": "3');alert('XSS');//",
            "technical_details": "When user input is placed inside JavaScript strings like startTimer('USER_INPUT'), attackers can use ');alert('XSS');// to escape the string and inject code.",
            "impact": "Full JavaScript execution capabilities within the application context",
            "prevention": "JavaScript-escape user input, use JSON.stringify(), avoid concatenating user data into scripts"
        },
        "Protocol XSS": {
            "description": "Malicious JavaScript executed through javascript: protocol in links or redirects",
            "how_it_works": [
                "1. Attacker injects javascript: protocol into href attributes",
                "2. When user clicks the link, browser executes the JavaScript",
                "3. Code runs with full access to the current page context",
                "4. Can be triggered automatically with onload or other events"
            ],
            "example_payload": "javascript:alert('XSS')",
            "technical_details": "The javascript: protocol allows arbitrary JavaScript execution when used in href attributes. Modern browsers restrict this but it still works in many contexts.",
            "impact": "Arbitrary JavaScript execution, often requires user interaction",
            "prevention": "Validate URL schemes, whitelist allowed protocols (http, https), encode special characters"
        },
        "Stored XSS (Filter Bypass)": {
            "description": "Malicious script stored in database and executed when page loads, bypassing input filters",
            "how_it_works": [
                "1. Attacker submits payload that bypasses server-side filters",
                "2. Malicious content stored in database or file system",
                "3. When other users visit the page, stored content is displayed",
                "4. Browser executes the stored malicious script automatically"
            ],
            "example_payload": "<img src='x' onerror='alert(\"XSS\")'>'",
            "technical_details": "Stored XSS persists the attack. Common bypasses include using img onerror instead of script tags, or svg onload events to evade simple <script> filters.",
            "impact": "Affects all users who view the infected content, most dangerous XSS type",
            "prevention": "Server-side validation, output encoding, comprehensive input filtering, CSP"
        },
        "Gadget XSS": {
            "description": "Exploits third-party JavaScript libraries or frameworks to execute malicious code",
            "how_it_works": [
                "1. Application loads external JavaScript from user-controlled source",
                "2. Attacker provides malicious JavaScript via data: URLs or bypassed filters",
                "3. External script loading mechanism executes the malicious code",
                "4. Attack leverages legitimate application functionality"
            ],
            "example_payload": "data:text/javascript,alert('XSS')",
            "technical_details": "Some applications load external scripts dynamically. The data: protocol can be used to embed JavaScript directly in URLs, bypassing http/https filters.",
            "impact": "Can bypass strict Content Security Policies, leverages trusted application features",
            "prevention": "Restrict external script sources, validate URLs, disable data: protocol for scripts"
        },
        "String Breaking XSS": {
            "description": "Breaking out of JavaScript string contexts to execute arbitrary code",
            "how_it_works": [
                "1. User input placed inside JavaScript string (e.g., console.log('USER_INPUT'))",
                "2. Attacker uses quotes and semicolons to terminate the string early",
                "3. Malicious JavaScript code injected after string termination",
                "4. Comments (//) used to ignore remaining original code"
            ],
            "example_payload": "\");alert(1);//",
            "technical_details": "When input goes into console.log('INPUT'), the payload \"\');alert(1);//\" results in console.log(\"\");alert(1);//\"), executing the alert.",
            "impact": "Full JavaScript execution in the page context",
            "prevention": "Escape quotes in user input, use JSON.stringify() for safe string embedding"
        },
        "Missing Security Header": {
            "description": "Critical HTTP security headers are missing from server responses",
            "how_it_works": [
                "1. Server responds to HTTP requests without security headers",
                "2. Browser receives response without security protections",
                "3. Various attacks become possible due to missing defenses",
                "4. Attackers can exploit the lack of security controls"
            ],
            "example_payload": "N/A - Configuration issue, not an injection attack",
            "technical_details": "HTTP security headers like Content-Security-Policy, X-Frame-Options, X-XSS-Protection provide browser-level security controls. When missing, applications become vulnerable to XSS, clickjacking, and other attacks.",
            "impact": "Enables XSS attacks, clickjacking, MIME sniffing attacks, and reduces overall security posture",
            "prevention": "Configure web server to send security headers: CSP, X-Frame-Options, X-XSS-Protection, X-Content-Type-Options, Strict-Transport-Security"
        },
        "Information Disclosure": {
            "description": "Sensitive information is exposed to unauthorized users",
            "how_it_works": [
                "1. Application exposes sensitive data in responses",
                "2. Information can be accessed by unauthorized users",
                "3. Data may include configuration, debugging info, or internal details",
                "4. Attackers use disclosed information for further attacks"
            ],
            "example_payload": "N/A - Information exposure, not injection",
            "technical_details": "Information disclosure occurs when applications reveal sensitive data like server versions, internal paths, configuration details, or error messages that help attackers understand the system.",
            "impact": "Provides reconnaissance information for attackers, may expose sensitive data directly",
            "prevention": "Remove debug information from production, configure error handling, disable server signatures, implement proper access controls"
        },
        "XSS": {
            "description": "Generic Cross-Site Scripting vulnerability allowing malicious script execution",
            "how_it_works": [
                "1. Attacker injects malicious JavaScript into web application",
                "2. Application fails to properly validate or encode user input",
                "3. Malicious script is served to other users",
                "4. Script executes in victim's browser with application privileges"
            ],
            "example_payload": "<script>alert('XSS')</script>",
            "technical_details": "XSS vulnerabilities occur when applications include untrusted data in web pages without proper validation or encoding. This allows attackers to execute scripts in users' browsers.",
            "impact": "Session hijacking, credential theft, defacement, malware distribution, phishing",
            "prevention": "Input validation, output encoding, Content Security Policy, use secure frameworks"
        },
        "XSS - Script Context": {
            "description": "User input is injected directly into JavaScript code within <script> tags",
            "how_it_works": [
                "1. Application includes user input inside <script> tags without proper escaping",
                "2. Attacker injects JavaScript code that breaks out of intended context",
                "3. Malicious code executes as part of the page's JavaScript",
                "4. Full access to DOM, cookies, and browser APIs"
            ],
            "example_payload": "'; alert('XSS'); //",
            "technical_details": "When user input is placed directly into JavaScript context, special characters like quotes and semicolons can break out of strings or statements to inject arbitrary code. This is more dangerous than HTML context XSS as it executes immediately.",
            "impact": "Complete client-side compromise, session hijacking, data exfiltration, malware injection",
            "prevention": "JavaScript-specific encoding, avoid dynamic script generation, use JSON encoding for data"
        }
    }
    
    return jsonify(explanations)

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
        return jsonify({"error": str(e)})

# ========== ADVANCED XBOW-CRUSHING ENDPOINTS ========== 

@app.route('/api/advanced/stats', methods=['GET'])
def api_advanced_stats():
    """Advanced scanning statistics - showcasing XBOW-crushing capabilities"""
    try:
        manager = AssetManager()
        
        with manager._get_db() as db:
            # Advanced vulnerability breakdown
            cursor = db.execute('''
                SELECT 
                    CASE 
                        WHEN type LIKE '%XXE%' OR type LIKE '%XML%' THEN 'XXE'
                        WHEN type LIKE '%GraphQL%' OR type LIKE '%graphql%' THEN 'GraphQL'
                        WHEN type LIKE '%API%' OR type LIKE '%IDOR%' OR type LIKE '%BOLA%' THEN 'API Logic'
                        WHEN type LIKE '%XSS%' THEN 'XSS'
                        WHEN type LIKE '%SQL%' THEN 'SQL Injection'
                        ELSE 'Other'
                    END as category,
                    COUNT(*) as count,
                    ROUND(AVG(confidence), 2) as avg_confidence
                FROM vulnerabilities 
                GROUP BY category
            ''')
            vuln_categories = [dict(zip([col[0] for col in cursor.description], row)) for row in cursor.fetchall()]
            
            # High-confidence findings (our zero false positive advantage)
            cursor = db.execute('SELECT COUNT(*) FROM vulnerabilities WHERE confidence >= 0.8')
            high_confidence = cursor.fetchone()[0]
            
            # Recent discovery rate
            cursor = db.execute("SELECT COUNT(*) FROM assets WHERE last_scanned >= datetime('now', '-24 hours')")
            recent_discoveries = cursor.fetchone()[0]
            
            # Advanced scanner performance
            cursor = db.execute('''
                SELECT 
                    COUNT(DISTINCT CASE WHEN url LIKE '%graphql%' OR title LIKE '%GraphQL%' THEN id END) as graphql_targets,
                    COUNT(DISTINCT CASE WHEN url LIKE '%api%' OR url LIKE '%rest%' THEN id END) as api_targets,
                    COUNT(DISTINCT CASE WHEN url LIKE '%soap%' OR url LIKE '%wsdl%' THEN id END) as xml_targets
                FROM assets
            ''')
            advanced_targets = dict(zip([col[0] for col in cursor.description], cursor.fetchone()))
            
        stats = {
            'vulnerability_categories': vuln_categories,
            'high_confidence_findings': high_confidence,
            'recent_discoveries_24h': recent_discoveries,
            'advanced_targets': advanced_targets,
            'xbow_advantages': {
                'zero_false_positives': high_confidence,
                'advanced_scanners_active': 4,
                'ml_classification_enabled': True,
                'unlimited_concurrency': True
            }
        }
        
        return jsonify(stats)
        
    except Exception as e:
        app.logger.error(f"Failed to fetch advanced stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scanner/status', methods=['GET'])
def api_scanner_status():
    """Real-time scanner status and performance"""
    try:
        # Check if engine is running
        engine_running = False
        engine_pid = None
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                name = (proc.info.get('name') or '').lower()
                cmdline = proc.info.get('cmdline') or []
                if 'python' in name and any('engine.py' in (arg or '') for arg in cmdline):
                    engine_running = True
                    engine_pid = proc.info['pid']
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # System performance
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        
        # Database stats
        manager = AssetManager()
        with manager._get_db() as db:
            cursor = db.execute("SELECT COUNT(*) FROM assets")
            total_assets = cursor.fetchone()[0]
            
            cursor = db.execute("SELECT COUNT(*) FROM vulnerabilities")
            total_vulns = cursor.fetchone()[0]
            
            cursor = db.execute("SELECT COUNT(*) FROM assets WHERE last_scanned >= datetime('now', '-1 hour')")
            recent_assets = cursor.fetchone()[0]
            
            # Advanced scanner specific counts
            cursor = db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE type LIKE '%XXE%' OR type LIKE '%XML%' ")
            xxe_findings = cursor.fetchone()[0]
            
            cursor = db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE type LIKE '%GraphQL%' OR type LIKE '%graphql%' ")
            graphql_findings = cursor.fetchone()[0]
            
            cursor = db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE type LIKE '%API%' OR type LIKE '%IDOR%' OR type LIKE '%BOLA%' ")
            api_logic_findings = cursor.fetchone()[0]
        
        status = {
            'engine': {
                'running': engine_running,
                'pid': engine_pid,
                'unlimited_mode': CONFIG.get('performance', {}).get('unlimited_concurrency', False)
            },
            'system': {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_available_gb': round(memory.available / (1024**3), 1)
            },
            'database': {
                'total_assets': total_assets,
                'total_vulnerabilities': total_vulns,
                'assets_last_hour': recent_assets
            },
            'xxe_scanner': {
                'active': engine_running,
                'findings': xxe_findings,
                'status': 'SCANNING' if engine_running else 'IDLE'
            },
            'graphql_scanner': {
                'active': engine_running,
                'findings': graphql_findings,
                'status': 'SCANNING' if engine_running else 'IDLE'
            },
            'api_logic_scanner': {
                'active': engine_running,
                'findings': api_logic_findings,
                'status': 'SCANNING' if engine_running else 'IDLE'
            },
            'ai_assistant': {
                'active': engine_running,
                'predictions': xxe_findings + graphql_findings + api_logic_findings,
                'status': 'ANALYZING' if engine_running else 'IDLE'
            },
            'performance': {
                'max_concurrent': 'UNLIMITED',
                'active_sessions': 0,
                'cpu_usage': int(cpu_percent)
            }
        }
        
        return jsonify(status)
        
    except Exception as e:
        app.logger.error(f"Failed to get scanner status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/findings/advanced', methods=['GET'])
def api_advanced_findings():
    """Advanced findings from our XBOW-crushing scanners"""
    try:
        manager = AssetManager()
        
        with manager._get_db() as db:
            # Get advanced findings with high confidence
            cursor = db.execute('''
                SELECT 
                    v.type,
                    v.description,
                    v.severity,
                    v.confidence,
                    v.evidence,
                    v.detected_at,
                    a.url,
                    a.title,
                    CASE 
                        WHEN v.type LIKE '%XXE%' OR v.type LIKE '%XML%' THEN 'XXE Scanner'
                        WHEN v.type LIKE '%GraphQL%' OR v.type LIKE '%graphql%' THEN 'GraphQL Scanner'
                        WHEN v.type LIKE '%API%' OR v.type LIKE '%IDOR%' OR v.type LIKE '%BOLA%' THEN 'API Logic Scanner'
                        ELSE 'Traditional Scanner'
                    END as scanner_used
                FROM vulnerabilities v
                LEFT JOIN assets a ON v.asset_id = a.id
                WHERE v.confidence >= 0.7
                ORDER BY v.detected_at DESC
                LIMIT 100
            ''')
            
            findings = [dict(zip([col[0] for col in cursor.description], row)) for row in cursor.fetchall()]
        
        return jsonify(findings)
        
    except Exception as e:
        app.logger.error(f"Failed to fetch advanced findings: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/targets/classification', methods=['GET'])
def api_target_classification():
    """Get intelligent target classification"""
    try:
        manager = AssetManager()
        
        with manager._get_db() as db:
            cursor = db.execute('''
                SELECT 
                    CASE
                        WHEN url LIKE '%graphql%' OR title LIKE '%GraphQL%' THEN 'GraphQL'
                        WHEN url LIKE '%api%' OR url LIKE '%rest%' THEN 'REST API'
                        WHEN url LIKE '%soap%' OR url LIKE '%wsdl%' THEN 'SOAP/XML'
                        WHEN url LIKE '%admin%' THEN 'Admin Panel'
                        WHEN status_code BETWEEN 200 AND 299 THEN 'Live Web App'
                        ELSE 'Unknown'
                    END as target_type,
                    COUNT(*) as count
                FROM assets
                GROUP BY target_type
                ORDER BY count DESC
            ''')
            
            classifications = [dict(zip([col[0] for col in cursor.description], row)) for row in cursor.fetchall()]
        
        return jsonify(classifications)
        
    except Exception as e:
        app.logger.error(f"Failed to get target classification: {e}")
        return jsonify({'error': str(e)}), 500

    except Exception as e:
        app.logger.error(f"Error getting activities: {e}")
        return jsonify({"activities": []})

@app.route("/api/scope", methods=["GET", "POST"])
def scope_manager():
    if request.method == 'POST':
        try:
            data = request.get_json()
            target = data.get('target', '').strip()
            
            if not target:
                return jsonify({"error": "Target is required"}), 400
            # Gracefully handle duplicates: if domain already in scope, return 200
            try:
                with sqlite3.connect(app.config['database_path']) as db:
                    row = db.execute("SELECT id FROM scope WHERE domain=?", (target,)).fetchone()
                    if row:
                        return jsonify({"message": "Target already in scope", "id": row[0]})
            except Exception:
                pass

            success = asset_manager.add_scope_target(target)
            return (jsonify({"message": "Target added successfully", "id": success})
                    if success else jsonify({"error": "Failed to add target"}), 200 if success else 400)
        except Exception as e:
            app.logger.error(f"Error adding scope: {e}")
            return jsonify({"error": "Failed to add target"}), 500
    else: # GET request
        return get_scope()

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

@app.route('/api/scope/<int:target_id>', methods=['PUT'])
def update_scope(target_id):
    """Update scope target flags (currently: is_active)."""
    try:
        data = request.get_json() or {}
        is_active = 1 if str(data.get('is_active')).lower() in ('1', 'true', 'yes') else 0
        with sqlite3.connect(app.config['database_path']) as db:
            cols = {row[1] for row in db.execute("PRAGMA table_info(scope)").fetchall()}
            if 'is_active' in cols:
                db.execute("UPDATE scope SET is_active = ? WHERE id = ?", (is_active, target_id))
            elif 'active' in cols:
                db.execute("UPDATE scope SET active = ? WHERE id = ?", (is_active, target_id))
            elif 'is_wildcard' in cols:
                db.execute("UPDATE scope SET is_wildcard = ? WHERE id = ?", (is_active, target_id))
            else:
                return jsonify({"error": "Unsupported scope schema"}), 500
            db.commit()
        return jsonify({"message": "Scope updated"})
    except Exception as e:
        app.logger.error(f"Error updating scope: {e}")
        return jsonify({"error": str(e)}), 500

# ===== Domain cookies API =====
@app.route('/api/cookies', methods=['GET', 'POST'])
def domain_cookies():
    try:
        with sqlite3.connect(app.config['database_path']) as db:
            db.row_factory = sqlite3.Row
            if request.method == 'GET':
                rows = db.execute("SELECT domain, cookie, persistent, auth_keys, last_updated, policy FROM cookies").fetchall()
                cookies = [dict(r) for r in rows]
                return jsonify({"cookies": cookies})
            data = request.get_json() or {}
            domain = (data.get('domain') or '').strip()
            cookie = data.get('cookie') or ''
            persistent = data.get('persistent')
            auth_keys = data.get('auth_keys')
            policy = data.get('policy')
            if not domain:
                return jsonify({"success": False, "error": "Domain is required"}), 400
            import json
            p_json = json.dumps(persistent) if isinstance(persistent, (list, tuple)) else (persistent or None)
            a_json = json.dumps(auth_keys) if isinstance(auth_keys, (list, tuple)) else (auth_keys or None)
            pol_json = json.dumps(policy) if isinstance(policy, dict) else (policy or None)
            # Upsert full policy
            # Use COALESCE to keep previous values if not provided
            row = db.execute("SELECT cookie, persistent, auth_keys, policy FROM cookies WHERE domain=?", (domain,)).fetchone()
            prev_cookie = (row[0] if row else '')
            prev_p = (row[1] if row else None)
            prev_a = (row[2] if row else None)
            prev_pol = (row[3] if row else None)
            final_cookie = cookie if cookie != '' else prev_cookie
            final_p = p_json if p_json is not None else prev_p
            final_a = a_json if a_json is not None else prev_a
            final_pol = pol_json if pol_json is not None else prev_pol
            db.execute("REPLACE INTO cookies(domain, cookie, persistent, auth_keys, last_updated, policy) VALUES(?,?,?,?,datetime('now'),?)",
                       (domain, final_cookie, final_p, final_a, final_pol))
            db.commit()
            return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/cookies/<domain>', methods=['GET'])
def get_domain_cookie(domain):
    try:
        with sqlite3.connect(app.config['database_path']) as db:
            row = db.execute("SELECT cookie, policy FROM cookies WHERE domain=?", (domain,)).fetchone()
            return jsonify({
                "cookie": (row[0] if row else ''),
                "policy": (row[1] if row and len(row) > 1 else None)
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/cookies/minimize', methods=['POST'])
def minimize_cookies():
    """Burp-style cookie minimizer: determine the minimal cookie set required for stable responses.
    Request JSON: { domain: 'example.com', url?: 'https://example.com/path', cookie_string: 'a=1; b=2' }
    Response JSON: { success: true, minimized_cookie: 'a=1', details: [{key, kept, reason}], baseline: {status, final_url} }
    """
    try:
        import asyncio
        import aiohttp
        import time as _time
        import re
        import re
        from urllib.parse import urlunparse, urlparse

        data = request.get_json() or {}
        domain = (data.get('domain') or '').strip()
        candidate_url = (data.get('url') or '').strip()
        cookie_string = (data.get('cookie_string') or '').strip()
        if not domain and not candidate_url:
            return jsonify({"success": False, "error": "Provide 'domain' or 'url'"}), 400
        if not cookie_string:
            return jsonify({"success": False, "error": "cookie_string is required"}), 400

        # Build target URL
        if not candidate_url:
            candidate_url = urlunparse(('http', domain, '/', '', '', ''))

        # Parse cookies into list of (k,v)
        def parse_cookie_items(s: str):
            items = []
            for part in [p.strip() for p in s.split(';') if p.strip()]:
                if '=' in part:
                    k, v = part.split('=', 1)
                    k = k.strip()
                    v = v.strip()
                    if k:
                        items.append((k, v))
            return items

        def join_cookie_items(items):
            return '; '.join([f"{k}={v}" for k, v in items])

        # Normalize response signature to compare equivalence
        def normalize_text(t: str) -> str:
            if not t:
                return ''
            # Strip dynamic numbers, timestamps, nonces (conservative)
            t = re.sub(r"\d{10,}", "<NUM>", t)  # long numbers
            t = re.sub(r"[0-9a-fA-F]{16,}", "<HEX>", t)  # long hex
            t = re.sub(r"\b\d{1,2}:[0-5]\d(:[0-5]\d)?\b", "<TIME>", t)
            return t[:50000]  # cap size for hashing

        async def fetch_signature(session: aiohttp.ClientSession, url: str, cookie: str):
            headers = {"User-Agent": "ModScan-AuthMin/1.0"}
            if cookie:
                headers['Cookie'] = cookie
            try:
                async with session.get(url, allow_redirects=True, timeout=15, headers=headers) as resp:
                    txt = await resp.text()
                    body_norm = normalize_text(txt)
                    # Extract <title> as a quick semantic hint
                    m = re.search(r"<title[^>]*>(.*?)</title>", txt, re.I | re.S)
                    title = (m.group(1).strip() if m else '')
                    final = str(resp.url)
                    return {
                        'status': resp.status,
                        'final_url': final,
                        'title': title[:256],
                        'body_sig': hash(body_norm)
                    }
            except Exception as e:
                return {'error': str(e)}

        async def minimize(url: str, cookie_str: str):
            items = parse_cookie_items(cookie_str)
            if not items:
                return [], cookie_str, {'error': 'no_cookies'}
            connector = aiohttp.TCPConnector(limit=10, ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                baseline = await fetch_signature(session, url, cookie_str)
                if 'error' in baseline:
                    return [], cookie_str, baseline

                kept = items[:]
                details = []

                async def test_without(index: int):
                    temp = kept[:index] + kept[index+1:]
                    sig = await fetch_signature(session, url, join_cookie_items(temp))
                    return sig

                # First pass: try removing each cookie once
                i = 0
                while i < len(kept):
                    key, val = kept[i]
                    sig = await test_without(i)
                    if 'error' in sig:
                        details.append({'key': key, 'kept': True, 'reason': f"network: {sig['error']}"})
                        i += 1
                        continue
                    same = (sig['status'] == baseline['status'] and sig['final_url'] == baseline['final_url'] and sig['body_sig'] == baseline['body_sig'])
                    if same:
                        # Drop unnecessary cookie
                        details.append({'key': key, 'kept': False, 'reason': 'no_change'})
                        kept.pop(i)
                        # Do not increment i; now at next item due to pop
                        continue
                    else:
                        details.append({'key': key, 'kept': True, 'reason': 'changes_response'})
                        i += 1

                # Optional second pass to catch dependent drops
                j = 0
                while j < len(kept):
                    key, val = kept[j]
                    sig = await test_without(j)
                    if 'error' in sig:
                        j += 1
                        continue
                    same = (sig['status'] == baseline['status'] and sig['final_url'] == baseline['final_url'] and sig['body_sig'] == baseline['body_sig'])
                    if same:
                        kept.pop(j)
                        continue
                    j += 1

                return details, join_cookie_items(kept), baseline

        # Run async minimizer
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        details, minimized, baseline = loop.run_until_complete(minimize(candidate_url, cookie_string))
        loop.close()

        return jsonify({
            'success': True,
            'minimized_cookie': minimized,
            'details': details,
            'baseline': baseline,
            'target_url': candidate_url
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

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

@app.route('/api/schema', methods=['GET'])
def get_dynamic_schema():
    """Get dynamic schema configuration for frontend"""
    try:
        from api_schema import APISchemaGenerator
        generator = APISchemaGenerator()
        config = generator.generate_frontend_config()
        return jsonify(config)
    except Exception as e:
        app.logger.error(f"Schema generation error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/domains', methods=['GET'])
def get_available_domains():
    """Get available domains for authentication"""
    try:
        from api_schema import APISchemaGenerator
        generator = APISchemaGenerator()
        domains = generator.get_available_domains()
        return jsonify({"domains": domains})
    except Exception as e:
        app.logger.error(f"Domains fetch error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/extract-cookies', methods=['POST'])
def extract_cookies():
    """Automatically extract cookies using browser automation"""
    try:
        import subprocess
        import asyncio
        import json as json_lib
        from urllib.parse import urlparse
        
        data = request.get_json()
        domain_url = data.get('domain_url')
        
        if not domain_url:
            return jsonify({"success": False, "error": "Domain URL is required"}), 400
        
        # Check for extractor script availability
        script_path = os.path.join(os.getcwd(), 'auto_cookie_extractor.py')
        if not os.path.exists(script_path):
            return jsonify({"success": False, "error": "Cookie extractor not available"}), 501

        app.logger.info(f"Starting cookie extraction for {domain_url}")
        result = subprocess.run(['python3', script_path, domain_url], capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            # Try to find the generated cookie file
            domain = urlparse(domain_url).netloc.replace('.', '_')
            cookie_file = f"cookies_{domain}.json"
            
            try:
                with open(cookie_file, 'r') as f:
                    cookie_data = json_lib.load(f)
                
                return jsonify({
                    "success": True,
                    "cookie_string": cookie_data['cookie_string'],
                    "domain": cookie_data['domain'],
                    "extracted_at": cookie_data['extracted_at']
                })
            except FileNotFoundError:
                return jsonify({
                    "success": False,
                    "error": "Cookie file not found - extraction may have failed"
                }), 500
        else:
            app.logger.error(f"Cookie extraction failed: {result.stderr}")
            return jsonify({
                "success": False,
                "error": f"Extraction process failed: {result.stderr}"
            }), 500
            
    except subprocess.TimeoutExpired:
        return jsonify({
            "success": False,
            "error": "Cookie extraction timed out - please try again"
        }), 500
    except Exception as e:
        app.logger.error(f"Cookie extraction error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/login-extract-cookies', methods=['POST'])
def login_extract_cookies():
    """Login with credentials and extract session cookies"""
    try:
        import asyncio
        import aiohttp
        from urllib.parse import urljoin, urlparse
        import re
        
        data = request.get_json()
        login_url = data.get('login_url')
        username = data.get('username')
        password = data.get('password')
        
        if not all([login_url, username, password]):
            return jsonify({"success": False, "error": "All fields are required"}), 400
        
        app.logger.info(f"Attempting login to {login_url} with username {username}")
        
        async def perform_login():
            jar = aiohttp.CookieJar(unsafe=True)
            async with aiohttp.ClientSession(cookie_jar=jar) as session:
                # Step 1: Get login page to extract CSRF tokens
                async with session.get(login_url) as response:
                    login_html = await response.text()
                    app.logger.info(f"Login page status: {response.status}")
                
                # Step 2: Extract CSRF token if present
                csrf_token = None
                if 'user_token' in login_html:
                    token_match = re.search(r'name=["\']user_token["\'] value=["\']([^"\']+)["\']', login_html)
                    if token_match:
                        csrf_token = token_match.group(1)
                        app.logger.info("Found CSRF token")
                
                # Step 3: Prepare login data
                login_data = {
                    'username': username,
                    'password': password,
                    'Login': 'Login'
                }
                if csrf_token:
                    login_data['user_token'] = csrf_token
                
                # Step 4: Perform login
                async with session.post(login_url, data=login_data, allow_redirects=False) as response:
                    app.logger.info(f"Login attempt status: {response.status}")
                    
                    # Check if we got a redirect (successful login) or 200
                    if response.status in [200, 302, 303]:
        # Extract all cookies from the session
                        all_cookies = []
                        for cookie in session.cookie_jar:
                            all_cookies.append(f"{cookie.key}={cookie.value}")
                        
                        app.logger.info(f"Found {len(all_cookies)} cookies: {[c.split('=')[0] for c in all_cookies]}")
                        
                        if all_cookies:
                            cookie_string = "; ".join(all_cookies)
                            
                            # Test the cookies by accessing the same origin root
                            from urllib.parse import urlparse, urlunparse
                            u = urlparse(login_url)
                            test_url = urlunparse((u.scheme, u.netloc, '/', '', '', ''))
                            async with session.get(test_url) as test_response:
                                test_content = await test_response.text()
                                if test_response.status in (200, 301, 302):
                                    app.logger.info("Authentication verified - can access protected pages")
                                else:
                                    app.logger.warning("Authentication may have failed - redirected to login")
                            
                            return {"success": True, "cookie_string": cookie_string}
                        else:
                            return {"success": False, "error": "No cookies found after login"}
                    else:
                        return {"success": False, "error": f"Login failed with status {response.status}"}
        
        # Run the async login function
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(perform_login())
        loop.close()
        
        return jsonify(result)
            
    except Exception as e:
        app.logger.error(f"Login extraction error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/verify_cookie', methods=['POST'])
def verify_cookie():
    """Verify a cookie works for provided domain or URL (universal).

    Request JSON: { domain?: string, url?: string, cookie_string?: string, login_url?, username?, password? }
    - If 'url' provided, probes that URL; else probes http://<domain>/ after normalizing.
    """
    try:
        import asyncio
        import aiohttp
        from urllib.parse import urlunparse, urlparse
        data = request.get_json() or {}
        domain_or_url = (data.get('domain') or data.get('url') or '').strip()
        cookie_string = (data.get('cookie_string') or '').strip()
        login_url = data.get('login_url')
        username = data.get('username')
        password = data.get('password')
        if not domain_or_url:
            return jsonify({"success": False, "error": "Provide 'domain' or 'url'"}), 400
        
        # Normalize domain_or_url to probe_url and normalized domain key
        parsed = urlparse(domain_or_url)
        if parsed.scheme and parsed.netloc:
            probe_url = domain_or_url
            norm_domain = parsed.hostname or parsed.netloc
        else:
            # Strip any scheme/path remnants
            clean = domain_or_url
            if clean.startswith('http://') or clean.startswith('https://'):
                clean = urlparse(clean).hostname or clean
            clean = clean.split('/')[0]
            norm_domain = clean
            probe_url = urlunparse(('http', norm_domain, '/', '', '', ''))
        
        async def _probe(u):
            headers = {"User-Agent": "ModScan-Verify/1.0"}
            if cookie_string:
                headers['Cookie'] = cookie_string
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(u, allow_redirects=True, timeout=10) as resp:
                    txt = await resp.text()
                    # Heuristic: 200/301/302 and not redirected to obvious login path
                    ok = resp.status in (200, 301, 302)
                    return ok, str(resp.url), resp.status, txt[:500]
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        ok, final_url, status, snippet = loop.run_until_complete(_probe(probe_url))
        
        if ok:
            # Merge persistent policy if present and persist back
            try:
                with sqlite3.connect(app.config['database_path']) as db:
                    row = db.execute("SELECT persistent FROM cookies WHERE domain=?", (norm_domain,)).fetchone()
                    merged_cookie = cookie_string
                    if row and row[0] and merged_cookie:
                        merged_cookie = _merge_persistent_cookie(merged_cookie, row[0])
                    db.execute("INSERT INTO cookies(domain, cookie, last_updated) VALUES(?,?,datetime('now'))\n                               ON CONFLICT(domain) DO UPDATE SET cookie=excluded.cookie, last_updated=excluded.last_updated",
                               (norm_domain, merged_cookie or ''))
                    db.commit()
                    cookie_string = merged_cookie
            except Exception:
                pass
            return jsonify({"success": True, "verified": True, "final_url": final_url, "status": status, "cookie_string": cookie_string, "domain": norm_domain})
        
        # Attempt refresh if creds provided
        if login_url and username and password:
            async def _refresh():
                jar = aiohttp.CookieJar(unsafe=True)
                async with aiohttp.ClientSession(cookie_jar=jar) as session:
                    async with session.get(login_url) as resp:
                        html = await resp.text()
                    import re
                    csrf = None
                    if 'user_token' in html:
                        m = re.search(r'name=["\']user_token["\'] value=["\']([^"\']+)["\']', html)
                        csrf = m.group(1) if m else None
                    form = {'username': username, 'password': password, 'Login': 'Login'}
                    if csrf:
                        form['user_token'] = csrf
                    async with session.post(login_url, data=form, allow_redirects=False) as r2:
                        # Build cookie string
                        parts = []
                        for c in session.cookie_jar:
                            parts.append(f"{c.key}={c.value}")
                        return '; '.join(parts)
            new_cookie = loop.run_until_complete(_refresh())
            loop.close()
            # Apply persistent policy if present and save
            try:
                with sqlite3.connect(app.config['database_path']) as db:
                    row = db.execute("SELECT persistent FROM cookies WHERE domain=?", (norm_domain,)).fetchone()
                    if row and row[0] and new_cookie:
                        new_cookie = _merge_persistent_cookie(new_cookie, row[0])
                    db.execute("INSERT INTO cookies(domain, cookie, last_updated) VALUES(?,?,datetime('now'))\n                               ON CONFLICT(domain) DO UPDATE SET cookie=excluded.cookie, last_updated=excluded.last_updated",
                               (norm_domain, new_cookie or ''))
                    db.commit()
            except Exception:
                pass
            return jsonify({"success": True, "verified": False, "refreshed": True, "cookie_string": new_cookie, "domain": norm_domain})
        
        loop.close()
        return jsonify({"success": True, "verified": False, "domain": norm_domain})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

def _merge_persistent_cookie(cookie_string: str, persistent_json: str) -> str:
    """Merge persistent cookie key=val pairs into cookie_string (override or append)."""
    try:
        import json, re
        cookie = cookie_string.strip()
        arr = json.loads(persistent_json) if persistent_json else []
        pairs = []
        for kv in arr:
            if isinstance(kv, str) and '=' in kv:
                key, val = kv.split('=', 1)
                key = key.strip()
                val = val.strip()
                if re.search(rf"\b{re.escape(key)}=", cookie, re.I):
                    cookie = re.sub(rf"\b{re.escape(key)}=[^;]*", f"{key}={val}", cookie, flags=re.I)
                else:
                    pairs.append(f"{key}={val}")
        if pairs:
            cookie = (cookie + '; ' + '; '.join(pairs)) if cookie else '; '.join(pairs)
        return cookie
    except Exception:
        return cookie_string

@app.route('/api/auth_policy', methods=['POST'])
def set_auth_policy():
    """Set per-domain auth policy: headers, bearer, localStorage/sessionStorage, login flow.

    Request JSON: {
      domain: 'example.com',
      policy: {
        headers?: {k: v},
        bearer?: 'token',
        local_storage?: {k: v},
        session_storage?: {k: v},
        login?: { url: 'https://...', username: 'u', password: 'p' }
      }
    }
    """
    try:
        data = request.get_json() or {}
        domain = (data.get('domain') or '').strip()
        policy = data.get('policy') or {}
        if not domain:
            return jsonify({"success": False, "error": "Domain is required"}), 400
        import json
        pol_json = json.dumps(policy, ensure_ascii=False)
        with sqlite3.connect(app.config['database_path']) as db:
            row = db.execute("SELECT domain FROM cookies WHERE domain=?", (domain,)).fetchone()
            if row:
                db.execute("UPDATE cookies SET policy=?, last_updated=datetime('now') WHERE domain=?", (pol_json, domain))
            else:
                db.execute("INSERT INTO cookies(domain, policy, last_updated) VALUES(?,?,datetime('now'))", (domain, pol_json))
            db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/auth_policy/<domain>', methods=['GET'])
def get_auth_policy(domain):
    """Fetch per-domain auth policy JSON"""
    try:
        with sqlite3.connect(app.config['database_path']) as db:
            row = db.execute("SELECT policy FROM cookies WHERE domain=?", (domain,)).fetchone()
            return jsonify({"policy": (row[0] if row else None)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/rescan_with_auth', methods=['POST'])
def rescan_with_auth():
    """Run authenticated vulnerability scan with stored cookies"""
    try:
        import subprocess
        import asyncio
        import aiohttp
        from urllib.parse import urlunparse
        
        data = request.get_json() or {}
        domain = (data.get('domain') or '').strip()
        cookie_string = (data.get('cookie_string') or '').strip()
        
        # Fallback: if domain missing, use first scope domain
        if not domain:
            try:
                from asset_manager import AssetManager
                am = AssetManager()
                scope = am.get_scope_domains()
                if scope:
                    domain = scope[0]
            except Exception:
                pass
        if not domain:
            return jsonify({"success": False, "error": "Domain is required"}), 400
        # Fetch saved cookie if not provided
        if not cookie_string:
            try:
                with sqlite3.connect(app.config['database_path']) as db:
                    row = db.execute("SELECT cookie FROM cookies WHERE domain=?", (domain,)).fetchone()
                    if row and row[0]:
                        cookie_string = row[0]
            except Exception:
                pass
        if not cookie_string:
            return jsonify({"success": False, "error": "Cookie string is required; verify/refresh or save policy"}), 400
        
        app.logger.info(f"Starting authenticated vulnerability scan for {domain}")
        
        # Verify cookie server-side before launching
        async def _probe():
            u = urlunparse(('http', domain, '/', '', '', ''))
            headers = {"User-Agent": "ModScan-Verify/1.0", "Cookie": cookie_string}
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(u, allow_redirects=True, timeout=10) as resp:
                    return resp.status in (200, 301, 302)
        # Use a dedicated event loop in this request thread to avoid 'no current event loop'
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        ok = loop.run_until_complete(_probe())
        loop.close()
        if not ok:
            return jsonify({"success": False, "error": "Cookie invalid/expired; use Verify/Refresh first"}), 400
        
        # Merge persistent cookie policy (e.g., security=low) and persist
        try:
            with sqlite3.connect(app.config['database_path']) as db:
                row = db.execute("SELECT persistent FROM cookies WHERE domain=?", (domain,)).fetchone()
                if row and row[0] and cookie_string:
                    cookie_string = _merge_persistent_cookie(cookie_string, row[0])
                db.execute(
                    "INSERT INTO cookies(domain, cookie, last_updated) VALUES(?, ?, datetime('now'))\n                     ON CONFLICT(domain) DO UPDATE SET cookie=excluded.cookie, last_updated=excluded.last_updated",
                    (domain, cookie_string or '')
                )
                db.commit()
        except Exception:
            pass

        # Create placeholder logs so UI doesn't show not-found
        try:
            logs_dir = Path(__file__).parent / 'logs'
            logs_dir.mkdir(parents=True, exist_ok=True)
            for name in ('engine.log', 'dashboard.log', 'main.log'):
                p = logs_dir / name
                if not p.exists():
                    p.touch()
        except Exception:
            pass

        # Launch engine with provided cookie and domain (universal approach)
        app.logger.info(f"Launching engine with MODSCAN_AUTH_DOMAIN={domain} and provided cookie...")
        env = os.environ.copy()
        env['MODSCAN_AUTH_DOMAIN'] = domain
        env['MODSCAN_AUTH_COOKIE'] = cookie_string
        # Force run regardless of TTL for user-initiated authenticated scans
        env['MODSCAN_TTL_HOURS'] = '0'
        subprocess.Popen(['python3', 'engine.py'], env=env)
        return jsonify({
            "success": True,
            "message": f"Engine started for {domain} with authentication",
            "hint": "Results will populate asynchronously in the dashboard",
            "started": True,
            "assets_scanned": 0,
            "vulnerabilities_found": 0
        })
            
    except subprocess.TimeoutExpired:
        return jsonify({
            "success": False,
            "error": "Authenticated scan timed out - this may take longer for large targets"
        }), 500
    except Exception as e:
        app.logger.error(f"Authenticated scan error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/screenshots/<path:filename>', methods=['GET'])
def serve_screenshot(filename):
    try:
        from flask import send_file
        import os
        import urllib.parse
        
        # Decode URL-encoded filename
        decoded_filename = urllib.parse.unquote(filename)
        
        # Direct file path - screenshots are stored in screenshots/ directory
        screenshot_path = os.path.join('screenshots', decoded_filename)
        
        if os.path.exists(screenshot_path):
            return send_file(screenshot_path, mimetype='image/png')
        
        # Return 404 if not found
        return jsonify({"error": f"Screenshot not found: {filename}"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ===== Evidence API =====

@app.route('/api/evidence/list', methods=['GET'])
def list_evidence():
    try:
        import os
        from pathlib import Path
        import time
        ev_dir = Path('evidence')
        sc_dir = Path('screenshots')
        items = []
        if ev_dir.exists():
            for html_file in ev_dir.glob('*.html'):
                base = html_file.stem
                headers_file = ev_dir / f"{base}.headers.json"
                requests_file = ev_dir / f"{base}.requests.jsonl"
                screenshot_file = sc_dir / f"{base}.png"
                items.append({
                    'base': base,
                    'modified': int(html_file.stat().st_mtime),
                    'html': f"/api/evidence/{html_file.name}",
                    'headers': f"/api/evidence/{headers_file.name}" if headers_file.exists() else None,
                    'requests': f"/api/evidence/{requests_file.name}" if requests_file.exists() else None,
                    'screenshot': f"/api/screenshots/{screenshot_file.name}" if screenshot_file.exists() else None,
                })
        # Sort by modified desc
        items.sort(key=lambda x: x['modified'], reverse=True)
        return jsonify({'evidence': items, 'total': len(items)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/evidence/<path:filename>', methods=['GET'])
def serve_evidence(filename):
    try:
        import os
        from flask import send_file
        import mimetypes
        from urllib.parse import unquote
        fname = unquote(filename)
        path = os.path.join('evidence', fname)
        if not os.path.exists(path):
            return jsonify({'error': 'Not found'}), 404
        mime, _ = mimetypes.guess_type(path)
        if not mime:
            # headers.json and requests.jsonl fall back to JSON/text
            if path.endswith('.json'):
                mime = 'application/json'
            elif path.endswith('.jsonl'):
                mime = 'text/plain'
            elif path.endswith('.html'):
                mime = 'text/html'
            else:
                mime = 'application/octet-stream'
        return send_file(path, mimetype=mime)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===== Auth Auto-Refresh =====

@app.route('/api/auto_refresh_session', methods=['POST'])
def auto_refresh_session():
    """Attempt to refresh session using stored per-domain policy login flow (universal)."""
    try:
        import asyncio
        import aiohttp
        import re
        data = request.get_json() or {}
        domain = (data.get('domain') or '').strip()
        override_login = data.get('login') or {}
        if not domain:
            return jsonify({'success': False, 'error': 'Domain is required'}), 400
        # Load policy
        pol = None
        with sqlite3.connect(app.config['database_path']) as db:
            row = db.execute('SELECT policy, persistent FROM cookies WHERE domain=?', (domain,)).fetchone()
            if row and row[0]:
                try:
                    import json as _json
                    pol = _json.loads(row[0])
                except Exception:
                    pol = None
            persistent_json = row[1] if row else None
        login_cfg = (pol.get('login') if isinstance(pol, dict) else {}) or {}
        # Override with provided fields if present
        for key in ('url','username','password'):
            if key in override_login and override_login[key]:
                login_cfg[key] = override_login[key]
        login_url = login_cfg.get('url')
        username = login_cfg.get('username')
        password = login_cfg.get('password')
        if not (login_url and username and password):
            return jsonify({'success': False, 'error': 'Missing login policy (url/username/password)'}), 400

        async def _do_login():
            jar = aiohttp.CookieJar(unsafe=True)
            async with aiohttp.ClientSession(cookie_jar=jar) as session:
                async with session.get(login_url, timeout=15) as r:
                    html = await r.text()
                csrf = None
                m = re.search(r'name=["\']user_token["\']\s+value=["\']([^"\']+)["\']', html)
                if m:
                    csrf = m.group(1)
                form = {'username': username, 'password': password}
                # Try common submit field names
                for k in ('Login','submit','logon','signin','_submit'):
                    form.setdefault(k, 'Login')
                if csrf:
                    form['user_token'] = csrf
                async with session.post(login_url, data=form, allow_redirects=True, timeout=20) as r2:
                    # Build cookie string
                    parts = []
                    for c in session.cookie_jar:
                        parts.append(f"{c.key}={c.value}")
                    return '; '.join(parts)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        new_cookie = loop.run_until_complete(_do_login())
        loop.close()
        if not new_cookie:
            return jsonify({'success': False, 'error': 'Login failed'}), 500
        # Merge persistent keys and save
        try:
            if persistent_json and new_cookie:
                new_cookie = _merge_persistent_cookie(new_cookie, persistent_json)
            with sqlite3.connect(app.config['database_path']) as db:
                db.execute(
                    "INSERT INTO cookies(domain, cookie, last_updated) VALUES(?,?,datetime('now'))\n                     ON CONFLICT(domain) DO UPDATE SET cookie=excluded.cookie, last_updated=excluded.last_updated",
                    (domain, new_cookie)
                )
                db.commit()
        except Exception:
            pass
        return jsonify({'success': True, 'cookie_string': new_cookie, 'domain': domain})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ===== Asset Enrichment & Cleanup =====

@app.route('/api/enrich_assets', methods=['POST'])
def enrich_assets():
    """Fetch details for assets with NULL status_code (unscanned seeds)."""
    try:
        import asyncio
        import aiohttp
        data = request.get_json() or {}
        domain = (data.get('domain') or '').strip()
        cookie_string = data.get('cookie_string') or ''
        limit = int(data.get('limit', 100))

        # If no cookie passed and a domain was provided, try to load stored cookie and merge persistent keys
        if domain and not cookie_string:
            try:
                with sqlite3.connect(app.config['database_path']) as db:
                    row = db.execute("SELECT cookie, persistent FROM cookies WHERE domain=?", (domain,)).fetchone()
                    if row:
                        cookie_string = row[0] or ''
                        if row[1]:
                            cookie_string = _merge_persistent_cookie(cookie_string, row[1])
            except Exception as e:
                app.logger.warning(f"Could not load cookie for {domain}: {e}")

        headers = {"User-Agent": "ModScan Enricher/1.0"}
        if cookie_string:
            headers["Cookie"] = cookie_string

        # Pull seeds needing enrichment
        with sqlite3.connect(app.config['database_path']) as db:
            db.row_factory = sqlite3.Row
            if domain:
                cursor = db.execute(
                    """
                    SELECT id, url FROM assets 
                    WHERE status_code IS NULL AND url LIKE ?
                    ORDER BY id DESC LIMIT ?
                    """, (f"%://{domain}/%", limit)
                )
            else:
                cursor = db.execute(
                    "SELECT id, url FROM assets WHERE status_code IS NULL ORDER BY id DESC LIMIT ?",
                    (limit,)
                )
            targets = [(row[0], row[1]) for row in cursor.fetchall()]

        async def fetch_update(session, item):
            asset_id, url = item
            t0 = _time.monotonic()
            try:
                async with session.get(url, allow_redirects=True, timeout=15) as resp:
                    txt = await resp.text()
                    dt = int((_time.monotonic() - t0) * 1000)
                    # extract <title>
                    m = re.search(r"<title[^>]*>(.*?)</title>", txt, re.I | re.S)
                    title = (m.group(1).strip() if m else 'Unknown')
                    content_len = len(txt.encode('utf-8', 'ignore'))
                    with sqlite3.connect(app.config['database_path']) as db:
                        db.execute(
                            """
                            UPDATE assets
                            SET status_code=?, title=?, content_length=?, response_time=?, last_scanned=datetime('now')
                            WHERE id=?
                            """,
                            (resp.status, title, content_len, dt, asset_id)
                        )
                        db.commit()
                    return True
            except Exception:
                # mark last_scanned so we don't hammer
                try:
                    with sqlite3.connect(app.config['database_path']) as db:
                        db.execute("UPDATE assets SET last_scanned=datetime('now') WHERE id=?", (asset_id,))
                        db.commit()
                except Exception:
                    pass
                return False

        async def run_enrichment():
            conn = aiohttp.TCPConnector(limit=20, ssl=False)
            async with aiohttp.ClientSession(headers=headers, connector=conn) as session:
                tasks = [fetch_update(session, it) for it in targets]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                ok = sum(1 for r in results if r is True)
                return ok, len(targets)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        ok, total = loop.run_until_complete(run_enrichment())
        loop.close()

        return jsonify({"success": True, "enriched": ok, "attempted": total})
    except Exception as e:
        app.logger.error(f"Asset enrichment error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/assets/cleanup', methods=['POST'])
def cleanup_assets():
    """Remove duplicate and malformed asset rows (universal)."""
    try:
        with sqlite3.connect(app.config['database_path']) as db:
            db.row_factory = sqlite3.Row
            # Remove rows with NULL/empty URL
            cur = db.execute("DELETE FROM assets WHERE url IS NULL OR TRIM(url) = ''")
            removed_empty = cur.rowcount if cur.rowcount is not None else 0
            # Collapse duplicates by keeping the smallest id per URL
            cur = db.execute("DELETE FROM assets WHERE id NOT IN (SELECT MIN(id) FROM assets GROUP BY url)")
            removed_dups = cur.rowcount if cur.rowcount is not None else 0
            db.commit()
        return jsonify({"success": True, "removed_empty": removed_empty, "removed_duplicates": removed_dups})
    except Exception as e:
        app.logger.error(f"Cleanup assets error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

    except Exception as e:
        app.logger.error(f"Error serving screenshot {filename}: {e}")
        from flask import abort
        abort(404)

@app.route('/api/vulnerability/<int:vuln_id>/details', methods=['GET'])
def get_vulnerability_details(vuln_id):
    """Get detailed vulnerability information with screenshots and exploit proofs."""
    try:
        manager = AssetManager()
        
        with manager._get_db() as db:
            # Get vulnerability with associated asset information
            cursor = db.execute("""
                SELECT v.*, a.url as asset_url, a.host as asset_host, 
                       a.screenshot_path, a.response_body, a.status_code,
                       a.title, a.tech_stack as technologies
                FROM vulnerabilities v 
                LEFT JOIN assets a ON v.asset_id = a.id 
                WHERE v.id = ?
            """, (vuln_id,))
            
            vuln = cursor.fetchone()
            if not vuln:
                return jsonify({"error": "Vulnerability not found"}), 404
            
            vuln_dict = dict(vuln)
            # Structured verification records if present
            try:
                verify_rows = db.execute(
                    "SELECT method, marker, details, screenshot_path, created_at, oob_event_id FROM vulnerability_verifications WHERE vulnerability_id=? ORDER BY id DESC",
                    (vuln_id,)
                ).fetchall()
                vuln_dict['verifications'] = [
                    {
                        'method': r['method'],
                        'marker': r['marker'],
                        'details': r['details'],
                        'screenshot_path': r['screenshot_path'],
                        'created_at': r['created_at'],
                        'oob_event_id': r['oob_event_id']
                    } for r in verify_rows
                ]
            except Exception:
                vuln_dict['verifications'] = []
            # Only show asset-specific screenshot, not random exploit screenshots
            vuln_dict['exploit_screenshots'] = []
            return jsonify(vuln_dict)
    except Exception as e:
        app.logger.error(f"Error getting vulnerability details: {e}")
        return jsonify({"error": "Failed to load vulnerability details"}), 500

@app.route('/api/exploit-screenshots', methods=['GET'])
def list_exploit_screenshots():
    """List all exploit proof screenshots available."""
    try:
        screenshot_dir = app.config.get('screenshot_dir', 'screenshots')
        exploit_screenshots = []
        
        if os.path.exists(screenshot_dir):
            for filename in os.listdir(screenshot_dir):
                if filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                    filepath = os.path.join(screenshot_dir, filename)
                    stat = os.stat(filepath)
                    exploit_screenshots.append({
                        'filename': filename,
                        'size': stat.st_size,
                        'modified': stat.st_mtime,
                        'url': f'/api/screenshots/{filename}'
                    })
        
        # Sort by modification time, newest first
        exploit_screenshots.sort(key=lambda x: x['modified'], reverse=True)
        
        return jsonify({
            'screenshots': exploit_screenshots,
            'total': len(exploit_screenshots)
        })
    except Exception as e:
        app.logger.error(f"Error listing exploit screenshots: {e}")
        return jsonify({"error": "Failed to list screenshots"}), 500

# --- Frontend Route ---
@app.route('/')
def index():
    response = make_response(render_template('FINAL_COMPLETE_ENTERPRISE_SIEM.html'))
    # Force browser to reload JavaScript
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/api/oob/callback', methods=['GET', 'POST'])
def oob_callback_ingest():
    """Ingest OOB collaborator callback. Expects a 'marker' string.

    Example: GET /api/oob/callback?marker=SSRF_1693078123
    Stores a verification record referencing the best matching vulnerability.
    """
    try:
        import time
        marker = request.values.get('marker', '').strip()
        method = request.values.get('method', 'oob_confirmed').strip()
        extra = request.values.get('extra', '')
        if not marker:
            return jsonify({"success": False, "error": "marker required"}), 400
        mgr = AssetManager()
        mgr.ensure_verification_table()
        vuln_id = None
        with mgr._get_db() as db:
            r = db.execute(
                "SELECT vulnerability_id FROM vulnerability_verifications WHERE marker LIKE ? ORDER BY id DESC LIMIT 1",
                (f"%{marker}%",)
            ).fetchone()
            if r:
                vuln_id = r[0]
            if not vuln_id:
                r = db.execute(
                    "SELECT id FROM vulnerabilities WHERE evidence LIKE ? ORDER BY detected_at DESC LIMIT 1",
                    (f"%{marker}%",)
                ).fetchone()
                if r:
                    vuln_id = r[0]
            if vuln_id:
                mgr.add_verification_record(
                    vulnerability_id=vuln_id,
                    method=method,
                    marker=marker,
                    details=f"OOB callback received: {marker} {(' | ' + extra) if extra else ''}",
                    screenshot_path="",
                    oob_event_id=str(int(time.time()))
                )
        return jsonify({"success": True, "matched_vulnerability_id": vuln_id})
    except Exception as e:
        app.logger.error(f"OOB ingest error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

def get_scope():
    """Return current DB-backed scope list with active flag."""
    try:
        rows = asset_manager.get_scope_targets()
        scope_list = []
        with sqlite3.connect(app.config['database_path']) as db:
            db.row_factory = sqlite3.Row
            cookie_map = {r[0]: True for r in db.execute("SELECT domain FROM cookies").fetchall()}
            for tid, dom, active in rows:
                last_scan = db.execute(
                    "SELECT MAX(last_nuclei_scan_at) FROM assets WHERE host = ?", (dom,)
                ).fetchone()[0]
                scope_list.append({
                    "id": tid,
                    "domain": dom,
                    "is_active": bool(active),
                    "cookie_present": bool(cookie_map.get(dom)),
                    "last_long_scan": last_scan or ""
                })
        # Expose a flat authorized_domains list using current scope domains for UI display
        authorized_domains = [item[1] for item in rows] if rows else []
        return jsonify({"scope": scope_list, "authorized_domains": authorized_domains, "wildcard_domains": []})
    except Exception as e:
        app.logger.error(f"Error getting scope: {e}")
        return jsonify({"scope": [], "error": str(e)}), 500

@app.route('/api/scan_unauth', methods=['POST'])
def scan_unauth():
    """Launch engine unauthenticated for a given or first scope domain."""
    try:
        data = request.get_json() or {}
        domain = (data.get('domain') or '').strip()
        if not domain:
            try:
                from asset_manager import AssetManager
                am = AssetManager()
                scope = am.get_scope_domains()
                if scope:
                    domain = scope[0]
            except Exception:
                pass
        if not domain:
            return jsonify({"success": False, "error": "No domain provided and scope is empty"}), 400
        env = os.environ.copy()
        env.pop('MODSCAN_AUTH_COOKIE', None)
        env['MODSCAN_AUTH_DOMAIN'] = domain
        env['MODSCAN_TTL_HOURS'] = '0'
        subprocess.Popen(['python3', 'engine.py'], env=env)
        return jsonify({"success": True, "message": f"Unauthenticated scan started for {domain}"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/scan/direct', methods=['POST'])
def direct_url_scan():
    """Direct vulnerability testing on specific URLs"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No JSON data provided"}), 400
            
        urls = data.get('urls', [])
        if isinstance(urls, str):
            urls = [u.strip() for u in urls.strip().split('\n') if u.strip()]
        
        if not urls:
            return jsonify({"success": False, "error": "No URLs provided"}), 400
            
        credentials = data.get('credentials', {})
        locked_cookies = data.get('locked_cookies', '')
        
        # Process URLs and handle authentication
        from urllib.parse import urlparse
        import requests
        
        results = []
        added_count = 0
        
        with sqlite3.connect(app.config['database_path']) as db:
            for url in urls:
                try:
                    parsed = urlparse(url)
                    domain = parsed.netloc
                    base_url = f"{parsed.scheme}://{domain}"
                    
                    # Handle authentication if credentials provided
                    session_cookies = ''
                    if credentials and credentials.get('username') and credentials.get('password'):
                        try:
                            # Use provided login_url or fallback to base_url
                            login_url = credentials.get('login_url', base_url)
                            
                            # Perform login using existing login function
                            session = requests.Session()
                            response = session.get(login_url, timeout=10, verify=False)
                            if response.status_code == 200:
                                # Look for CSRF token
                                csrf_token = None
                                if 'user_token' in response.text:
                                    import re
                                    token_match = re.search(r'name=["\']user_token["\'] value=["\']([^"\']+)["\']', response.text)
                                    if token_match:
                                        csrf_token = token_match.group(1)
                                
                                # Prepare login data
                                login_data = {
                                    'username': credentials['username'],
                                    'password': credentials['password'],
                                    'Login': 'Login'
                                }
                                
                                if csrf_token:
                                    login_data['user_token'] = csrf_token
                                
                                # Submit login
                                login_response = session.post(login_url, data=login_data, timeout=10, verify=False)
                                
                                # Check for successful login indicators
                                if (login_response.status_code == 200 and
                                    ('welcome' in login_response.text.lower() or
                                     'dashboard' in login_response.text.lower() or
                                     'logout' in login_response.text.lower() or
                                     'vulnerabilities' in login_response.text.lower())):
                                    
                                    # Extract cookies
                                    cookies = {}
                                    for cookie in session.cookies:
                                        cookies[cookie.name] = cookie.value
                                    
                                    # Apply security level override for DVWA
                                    if 'security' in cookies and 'dvwa' in login_url.lower():
                                        cookies['security'] = 'low'  # Force security to low for testing
                                    
                                    session_cookies = '; '.join([f"{name}={value}" for name, value in cookies.items()])
                                    results.append(f"✅ Logged in to {domain}")
                                else:
                                    results.append(f"⚠️ Login failed for {domain}")
                            else:
                                results.append(f"⚠️ Could not access login page for {domain}")
                                
                        except Exception as e:
                            results.append(f"⚠️ Login error for {domain}: {str(e)}")
                    
                    # Apply locked cookies if provided
                    if locked_cookies:
                        # Parse and merge cookies
                        if session_cookies:
                            existing_dict = {}
                            for cookie in session_cookies.split(';'):
                                cookie = cookie.strip()
                                if '=' in cookie:
                                    name, value = cookie.split('=', 1)
                                    existing_dict[name.strip()] = value.strip()
                        else:
                            existing_dict = {}
                        
                        # Apply locked cookies (override existing)
                        for cookie in locked_cookies.split(';'):
                            cookie = cookie.strip()
                            if '=' in cookie:
                                name, value = cookie.split('=', 1)
                                existing_dict[name.strip()] = value.strip()
                        
                        session_cookies = '; '.join([f"{name}={value}" for name, value in existing_dict.items()])
                        results.append(f"🔒 Applied locked cookies for {domain}")
                    
                    # Add as asset to database
                    db.execute("""
                        INSERT OR REPLACE INTO assets (url, host, discovered_at, status_code, title, tech_stack) 
                        VALUES (?, ?, datetime('now'), NULL, 'Direct URL Test', 'Manual Entry')
                    """, (url, domain))
                    added_count += 1
                    
                    # Store cookies and auth policy in database if we have them
                    if session_cookies:
                        username = credentials.get('username', '') if credentials else ''
                        password = credentials.get('password', '') if credentials else ''
                        
                        # Create auth policy for auto-refresh  
                        auth_policy = {
                            'auto_refresh': data.get('auto_refresh', False),
                            'locked_cookies': locked_cookies,
                            'login_url': credentials.get('login_url', f"{base_url}/login.php"),
                            'username_field': 'username',
                            'password_field': 'password'
                        }
                        
                        # Store in cookies table
                        db.execute("""
                            INSERT OR REPLACE INTO cookies 
                            (domain, cookie, persistent, auth_keys, policy, last_updated) 
                            VALUES (?, ?, ?, ?, ?, datetime('now'))
                        """, (domain, session_cookies, f'username:{username}', f'password:{password}', 
                             json.dumps(auth_policy)))
                    
                except Exception as e:
                    results.append(f"❌ Error processing {url}: {str(e)}")
                    continue
                    
            db.commit()
        
        # After adding URLs, trigger authenticated vulnerability scanning
        if added_count > 0:
            try:
                # Get the domain from the first URL for scanning
                first_domain = urlparse(urls[0]).netloc if urls else None
                
                if first_domain:
                    # Set up environment for authenticated engine scan
                    env = os.environ.copy()
                    # Ensure process guard is active
                    env.pop('MODSCAN_SKIP_PROCESS_GUARD', None)
                    env['MODSCAN_AUTH_DOMAIN'] = first_domain
                    env['MODSCAN_TTL_HOURS'] = '0'  # Force fresh scan
                    env['MODSCAN_DIRECT_URL_TESTING'] = '1'  # Skip discovery, test only provided URLs
                    env['MODSCAN_VULN_VERBOSE'] = '1'  # Show detailed Tier 3 progress
                    env['MODSCAN_FORCE_REFRESH_EVERY_URL'] = '1'  # Strict targets: refresh auth per URL
                    # Pass the exact URLs the user submitted so the engine scans them first
                    try:
                        import json as _json
                        env['MODSCAN_DIRECT_URLS'] = _json.dumps(urls)
                    except Exception:
                        env['MODSCAN_DIRECT_URLS'] = '\n'.join(urls)
                    # Only scan the provided URLs
                    env['MODSCAN_ONLY_DIRECT_URLS'] = '1'
                    # One-shot: exit after direct pass
                    env['MODSCAN_SINGLE_SHOT'] = '1'
                    # Enable strict IDOR comparison
                    env['MODSCAN_IDOR_STRICT'] = '1'
                    # Stabilize small targets: lower inline concurrency (can be adjusted later via UI)
                    env['MODSCAN_INLINE_CONCURRENCY'] = '1'
                    
                    # Log environment variables for debugging
                    app.logger.info(f"🔧 Direct URL Testing - Setting env vars: MODSCAN_DIRECT_URL_TESTING=1, MODSCAN_AUTH_DOMAIN={first_domain}")
                    
                    # Start the engine with authentication for this domain
                    subprocess.Popen(['python3', 'engine.py'], env=env, cwd='/home/michael/recon-platform/modscan')
                    results.append(f"🚀 Started authenticated vulnerability scanning for {first_domain}")
            except Exception as e:
                results.append(f"⚠️ Failed to start vulnerability scan: {str(e)}")
            
        return jsonify({
            "success": True, 
            "message": f"Added {added_count} URLs and started vulnerability testing",
            "urls_added": added_count,
            "auth_results": results
        })
        
    except Exception as e:
        app.logger.error(f"Direct scan error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

def init_db_and_scope():
    with app.app_context():
        db = sqlite3.connect(app.config['database_path'])
        with db:
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

            # Ensure critical columns exist for mapping (SQLite lacks IF NOT EXISTS for columns)
            cols = {row[1] for row in db.execute('PRAGMA table_info(assets)').fetchall()}
            if 'discovered_at' not in cols:
                db.execute("ALTER TABLE assets ADD COLUMN discovered_at TEXT")
            if 'tech_stack' not in cols:
                db.execute("ALTER TABLE assets ADD COLUMN tech_stack TEXT")
            if 'response_time' not in cols:
                db.execute("ALTER TABLE assets ADD COLUMN response_time REAL")
            if 'content_length' not in cols:
                db.execute("ALTER TABLE assets ADD COLUMN content_length INTEGER")
            if 'last_nuclei_scan_at' not in cols:
                db.execute("ALTER TABLE assets ADD COLUMN last_nuclei_scan_at TEXT")
            # Add columns required by scanning workflow if missing
            if 'basic_scan_complete' not in cols:
                db.execute("ALTER TABLE assets ADD COLUMN basic_scan_complete INTEGER DEFAULT 0")
            if 'deep_scan_complete' not in cols:
                db.execute("ALTER TABLE assets ADD COLUMN deep_scan_complete INTEGER DEFAULT 0")
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
            db.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY, asset_id INTEGER, type TEXT, description TEXT,
                    severity TEXT, evidence TEXT, payload TEXT, detected_at TEXT, confidence REAL
                )
            """)
            # Ensure confidence column exists
            vcols = {row[1] for row in db.execute('PRAGMA table_info(vulnerabilities)').fetchall()}
            if 'confidence' not in vcols:
                db.execute("ALTER TABLE vulnerabilities ADD COLUMN confidence REAL")

            # Ensure activities table exists
            db.execute("""
                CREATE TABLE IF NOT EXISTS activities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT,
                    message TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                )
            """)
            # Migrate/ensure columns expected by AssetManager.activity mappings
            try:
                acols = {row[1] for row in db.execute('PRAGMA table_info(activities)').fetchall()}
                if 'timestamp' not in acols:
                    db.execute("ALTER TABLE activities ADD COLUMN timestamp TEXT")
                if 'action' not in acols:
                    db.execute("ALTER TABLE activities ADD COLUMN action TEXT")
                if 'details' not in acols:
                    db.execute("ALTER TABLE activities ADD COLUMN details TEXT")
                if 'target' not in acols:
                    db.execute("ALTER TABLE activities ADD COLUMN target TEXT")
                # Optional status column for richer logging
                if 'status' not in acols:
                    db.execute("ALTER TABLE activities ADD COLUMN status TEXT")
            except Exception:
                pass
            # Ensure scope table exists with universal schema (domain/is_active)
            db.execute("""
                CREATE TABLE IF NOT EXISTS scope (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE,
                    is_active INTEGER NOT NULL DEFAULT 1
                )
            """)
            # Cookies table for per-domain session persistence and policies
            db.execute("""
                CREATE TABLE IF NOT EXISTS cookies (
                    domain TEXT PRIMARY KEY,
                    cookie TEXT,
                    persistent TEXT,   -- JSON array of 'key=value'
                    auth_keys TEXT,    -- JSON array of cookie names considered auth
                    last_updated TEXT DEFAULT (datetime('now')),
                    policy TEXT        -- JSON object with headers/bearer/login/storage
                )
            """)
            # Ensure columns exist (migrations for existing DBs)
            ccols = {row[1] for row in db.execute('PRAGMA table_info(cookies)').fetchall()}
            if 'persistent' not in ccols:
                db.execute("ALTER TABLE cookies ADD COLUMN persistent TEXT")
            if 'auth_keys' not in ccols:
                db.execute("ALTER TABLE cookies ADD COLUMN auth_keys TEXT")
            if 'policy' not in ccols:
                db.execute("ALTER TABLE cookies ADD COLUMN policy TEXT")
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

@app.route('/api/cleanup/test-paths', methods=['POST'])
def cleanup_test_paths():
    """Remove assets with obvious test/random paths that are likely uninteresting."""
    try:
        import sqlite3
        
        # Patterns for obvious test/random paths
        test_patterns = [
            # Numeric paths
            "url LIKE '%/1' OR url LIKE '%/2' OR url LIKE '%/3' OR url LIKE '%/4' OR url LIKE '%/5'",
            "url LIKE '%/10' OR url LIKE '%/11' OR url LIKE '%/12' OR url LIKE '%/13' OR url LIKE '%/14'",
            "url LIKE '%/20' OR url LIKE '%/21' OR url LIKE '%/22' OR url LIKE '%/23' OR url LIKE '%/24'",
            "url LIKE '%/30' OR url LIKE '%/31' OR url LIKE '%/32' OR url LIKE '%/33' OR url LIKE '%/34'",
            "url LIKE '%/40' OR url LIKE '%/41' OR url LIKE '%/42' OR url LIKE '%/43' OR url LIKE '%/44'",
            "url LIKE '%/50' OR url LIKE '%/51' OR url LIKE '%/52' OR url LIKE '%/53' OR url LIKE '%/54'",
            # Test parameters
            "url LIKE '%?id=test%' OR url LIKE '%?q=test%' OR url LIKE '%?search=test%'",
            "url LIKE '%?page=test%' OR url LIKE '%?user=test%' OR url LIKE '%?Article=test%'",
            "url LIKE '%?CKEditorFuncNum=test%'",
            # Other test paths
            "url LIKE '%/test%' OR url LIKE '%/random%' OR url LIKE '%/example%'"
        ]
        
        # Combine all patterns
        where_clause = " OR ".join(f"({pattern})" for pattern in test_patterns)
        
        # Count assets to be deleted
        conn = sqlite3.connect('lean_recon.db')
        cursor = conn.cursor()
        
        count_query = f"SELECT COUNT(*) FROM assets WHERE {where_clause}"
        cursor.execute(count_query)
        count_to_delete = cursor.fetchone()[0]
        
        if count_to_delete == 0:
            conn.close()
            return jsonify({"success": True, "deleted": 0, "message": "No test paths found"})
        
        # Delete the assets
        delete_query = f"DELETE FROM assets WHERE {where_clause}"
        cursor.execute(delete_query)
        conn.commit()
        conn.close()
        
        app.logger.info(f"Cleaned up {count_to_delete} test/random path assets")
        return jsonify({"success": True, "deleted": count_to_delete})
        
    except Exception as e:
        app.logger.error(f"Error in cleanup_test_paths: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/modscan_findings')
def modscan_findings():
    """Get recent ModScan++ findings from findings.jsonl"""
    try:
        findings_file = Path(__file__).parent / "findings.jsonl"
        if not findings_file.exists():
            return jsonify({"findings": [], "total": 0})
        
        findings = []
        with findings_file.open('r') as f:
            for line in f:
                try:
                    finding = json.loads(line.strip())
                    findings.append(finding)
                except:
                    continue
        
        # Sort by timestamp, newest first
        findings.sort(key=lambda x: x.get('ts', ''), reverse=True)
        
        # Get pagination params
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 25))
        vuln_type = request.args.get('type', '')
        
        # Filter by type if specified
        if vuln_type:
            findings = [f for f in findings if f.get('category', '').lower() == vuln_type.lower()]
        
        # Paginate
        total = len(findings)
        start = (page - 1) * per_page
        end = start + per_page
        paginated = findings[start:end]
        
        return jsonify({
            "findings": paginated,
            "page": page,
            "per_page": per_page,
            "total": total
        })
        
    except Exception as e:
        app.logger.error(f"Error in modscan_findings: {e}")
        return jsonify({"error": str(e)})

# ===== Terminal Log Viewer API =====

@app.route('/api/logs/files', methods=['GET'])
def get_log_files():
    """Get list of available log files"""
    try:
        log_files = []
        base_dir = Path(__file__).parent
        
        # Main log files
        main_logs = ['engine.log', 'dashboard.log', 'main.log']
        for log_file in main_logs:
            log_path = base_dir / log_file
            if log_path.exists():
                log_files.append({
                    'name': log_file,
                    'path': str(log_path),
                    'size': log_path.stat().st_size,
                    'modified': log_path.stat().st_mtime
                })
        
        # Logs directory
        logs_dir = base_dir / 'logs'
        if logs_dir.exists():
            for log_file in logs_dir.glob('*.log'):
                log_files.append({
                    'name': f"logs/{log_file.name}",
                    'path': str(log_file),
                    'size': log_file.stat().st_size,
                    'modified': log_file.stat().st_mtime
                })
        
        # Sort by modification time, newest first
        log_files.sort(key=lambda x: x['modified'], reverse=True)
        
        return jsonify({"log_files": log_files})
        
    except Exception as e:
        app.logger.error(f"Error getting log files: {e}")
        return jsonify({"error": str(e), "log_files": []})

@app.route('/api/logs/content', methods=['GET'])
def get_log_content():
    """Get log file content with tail functionality"""
    try:
        log_file = request.args.get('file', 'engine.log')
        lines = int(request.args.get('lines', 100))
        follow = request.args.get('follow', 'false').lower() == 'true'
        
        # Security: only allow reading log files
        allowed_logs = ['engine.log', 'dashboard.log', 'main.log']
        base_dir = Path(__file__).parent
        
        if log_file.startswith('logs/'):
            log_path = base_dir / log_file
        else:
            if log_file not in allowed_logs:
                return jsonify({"error": "Access denied to this log file"})
            log_path = base_dir / log_file
        
        if not log_path.exists():
            return jsonify({"content": f"Log file {log_file} not found", "lines": 0})
        
        # Read last N lines of the file
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            all_lines = f.readlines()
            
        # Get last N lines
        if lines > 0:
            content_lines = all_lines[-lines:]
        else:
            content_lines = all_lines
            
        content = ''.join(content_lines)
        
        return jsonify({
            "content": content,
            "lines": len(content_lines),
            "total_lines": len(all_lines),
            "file": log_file,
            "size": log_path.stat().st_size
        })
        
    except Exception as e:
        app.logger.error(f"Error reading log content: {e}")
        return jsonify({"error": str(e), "content": ""})

@app.route('/api/logs/stream', methods=['GET'])
def stream_log():
    """Stream log file updates in real-time"""
    try:
        log_file = request.args.get('file', 'engine.log')
        
        # Security check
        allowed_logs = ['engine.log', 'dashboard.log', 'main.log']
        base_dir = Path(__file__).parent
        
        if log_file.startswith('logs/'):
            log_path = base_dir / log_file
        else:
            if log_file not in allowed_logs:
                return jsonify({"error": "Access denied"})
            log_path = base_dir / log_file
        
        if not log_path.exists():
            return jsonify({"error": f"Log file {log_file} not found"})
        
        def generate():
            try:
                with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                    # Go to end of file
                    f.seek(0, 2)
                    
                    while True:
                        line = f.readline()
                        if line:
                            yield f"data: {json.dumps({'line': line.rstrip(), 'timestamp': time.time()})}\n\n"
                        else:
                            time.sleep(0.5)  # Wait for new content
            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
        
        response = make_response(generate())
        response.headers['Content-Type'] = 'text/event-stream'
        response.headers['Cache-Control'] = 'no-cache'
        response.headers['Connection'] = 'keep-alive'
        response.headers['Access-Control-Allow-Origin'] = '*'
        
        return response
        
    except Exception as e:
        app.logger.error(f"Error streaming log: {e}")
        return jsonify({"error": str(e)})

@app.route('/api/logs/clear', methods=['POST'])
def clear_logs():
    """Delete log files for a clean workspace (non-destructive to code)."""
    try:
        base_dir = Path(__file__).parent
        logs_dir = base_dir / 'logs'
        removed = []
        patterns = [
            'engine.log', 'dashboard.log', 'main.log',
            'dashboard.log.*', 'engine.log.*', 'main.log.*'
        ]
        # Remove top-level logs
        for pat in patterns:
            for p in base_dir.glob(pat):
                try:
                    p.unlink()
                    removed.append(str(p))
                except Exception:
                    pass
        # Remove logs in logs/
        if logs_dir.exists():
            for p in logs_dir.glob('*.log*'):
                try:
                    p.unlink()
                    removed.append(str(p))
                except Exception:
                    pass
        return jsonify({"success": True, "removed": removed, "count": len(removed)})
    except Exception as e:
        app.logger.error(f"Error clearing logs: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/cookies/persist', methods=['POST'])
def persist_cookie_keys():
    """Set or update persistent cookie key=val pairs for a domain."""
    try:
        data = request.get_json() or {}
        domain = (data.get('domain') or '').strip()
        pairs = data.get('pairs') or []  # list of 'key=value'
        if not domain:
            return jsonify({"success": False, "error": "Domain is required"}), 400
        # Normalize pairs
        cleaned = []
        for p in pairs:
            if isinstance(p, str) and '=' in p:
                k, v = p.split('=', 1)
                k = k.strip(); v = v.strip()
                if k:
                    cleaned.append(f"{k}={v}")
        import json
        with sqlite3.connect(app.config['database_path']) as db:
            # Merge with existing persistent
            row = db.execute("SELECT persistent FROM cookies WHERE domain=?", (domain,)).fetchone()
            existing = []
            if row and row[0]:
                try:
                    existing = json.loads(row[0])
                except Exception:
                    existing = []
            # Merge/override by key
            merged_map = {}
            for kv in existing:
                if isinstance(kv, str) and '=' in kv:
                    k, v = kv.split('=', 1)
                    merged_map[k.strip()] = v.strip()
            for kv in cleaned:
                k, v = kv.split('=', 1)
                merged_map[k.strip()] = v.strip()
            merged = [f"{k}={v}" for k, v in merged_map.items()]
            db.execute("INSERT INTO cookies(domain, persistent, last_updated) VALUES(?, ?, datetime('now'))\n                       ON CONFLICT(domain) DO UPDATE SET persistent=excluded.persistent, last_updated=excluded.last_updated",
                       (domain, json.dumps(merged)))
            db.commit()
        return jsonify({"success": True, "domain": domain, "persistent": merged})
    except Exception as e:
        app.logger.error(f"Persist cookie error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/admin/reset_db', methods=['POST'])
def reset_db():
    """Clear core data tables (assets, vulnerabilities, activities) but preserve scope and cookies."""
    try:
        removed = {"assets": 0, "vulnerabilities": 0, "activities": 0}
        with sqlite3.connect(app.config['database_path']) as db:
            db.row_factory = sqlite3.Row
            # Count and delete
            for table in ("assets", "vulnerabilities", "activities"):
                try:
                    c = db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                except Exception:
                    c = 0
                removed[table] = c
                try:
                    db.execute(f"DELETE FROM {table}")
                except Exception:
                    pass
            db.commit()
            try:
                db.execute("VACUUM")
            except Exception:
                pass
        # Also clear scan registry file if present
        try:
            reg_path = Path(__file__).resolve().parent / 'scan_registry.json'
            if reg_path.exists():
                reg_path.write_text('{}', encoding='utf-8')
        except Exception:
            pass
        return jsonify({"success": True, "removed": removed})
    except Exception as e:
        app.logger.error(f"DB reset error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

# ===== Service Control =====

@app.route('/api/restart_services', methods=['POST'])
def restart_services():
    """Kill existing engine processes, clear logs, and start engine (optionally with auth)."""
    try:
        data = request.get_json() or {}
        domain = (data.get('domain') or '').strip()
        cookie_string = data.get('cookie') or ''

        # Kill existing engine processes
        killed = 0
        try:
            current_pid = os.getpid()
            for proc in psutil.process_iter(["pid", "cmdline"]):
                if proc.info.get("pid") == current_pid:
                    continue
                cmdline = " ".join(proc.info.get("cmdline") or [])
                if "engine.py" in cmdline and "python" in cmdline:
                    proc.kill()
                    killed += 1
        except Exception as e:
            app.logger.warning(f"Process kill warning: {e}")

        # Clear logs (engine/dashboard/main, both top-level and logs/)
        removed = []
        try:
            base_dir = Path(__file__).parent
            logs_dir = base_dir / 'logs'
            patterns = [
                'engine.log', 'dashboard.log', 'main.log',
                'dashboard.log.*', 'engine.log.*', 'main.log.*'
            ]
            for pat in patterns:
                for p in base_dir.glob(pat):
                    try:
                        p.unlink()
                        removed.append(str(p))
                    except Exception:
                        pass
            if logs_dir.exists():
                for p in logs_dir.glob('*.log*'):
                    try:
                        p.unlink()
                        removed.append(str(p))
                    except Exception:
                        pass
        except Exception as e:
            app.logger.warning(f"Log clear warning: {e}")

        # Default to sole saved session if none explicitly provided
        if not domain and not cookie_string:
            try:
                with sqlite3.connect(app.config['database_path']) as db:
                    rows = list(db.execute("SELECT domain, cookie, persistent FROM cookies").fetchall())
                    if len(rows) == 1:
                        domain = rows[0][0]
                        cookie_string = rows[0][1] or ''
                        if rows[0][2]:
                            cookie_string = _merge_persistent_cookie(cookie_string, rows[0][2])
                        app.logger.info(f"Default-auth restart using saved session for {domain}")
            except Exception as e:
                app.logger.warning(f"Default-auth selection failed: {e}")

        # Resolve cookie if domain provided
        env = os.environ.copy()
        if domain:
            # If cookie not provided, try to fetch from DB
            if not cookie_string:
                try:
                    with sqlite3.connect(app.config['database_path']) as db:
                        row = db.execute("SELECT cookie, persistent FROM cookies WHERE domain=?", (domain,)).fetchone()
                        if row:
                            cookie_string = row[0] or ''
                            # Merge persistent if present
                            if row[1]:
                                cookie_string = _merge_persistent_cookie(cookie_string, row[1])
                except Exception:
                    pass
            else:
                # Merge persistent policy and persist back
                try:
                    with sqlite3.connect(app.config['database_path']) as db:
                        row = db.execute("SELECT persistent FROM cookies WHERE domain=?", (domain,)).fetchone()
                        if row and row[0]:
                            cookie_string = _merge_persistent_cookie(cookie_string, row[0])
                        db.execute(
                            "INSERT INTO cookies(domain, cookie, last_updated) VALUES(?,?,datetime('now'))\n                             ON CONFLICT(domain) DO UPDATE SET cookie=excluded.cookie, last_updated=excluded.last_updated",
                            (domain, cookie_string or '')
                        )
                        db.commit()
                except Exception:
                    pass

            # Set env for auth if we have cookie
            if cookie_string:
                env['MODSCAN_AUTH_DOMAIN'] = domain
                env['MODSCAN_AUTH_COOKIE'] = cookie_string
        # Create placeholder logs so UI doesn't show not-found
        try:
            logs_dir = Path(__file__).parent / 'logs'
            logs_dir.mkdir(parents=True, exist_ok=True)
            for name in ('engine.log', 'dashboard.log', 'main.log'):
                p = logs_dir / name
                if not p.exists():
                    p.touch()
        except Exception:
            pass

        # Force run immediately
        env['MODSCAN_TTL_HOURS'] = '0'
        subprocess.Popen(['python3', 'engine.py'], env=env)
        app.logger.info(f"Engine restarted. Killed={killed}, Logs cleared={len(removed)}")

        # Kick off background enrichment for quick status/title population
        try:
            import threading
            threading.Thread(target=_background_enrich, args=(domain, cookie_string, 500), daemon=True).start()
            app.logger.info("Background enrichment started")
        except Exception as e:
            app.logger.warning(f"Failed to start background enrichment: {e}")

        return jsonify({"success": True, "killed": killed, "logs_cleared": len(removed)})
    except Exception as e:
        app.logger.error(f"Restart services error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

def _background_enrich(domain: str, cookie_string: str, limit: int = 150):
    """Populate status/title/time for assets missing status_code in background."""
    try:
        import asyncio, aiohttp, re, time as _time
        # Pull targets
        with sqlite3.connect(app.config['database_path']) as db:
            db.row_factory = sqlite3.Row
            if domain:
                cursor = db.execute(
                    """
                    SELECT id, url FROM assets 
                    WHERE status_code IS NULL AND url LIKE ?
                    ORDER BY id DESC LIMIT ?
                    """, (f"%://{domain}/%", limit)
                )
            else:
                cursor = db.execute(
                    "SELECT id, url FROM assets WHERE status_code IS NULL ORDER BY id DESC LIMIT ?",
                    (limit,)
                )
            targets = [(row[0], row[1]) for row in cursor.fetchall()]
        if not targets:
            return

        headers = {"User-Agent": "ModScan Enricher/1.0"}
        if cookie_string:
            headers["Cookie"] = cookie_string

        async def fetch_update(session, item):
            asset_id, url = item
            t0 = _time.monotonic()
            try:
                async with session.get(url, allow_redirects=True, timeout=15) as resp:
                    txt = await resp.text()
                    dt = int((_time.monotonic() - t0) * 1000)
                    m = re.search(r"<title[^>]*>(.*?)</title>", txt, re.I | re.S)
                    title = (m.group(1).strip() if m else 'Unknown')
                    content_len = len(txt.encode('utf-8', 'ignore'))
                    with sqlite3.connect(app.config['database_path']) as db:
                        db.execute(
                            """
                            UPDATE assets
                            SET status_code=?, title=?, content_length=?, response_time=?, last_scanned=datetime('now')
                            WHERE id=?
                            """,
                            (resp.status, title, content_len, dt, asset_id)
                        )
                        db.commit()
                    return True
            except Exception:
                try:
                    # Fallback: if HTTPS fails, try HTTP for same path
                    from urllib.parse import urlsplit, urlunsplit
                    sp = urlsplit(url)
                    if sp.scheme.lower() == 'https':
                        http_url = urlunsplit(('http', sp.netloc, sp.path or '/', sp.query, ''))
                        try:
                            async with session.get(http_url, allow_redirects=True, timeout=10) as r2:
                                txt2 = await r2.text()
                                dt2 = int((_time.monotonic() - t0) * 1000)
                                import re as _re
                                m2 = _re.search(r"<title[^>]*>(.*?)</title>", txt2, _re.I | _re.S)
                                title2 = (m2.group(1).strip() if m2 else 'Unknown')
                                clen2 = len(txt2.encode('utf-8', 'ignore'))
                                with sqlite3.connect(app.config['database_path']) as db2:
                                    db2.execute(
                                        """
                                        UPDATE assets
                                        SET status_code=?, title=?, content_length=?, response_time=?, last_scanned=datetime('now')
                                        WHERE id=?
                                        """,
                                        (r2.status, title2, clen2, dt2, asset_id)
                                    )
                                    db2.commit()
                                return True
                        except Exception:
                            pass
                    # Final: just bump last_scanned to avoid hammering
                    with sqlite3.connect(app.config['database_path']) as db3:
                        db3.execute("UPDATE assets SET last_scanned=datetime('now') WHERE id=?", (asset_id,))
                        db3.commit()
                except Exception:
                    pass
                return False

        async def run_enrichment():
            conn = aiohttp.TCPConnector(limit=20, ssl=False)
            async with aiohttp.ClientSession(headers=headers, connector=conn) as session:
                tasks = [fetch_update(session, it) for it in targets]
                await asyncio.gather(*tasks, return_exceptions=True)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(run_enrichment())
        loop.close()
    except Exception as e:
        try:
            app.logger.warning(f"Background enrich error: {e}")
        except Exception:
            pass

# ===== IDOR Testing API Endpoints =====

@app.route('/api/credentials', methods=['GET'])
def get_credentials():
    """Get all stored credential sets"""
    try:
        # Placeholder: start with no baked-in credentials (universal)
        credentials = []
        return jsonify({"success": True, "credentials": credentials})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/credentials', methods=['POST'])
def add_credential():
    """Add a new credential set"""
    try:
        data = request.get_json()
        name = data.get('name')
        session_cookie = data.get('session_cookie')
        role = data.get('role', 'user')
        user_id = data.get('user_id', '')
        description = data.get('description', '')
        
        if not name or not session_cookie:
            return jsonify({"success": False, "error": "Name and session cookie are required"}), 400
        
        # In a full implementation, save to database
        # For now, just validate and return success
        
        return jsonify({
            "success": True,
            "message": f"Credential set '{name}' added successfully",
            "credential": {
                "name": name,
                "role": role,
                "user_id": user_id,
                "description": description
            }
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/automated-burp-test', methods=['POST'])
def run_automated_burp_test():
    """Run comprehensive automated Burp-style vulnerability testing"""
    try:
        data = request.get_json()
        target_url = data.get('target_url', '')
        
        # Import and initialize automated tester
        import sys
        import os
        sys.path.append(os.path.join(os.path.dirname(__file__), 'modules'))
        from automated_burp_testing import AutomatedBurpTester
        
        tester = AutomatedBurpTester(asset_manager, config)
        
        # Run automated testing
        async def run_test():
            findings = await tester.run_automated_testing(target_url)
            await tester.save_findings_to_db(findings)
            return findings
        
        findings = asyncio.run(run_test())
        
        findings_data = []
        for finding in findings:
            findings_data.append({
                'type': finding['type'],
                'severity': finding['severity'],
                'url': finding['url'],
                'evidence': finding['evidence'],
                'parameter': finding.get('parameter', 'N/A'),
                'payload': finding.get('payload', 'N/A')
            })
        
        return jsonify({
            "success": True,
            "findings_count": len(findings),
            "findings": findings_data,
            "message": f"Automated testing complete. Found {len(findings)} potential vulnerabilities."
        })
        
    except Exception as e:
        app.logger.error(f"Automated testing failed: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/idor-test', methods=['POST'])
def run_idor_test():
    """Run comprehensive IDOR testing with multiple credentials"""
    try:
        data = request.get_json()
        target_url = data.get('target_url', '')
        credentials = data.get('credentials', [])
        
        if not credentials:
            return jsonify({"success": False, "error": "At least one credential set is required"}), 400
        
        # Import and initialize IDOR tester
        import sys
        sys.path.append('/home/michael/recon-platform/modscan/modules')
        from multi_credential_idor_tester import MultiCredentialIDORTester, Credential
        from asset_manager import AssetManager
        
        # Initialize components
        asset_manager = AssetManager()
        config = {"test_credentials": credentials}
        idor_tester = MultiCredentialIDORTester(asset_manager, config)
        
        # Run IDOR testing
        import asyncio
        import aiohttp
        
        async def run_test():
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=30)) as session:
                findings = await idor_tester.test_idor_vulnerabilities(session)
                return findings
        
        # Execute the test
        findings = asyncio.run(run_test())
        
        # Convert findings to JSON serializable format
        findings_data = []
        for finding in findings:
            findings_data.append({
                "url": finding.url,
                "vuln_type": finding.vuln_type,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "source_user": finding.source_user,
                "target_user": finding.target_user,
                "payload": finding.payload,
                "evidence": finding.evidence,
                "discovered_at": finding.discovered_at.isoformat()
            })
        
        return jsonify({
            "success": True,
            "message": f"IDOR testing completed - {len(findings)} vulnerabilities found",
            "findings": findings_data,
            "test_summary": {
                "credentials_tested": len(credentials),
                "vulnerabilities_found": len(findings),
                "critical": len([f for f in findings if f.severity == 'CRITICAL']),
                "high": len([f for f in findings if f.severity == 'HIGH']),
                "medium": len([f for f in findings if f.severity == 'MEDIUM'])
            }
        })
        
    except Exception as e:
        app.logger.error(f"IDOR testing error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/response-compare', methods=['POST'])
def compare_responses():
    """Compare two HTTP responses for differences"""
    try:
        data = request.get_json()
        url = data.get('url')
        credential1 = data.get('credential1')
        credential2 = data.get('credential2')
        
        if not all([url, credential1, credential2]):
            return jsonify({"success": False, "error": "URL and both credentials are required"}), 400
        
        import asyncio
        import aiohttp
        
        async def fetch_responses():
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=15)) as session:
                # Fetch with credential 1
                headers1 = {'Cookie': credential1.get('session_cookie', '')}
                async with session.get(url, headers=headers1) as response1:
                    text1 = await response1.text()
                    status1 = response1.status
                
                # Fetch with credential 2  
                headers2 = {'Cookie': credential2.get('session_cookie', '')}
                async with session.get(url, headers=headers2) as response2:
                    text2 = await response2.text()
                    status2 = response2.status
                
                return (text1, status1), (text2, status2)
        
        # Get responses
        (response1, status1), (response2, status2) = asyncio.run(fetch_responses())
        
        # Import response comparator
        import sys
        sys.path.append('/home/michael/recon-platform/modscan/modules')
        from multi_credential_idor_tester import ResponseComparator
        
        # Analyze differences
        similarity = ResponseComparator.calculate_response_similarity(response1, response2)
        sensitive_data1 = ResponseComparator.extract_sensitive_data(response1)
        sensitive_data2 = ResponseComparator.extract_sensitive_data(response2)
        leakage = ResponseComparator.identify_data_leakage(response1, response2, credential2.get('name', 'user2'))
        
        # Generate diff
        import difflib
        diff = list(difflib.unified_diff(
            response1.splitlines(keepends=True),
            response2.splitlines(keepends=True),
            fromfile=f"{credential1.get('name', 'user1')}_response",
            tofile=f"{credential2.get('name', 'user2')}_response",
            n=3
        ))
        
        return jsonify({
            "success": True,
            "comparison": {
                "similarity": similarity,
                "status_codes": {"user1": status1, "user2": status2},
                "response_lengths": {"user1": len(response1), "user2": len(response2)},
                "sensitive_data": {
                    "user1": sensitive_data1,
                    "user2": sensitive_data2
                },
                "data_leakage": leakage,
                "diff": ''.join(diff[:100])  # Limit diff size
            }
        })
        
    except Exception as e:
        app.logger.error(f"Response comparison error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        init_db_and_scope()
    app.run(host=app.config['dashboard_host'], port=app.config['dashboard_port'], debug=False)
# ===== Scope API (DB-backed) =====

def _scope_db_path():
    # Honor env var you already export; fallback to project DB file
    return os.environ.get("MODSCAN_DB", os.path.abspath("lean_recon.db"))

def _scope_conn():
    return sqlite3.connect(_scope_db_path())

def _normalize_domain(d: str) -> str:
    return (d or "").strip().lower()
@app.route('/api/admin/migrate', methods=['POST'])
def run_migrations():
    """Run lightweight DB migrations (safe to run while engine is active)."""
    try:
        init_db_and_scope()
        return jsonify({"success": True, "message": "Migrations applied"})
    except Exception as e:
        app.logger.error(f"Migration error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500
# ===== Code Audit (Unused Scripts) =====
# (Removed interactive audit/delete endpoints per request; keep code cleanup manual)
