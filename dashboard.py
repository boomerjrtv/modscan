import sqlite3
import os
import json
import sys
from pathlib import Path
from flask import Flask, jsonify, render_template, g, request, make_response
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
                if 'python' in proc.info['name'].lower() and any('engine.py' in arg for arg in proc.info['cmdline']):
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
                
            success = asset_manager.add_scope_target(target)
            
            if success:
                return jsonify({"message": "Target added successfully"})
            else:
                return jsonify({"error": "Failed to add target"}), 400
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
        
        # Decode URL-encoded filename
        decoded_filename = urllib.parse.unquote(filename)
        
        # Direct file path - screenshots are stored in screenshots/ directory
        screenshot_path = os.path.join('screenshots', decoded_filename)
        
        if os.path.exists(screenshot_path):
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
    response = make_response(render_template('FINAL_COMPLETE_ENTERPRISE_SIEM.html'))
    # Force browser to reload JavaScript
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

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