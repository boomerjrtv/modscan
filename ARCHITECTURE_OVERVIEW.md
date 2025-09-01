# ModScan Universal Vulnerability Scanner - Architecture Overview

## 🏗️ CURRENT SYSTEM STATUS

### ✅ **ACTIVE COMPONENTS**
- **Dashboard/Frontend**: ✅ Running (python3 dashboard.py on port 5000)
- **Scanner Engine**: ✅ Operational with Playwright browser automation
- **Database**: ✅ SQLite with asset management
- **AI Workers**: ✅ 4 specialized pentester agents + 1 coordinator
- **Agentic Browser Loop (ABL)**: ✅ Tier 2.5 intelligent exploration with skill generation

---

## 🧠 **4 AI PENTESTER WORKERS** 

### **1. SQLi Hunter** 🎯
- **Specialty**: SQL Injection Detection
- **Capabilities**: 
  - Advanced SQL payload testing
  - Database fingerprinting
  - Error-based and blind SQLi detection
  - AI-powered payload optimization

### **2. XSS Hunter** 🎭
- **Specialty**: Cross-Site Scripting Detection  
- **Capabilities**:
  - DOM, Stored, and Reflected XSS
  - Context-aware payload generation
  - CSP bypass techniques
  - Browser-based execution validation

### **3. AuthZ Hunter** 🔐
- **Specialty**: Authentication & Authorization Testing
- **Capabilities**:
  - Broken access control detection
  - Privilege escalation testing
  - JWT/session analysis
  - Authorization bypass techniques

### **4. InfoDisc Hunter** 📊
- **Specialty**: Information Disclosure Detection
- **Capabilities**:
  - Sensitive file exposure (robots.txt, .htaccess, etc.)
  - Configuration file leaks
  - Debug info exposure  
  - Directory traversal

### **5. Exploit Chainer** ⛓️
- **Specialty**: Exploit Chain Coordination
- **Role**: Combines findings from all 4 hunters to create exploit chains
- **Capabilities**:

---

## 📋 **UNIVERSAL FORM PARSER**

### **Overview**
The Universal Form Parser (`modules/universal_form_parser.py`) provides target-agnostic HTML form parsing for vulnerability scanning. It automatically adapts to any web application without requiring target-specific configurations.

### **Key Features**
- **Universal Parsing**: Works with any HTML form structure
- **CSRF Token Detection**: Automatically identifies CSRF tokens using common patterns
- **Multiple Input Types**: Supports text, password, hidden, checkbox, radio, select, textarea, file inputs
- **URL Resolution**: Resolves relative form actions to absolute URLs
- **Graceful Degradation**: Falls back to regex parsing when BeautifulSoup unavailable
- **Malformed HTML Handling**: Robust to invalid or incomplete HTML

### **API Functions**

#### `parse_forms(html_content: str, base_url: Optional[str] = None) -> List[Dict]`
Main parsing function that extracts all forms from HTML.

**Returns form structure:**
```python
{
    'action': 'https://example.com/submit',           # Resolved absolute URL
    'method': 'POST',                                 # GET/POST/etc
    'enctype': 'application/x-www-form-urlencoded',   # Form encoding
    'inputs': {
        'username': {'type': 'text', 'value': ''},
        'password': {'type': 'password', 'value': ''},
        'csrf_token': {'type': 'hidden', 'value': 'abc123', 'is_csrf': True},
        'remember': {'type': 'checkbox', 'value': '1', 'checked': False},
        'country': {'type': 'select', 'value': 'US', 'options': ['US', 'CA'], 'multiple': False},
        'comments': {'type': 'textarea', 'value': 'Default text'}
    }
}
```

#### `get_testable_fields(form_inputs: Dict) -> Dict[str, List[str]]`
Categorizes form fields for vulnerability testing.

**Returns:**
```python
{
    'testable': ['username', 'email', 'search'],     # Safe to test with payloads
    'protected': ['csrf_token', 'submit_btn']        # Should preserve values
}
```

#### `build_form_data(form_inputs: Dict, payload_data: Dict[str, str] = None) -> Dict[str, str]`
Builds form submission data, preserving protected fields and applying payloads.

### **Integration with Vulnerability Scanner**
The scanner's `_parse_forms_with_values()` method now delegates to the universal parser:

```python
# OLD: Regex-based parsing (limited, brittle)
forms = await self._parse_forms_with_values(html_content)

# NEW: Universal parser (comprehensive, robust)  
forms = await self._parse_forms_with_values(html_content, base_url)
```

**Benefits:**
- ✅ **Universal**: Works on any web application
- ✅ **CSRF-Aware**: Preserves authentication tokens
- ✅ **Comprehensive**: Handles all input types and form structures
- ✅ **Robust**: Gracefully handles malformed HTML
- ✅ **Performance**: Size limits prevent DoS on large pages

### **CSRF Detection Patterns**
The parser automatically detects CSRF tokens using these patterns:
- `csrf`, `_token`, `authenticity_token`, `request_verification_token`
- `xsrf`, `__RequestVerificationToken`, `csrfmiddlewaretoken`
- `anti_csrf`, `csrf_hash`, `csrf_test_name`, `form_token`, `security_token`

Case-insensitive matching ensures detection across all platforms.

### **Capabilities**:
  - Multi-step attack orchestration
  - Vulnerability correlation
  - Maximum impact exploitation

---

## 🤖 **AGENTIC BROWSER LOOP (ABL)**

The ABL system provides intelligent browser automation that goes beyond static scanning to actively explore applications through dynamic interaction. Integrated as Tier 2.5 in the scanning pipeline, it bridges the gap between passive discovery and active vulnerability testing.

### **Core Components**

#### **Action Schema & Validation**
- **Universal Action Types**: `goto`, `click`, `fill`, `submit`, `evaluate`, `wait_for_selector`, `wait_for_url`
- **Safety Constraints**: HTTPS/HTTP only, allowlisted hosts, timeout enforcement
- **Selector Strategies**: Auto-detection, text-based, role-based, label-based, CSS selectors

#### **Observation Compression**
- **Token-Efficient**: Compresses page content, forms, console messages, network requests
- **Smart Filtering**: Prioritizes errors, API calls, admin endpoints, failed requests
- **Evidence Capture**: Screenshots via ScreenshotManager integration

#### **Trace Export (JSONL)**
```json
{
  "step": 0,
  "timestamp": "2025-08-30T17:51:01.123Z", 
  "action": {"type": "goto", "target": "https://target.com"},
  "observation": {"url": "https://target.com", "title": "App", "forms_summary": [...]},
  "execution_time_ms": 1250
}
```

#### **Skill Generation**
When vulnerability signals are detected, ABL automatically generates deterministic Playwright replay scripts:

**Signal Detection Patterns:**
- **XSS**: `<script>alert()`, `javascript:`, `onerror=`, DOM execution markers
- **SQLi**: SQL syntax errors, `mysql_fetch_array()`, ODBC errors, PostgreSQL errors
- **LFI**: `/etc/passwd`, boot loader signatures, include() errors
- **RCE**: `uid=` output, directory listings, Windows version strings
- **SSRF**: Connection refused to localhost/internal IPs
- **Sensitive**: API keys, passwords, private keys in responses

**Generated Skills Location**: `tools/skills/<session-id>-<signals>.py`

### **Engine Integration (Tier 2.5)**

ABL is triggered after Tier 2 (Profiling) when `agent_enabled: true` for the current scan profile:

```json
// scan_profile.json
{
  "profile": "aggressive",
  "agent_enabled": {
    "stealth": false,
    "normal": false, 
    "aggressive": true
  }
}
```

**Execution Flow:**
1. **CPU Check**: Skip if system load > 75%
2. **Candidate Selection**: Recently profiled assets with status 200/401/403
3. **Budget Enforcement**: Max 12 steps, 8 clicks, 15 seconds per session
4. **Concurrent Exploration**: Up to 3 URLs with 20-second total timeout
5. **Skill Export**: Automatic generation when signals detected

### **Budget System**

Conservative resource constraints maintain scanning performance:

```python
budgets = {
    'max_steps': 12,           # Maximum browser actions
    'max_clicks': 8,           # Click-specific limit  
    'max_time_ms': 15000,      # 15-second session timeout
    'action_timeout': 5000     # 5-second per-action timeout
}
```

### **Universal Principles**

✅ **Target-Agnostic**: Works on any web application without configuration  
✅ **CSRF-Aware**: Integrates with UniversalFormParser for token handling  
✅ **Proxy-Compatible**: Respects ProxyManager configuration  
✅ **Evidence-Rich**: Screenshots and traces for every interaction  
✅ **Safe by Design**: Host allowlists, scheme restrictions, budget enforcement  
✅ **Headless Ready**: No GUI dependencies, perfect for automation  

### **Live Browser View (LAN)**

You can watch any Playwright-driven browser sessions live over your LAN using Chrome DevTools. Toggle with environment variables — no code changes required:

- `MODSCAN_BROWSER_HEADFUL=1`: Run Chromium headful (visible windows if a display is available)
- `MODSCAN_BROWSER_DEVTOOLS=1`: Open DevTools alongside the browser
- `MODSCAN_BROWSER_RDP_PORT=9222`: Expose Remote Debugging on this port
- `MODSCAN_BROWSER_RDP_ADDR=0.0.0.0`: Bind DevTools to all interfaces (LAN access)

Connect from your workstation:
- In Chrome: open `chrome://inspect` → Configure… → add `http://<scanner-host>:<port>` (e.g., `http://192.168.1.50:9222`) → you’ll see pages and can click “inspect”.
- Or open `http://<scanner-host>:<port>/json` to list targets.

Notes:
- Works for ABL, AI Exploit Executor, and ML verification flows.
- If running headless servers without a display, you can still use DevTools remote inspection. Headful windows require a display/X server.

### **Skill Replay Usage**

Generated skills can be replayed independently:

```bash
# Execute a generated skill
python tools/skills/abl_20250830_175101_910d8f18-xss-sqli.py

# Or use future CLI helper  
python scripts/abl_replay.py tools/skills/example-skill.py
```

### **Direct URL Testing Mode**

When `MODSCAN_DIRECT_URL_TESTING` is set, ABL focuses exclusively on provided URLs:

```bash
export MODSCAN_DIRECT_URL_TESTING="https://target.com/login,https://target.com/admin"
python engine.py
```

### **Trace Analysis**

Traces provide detailed interaction history for debugging and analysis:

```bash
# View trace file
cat evidence/trace_abl_20250830_175101_910d8f18.jsonl | jq .

# Extract all actions
cat evidence/trace_*.jsonl | jq '.action.type' | sort | uniq -c
```

---

## ✅ Verification Architecture (Universal)

Every finding is validated with deterministic, target‑agnostic techniques and visible proof:

- SQLi: visible UNION marker in response; payload capture; DBMS fingerprints.
- XSS: reflected marker (<img onerror>); DOM XSS execution flag; screenshots.
- Command Injection: echo marker output in response; screenshots.
- LFI: `/etc/passwd` patterns; screenshots.
- Open Redirect: 3xx Location verification; screenshots.
- SSRF: OOB beacon to collaborator/blind_xss_domain; `/api/oob/callback` ingests confirmations.
- IDOR: swap numeric identifiers and record `state_diff`; screenshots.
- CSRF: missing CSRF token on form render; screenshots.

Evidence includes `Verification: <method>` and `Screenshot: <path>`. Structured records are stored in `vulnerability_verifications` (method, marker, details, screenshot_path, timestamp). The dashboard shows a VERIFIED badge, supports re‑verification, and provides a Proof modal listing verification steps and PoC screenshots.


## 🌊 **SCANNING WORKFLOW DECISION TREE**

```
┌─────────────────────────────────────────┐
│            TARGET INPUT                 │
│         (URL provided)                  │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│          INITIALIZATION                 │
│  • Load SecLists (60K+ wordlists)      │
│  • Initialize 4 AI agents              │  
│  • Setup Playwright browser            │
│  • Configure proxy rotation (30)       │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│         DISCOVERY PHASE                 │
│  • Technology detection                 │
│  • Directory enumeration                │
│  • Endpoint discovery                   │
│  • Form detection                       │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│    AGENTIC EXPLORATION (Tier 2.5)      │
│  • Intelligent browser automation      │
│  • Dynamic form interaction            │
│  • Signal-based skill generation       │
│  • Conservative budget enforcement     │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│      PARALLEL AI TESTING                │
├─────────────────────────────────────────┤
│  ┌─────────┐ ┌─────────┐ ┌─────────┐   │
│  │SQLi     │ │XSS      │ │AuthZ    │   │
│  │Hunter   │ │Hunter   │ │Hunter   │   │
│  └─────────┘ └─────────┘ └─────────┘   │
│              ┌─────────┐               │
│              │InfoDisc │               │
│              │Hunter   │               │
│              └─────────┘               │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│        EXPLOIT CHAINING                 │
│  • Correlate all findings              │
│  • Build multi-step attack chains      │
│  • Prioritize by impact                │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│       BROWSER AUTOMATION                │
│  • Auth automation (generic)           │
│  • Real exploit demonstrations         │
│  • Screenshot evidence capture         │
│  • Interactive vulnerability tests     │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│         REPORTING                       │
│  • Store in SQLite database            │
│  • Update dashboard in real-time       │
│  • Generate exploit proofs             │
│  • Asset management integration        │
└─────────────────────────────────────────┘
```

---

## 🎯 **TARGETING CAPABILITIES**

### **YES - You can test specific URLs:**
```bash
# Single URL scan
python3 engine.py --target http://example.com/

# Specific endpoint  
python3 engine.py --target http://example.com/products?id=1

# Multiple depths
python3 engine.py --target http://example.com --max-depth 3
```

### **Scan Types:**
- **Single URL**: Direct vulnerability testing
- **Domain crawling**: Discovers and tests all endpoints  
- **Depth-limited**: Controls crawling scope (--max-depth)
- **Path-specific**: Focuses on specific application areas

---

## 🖥️ **FRONTEND STATUS**

### **Dashboard Available At:**
- **URL**: http://localhost:5000 (or server IP:5000)
- **Status**: ✅ RUNNING (python3 dashboard.py)
- **Features**:
  - Real-time scan results
  - Vulnerability timeline
  - Asset management interface
  - Exploit proof viewing
  - Screenshot gallery

### **Dashboard Capabilities:**
- Live vulnerability feed
- Interactive scan controls  
- Export reports (JSON/HTML)
- Historical scan comparison
- Risk assessment visualization

---

## 🔧 **TECHNICAL STACK**

### **Core Engine:**
- **Language**: Python 3.10+ with AsyncIO
- **HTTP**: aiohttp for concurrent requests
- **Browser**: Playwright (replaced Selenium)
- **AI**: Gemini 2.0 Flash (4 specialized agents)
- **Database**: SQLite with asset management
- **Wordlists**: SecLists (60K+ entries)

### **Performance:**
- **Concurrency**: Up to 10 parallel requests
- **Proxy Rotation**: 30 rotating proxies  
- **Browser Automation**: Headless Chromium
- **ML Integration**: Vulnerability prediction models
- **Screenshot**: Chrome headless capture

---

## 🚀 **NEXT ACTIONS**

1. **Access Dashboard**: Visit http://your-server-ip:5000
2. **Run Targeted Scan**: Use specific URLs for focused testing
3. **Review AI Findings**: Check the 4 specialist reports
4. **Export Results**: Generate comprehensive reports
5. **Chain Exploits**: Let the Exploit Chainer find attack paths

**Your ModScan platform is fully operational with advanced AI-powered vulnerability detection and browser automation!**
