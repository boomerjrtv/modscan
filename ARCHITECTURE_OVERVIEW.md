# ModScan Universal Vulnerability Scanner - Architecture Overview

## 🏗️ CURRENT SYSTEM STATUS

### ✅ **ACTIVE COMPONENTS**
- **Dashboard/Frontend**: ✅ Running (python3 dashboard.py on port 5000)
- **Scanner Engine**: ✅ Operational with Playwright browser automation
- **Database**: ✅ SQLite with asset management
- **AI Workers**: ✅ 4 specialized pentester agents + 1 coordinator

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
