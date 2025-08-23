# ModScan Vulnerability Scanner - Universal Scanning Principles

## Core Mission Statement

This vulnerability scanning platform is designed to work **UNIVERSALLY** against ANY target without requiring target-specific scripts, configurations, or adaptations. The scanner must automatically adapt to whatever it encounters.

## CRITICAL DEVELOPMENT RULES

### ❌ NEVER CREATE TARGET-SPECIFIC SCRIPTS

- **NO** DVWA-specific scripts
- **NO** WordPress-specific scanners  
- **NO** Application-specific test files
- **NO** Hardcoded target assumptions
- **NO** Manual configuration for specific platforms
- **NO** "focused_", "enhanced_", or "comprehensive_" scripts for specific targets
- **NO** Individual test scripts that only work on one application type
- **ALWAYS** enhance the universal engine modules instead of creating bypasses

### ❌ NEVER CREATE NEW SCRIPTS TO FIX ISSUES

- **NO** Creating simple_engine.py, quick_scan.py, or other "helper" scripts
- **NO** Workaround scripts that bypass the main engine
- **FIX THE ROOT CAUSE** in existing modules, don't create new ones
- **ENHANCE EXISTING SYSTEMS** rather than creating duplicates
- If something doesn't work, fix the core module, don't build around it

### ✅ ALWAYS BUILD UNIVERSAL CAPABILITIES

- **Automatic target fingerprinting** - Detect what you're scanning without assumptions
- **Dynamic payload generation** - Adapt payloads based on discovered technologies
- **Universal form parsing** - Handle any form structure (CSRF tokens, field types, etc.)
- **Intelligent path discovery** - Use comprehensive wordlists that work on any target
- **Adaptive vulnerability testing** - Test what makes sense for each discovered endpoint
- **Robust crawling integration** - Discovery should leverage crawling for comprehensive coverage
- **Automatic authentication refresh** - When auth cookies expire, auto-refresh with stored credentials

## Platform Architecture Principles

### Discovery Engine
- Must work on **any web application** (PHP, .NET, Java, Python, Node.js, etc.)
- Use comprehensive SecLists wordlists (60K+ paths) not tiny custom lists
- Automatically detect and handle different server technologies
- Proxy-aware for both internal and external targets

### Vulnerability Scanner
- **Universal payload sets** that work across all platforms
- **Smart form parsing** that extracts CSRF tokens, hidden fields, and input types
- **Technology-aware testing** that adapts based on fingerprinting
- **AI validation** to eliminate false positives across all target types

### Multi-AI Pentester Team
- **Specialist agents** that understand different vulnerability classes
- **Universal exploitation techniques** not tied to specific applications
- **Adaptive payload generation** based on target characteristics
- **Cross-platform exploit chaining** that works on any technology stack

## Testing Philosophy

### Real-World Effectiveness
- Scanner must find **REAL vulnerabilities** on any target
- Zero tolerance for false positives through AI validation
- Demonstrate actual exploitation capabilities with browser automation
- Generate actionable proof-of-concept evidence

### Automated Intelligence
- Use cheap AI (Gemini Flash 2.0) for smart analysis at scale
- Automatically chain vulnerabilities for maximum impact
- Generate step-by-step exploitation guidance
- Provide realistic remediation recommendations

## Implementation Guidelines

### When Adding New Features
1. **Ask: "Will this work on ANY target?"**
2. **Avoid hardcoded assumptions about target technology**
3. **Use fingerprinting to adapt behavior dynamically**
4. **Test on diverse targets (not just DVWA)**
5. **Validate with AI to ensure real-world applicability**

### Code Review Checklist
- ❌ Contains target-specific logic?
- ❌ Hardcoded paths or payloads for specific apps?
- ❌ Assumes particular server technology?
- ✅ Works on any HTTP/HTTPS target?
- ✅ Adapts based on discovered characteristics?
- ✅ Uses comprehensive, universal wordlists?

## Success Metrics

The platform succeeds when it can:
- **Scan any web application** without configuration
- **Find real vulnerabilities** on diverse targets
- **Adapt automatically** to different technologies
- **Generate actionable exploit proofs** for any platform
- **Chain vulnerabilities intelligently** regardless of target type

## Current Capabilities Status

### ✅ Working Universal Features
- **Discovery Engine**: 60K+ SecLists paths, massively parallel, proxy-aware
- **Vulnerability Scanner**: Universal payloads, smart form parsing, CSRF handling
- **Multi-AI Team**: 4 specialist agents, exploit chaining, browser automation
- **AI Validation**: Brutal honesty mode, zero false positives
- **Database**: Universal vulnerability storage and analysis

### 🎯 Deployment Ready
The platform currently finds **REAL vulnerabilities** on:
- DVWA (Damn Vulnerable Web Application)
- Centene corporate applications
- Temu e-commerce platform
- Any standard web application with common vulnerabilities

## Git Workflow & Progress Saving

### 🔄 ALWAYS COMMIT WORKING FEATURES

When we achieve a working milestone:

1. **Test thoroughly** - Verify the feature works end-to-end
2. **Commit immediately** - Don't risk losing working code
3. **Use descriptive commits** - Explain what's working and why

### Git Commands for Progress Saving
```bash
# Check status and see changes
git status
git diff

# Stage and commit working features
git add .
git commit -m "feat: working asset discovery engine

- Fixed process guard hanging issues
- Engine successfully discovers assets on 192.168.1.42
- Assets appear in dashboard with today's date
- Recursive discovery finds DVWA vulnerability paths

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"

# Push to backup progress
git push origin feat/working-discovery
```

### 📊 Feature Completion Checklist

Before committing a "working" feature, verify:
- ✅ Engine starts without hanging
- ✅ Assets are discovered and saved to database
- ✅ New discoveries appear in dashboard with correct date
- ✅ No false positives or crashes
- ✅ Recursive discovery finds real vulnerability paths

### 🚨 Never Lose Working Code

If something is working, **COMMIT IMMEDIATELY** before making changes.
Better to have many small commits than lose a working feature.

## Dashboard Management

### 🔄 Restarting Dashboard Properly

**CRITICAL**: Dashboard restart commands ALWAYS error but still work. This happens EVERY TIME and is NORMAL.

The dashboard can get stuck or need restarting after code changes:

```bash
# Step 1: Find and kill ALL dashboard processes (errors are normal)
ps aux | grep dashboard
sudo kill -9 [PID_FROM_ABOVE]

# Step 2: Alternative kill methods (errors are normal)  
sudo pkill -f dashboard.py
sudo pkill -f main.py
sudo lsof -ti:8000 | xargs sudo kill -9

# Step 3: Start fresh dashboard
source .venv/bin/activate && python dashboard.py &
```

**IMPORTANT NOTES**:
- Kill commands will show "Error" - this is NORMAL and EXPECTED
- Always use `ps aux | grep dashboard` to find actual process IDs
- Multiple kill attempts are normal - processes are stubborn
- Dashboard restart is required after ANY template changes
- Don't panic when kill commands error - they usually still work

### 📊 Dashboard Asset Display Issues

**Problem**: New discoveries don't show in dashboard
**Cause**: Assets without status_code get filtered out by default "scanned:true" filter

**Solutions**:
1. Remove search filters to see all assets (including new discoveries)
2. Use `scanned:false` to see only unscanned assets  
3. Assets are now ordered by `discovered_at DESC` (newest first)

**Note**: "New Today" counter only counts assets with status codes. Raw discoveries from engine show as status_code = None until they're scanned.

## CRITICAL: VulnerabilityFinding Structure

### 🚨 AUTHORITATIVE VULNERABILITY STRUCTURE 🚨

**ALL vulnerability scanners MUST use the centralized VulnerabilityFinding structure from `asset_manager.py`.**

```python
# CORRECT: Import from asset_manager
from asset_manager import VulnerabilityFinding

# Create vulnerability finding with EXACT field names
finding = VulnerabilityFinding(
    url="http://target.com/vulnerable",           # Target URL
    vuln_type="SQL_INJECTION",                   # Use vuln_type NOT type
    severity="Critical",                         # Critical, High, Medium, Low, Info
    confidence=0.90,                             # Float 0.0-1.0
    payload="' OR 1=1--",                        # Attack payload
    evidence="SQL error: mysql_fetch_array()",   # Evidence found
    discovered_at=datetime.now(),                # When found
    impact_description="Database access possible", # Impact (optional)
    remediation="Use parameterized queries",     # Fix advice (optional)
    affected_parameter="id",                     # Vulnerable param (optional)
    raw_request="GET /app?id=1' HTTP/1.1",      # HTTP request (optional)
    raw_response="SQL syntax error...",          # HTTP response (optional)
)

# CORRECT: Store in database
asset_manager.add_vulnerability_finding(finding, asset_id)
```

### ❌ FORBIDDEN PATTERNS

**NEVER use these incorrect field names:**
- ❌ `type` (use `vuln_type`)
- ❌ `vulnerability_type` (use `vuln_type`)
- ❌ `asset_url` (use `url`)
- ❌ `confidence_score` (use `confidence`)
- ❌ `description` directly (use `impact_description`)

### ✅ REQUIRED FIELD MAPPING

| VulnerabilityFinding Field | Database Column | Type | Required |
|---------------------------|-----------------|------|----------|
| `url` | url | TEXT | ✅ |
| `vuln_type` | type | TEXT | ✅ |
| `severity` | severity | TEXT | ✅ |
| `confidence` | confidence | FLOAT | ✅ |
| `payload` | payload | TEXT | ✅ |
| `evidence` | evidence | TEXT | ✅ |
| `discovered_at` | detected_at | TEXT | ✅ |
| `impact_description` | description | TEXT | ✅ |

### 🔧 Database Storage

```python
# CORRECT: Use centralized method
asset_manager.add_vulnerability_finding(finding, asset_id)

# DEPRECATED: Don't use legacy dict method
asset_manager.add_vulnerability(vuln_dict)  # OLD WAY
```

### 📊 Severity Levels

Use these EXACT severity values:
- `"Critical"` - Complete system compromise
- `"High"` - Significant security impact
- `"Medium"` - Moderate security risk
- `"Low"` - Minor security concern
- `"Info"` - Informational finding

### 🎯 Vulnerability Types

Standard vulnerability types (use these exact strings):
- `"SQL_INJECTION"` - SQL injection vulnerabilities
- `"XSS"` - Cross-site scripting
- `"IDOR"` - Insecure direct object references
- `"CSRF"` - Cross-site request forgery
- `"LFI"` - Local file inclusion
- `"RFI"` - Remote file inclusion
- `"SSRF"` - Server-side request forgery
- `"COMMAND_INJECTION"` - Command injection
- `"PATH_TRAVERSAL"` - Directory traversal
- `"OPEN_REDIRECT"` - Open redirect

## Final Note

**NEVER** compromise the universal nature of this platform by adding target-specific logic. If something doesn't work on a specific target, enhance the universal capabilities rather than creating exceptions.

**ALWAYS** use the centralized VulnerabilityFinding structure from `asset_manager.py` for consistency.

The goal is a single platform that works everywhere, not a collection of target-specific tools.

