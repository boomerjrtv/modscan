# ModScan Vulnerability Scanner - Universal Scanning Principles

## Core Mission Statement

This vulnerability scanning platform is designed to work **UNIVERSALLY** against ANY target without requiring target-specific scripts, configurations, or adaptations. The scanner must automatically adapt to whatever it encounters.

## 🎯 PRIMARY BENCHMARK: VulnWeb Complete Discovery

**CRITICAL ONGOING GOAL**: The scanner MUST find ALL vulnerabilities available on the 5 VulnWeb targets. This is our primary benchmark for scanner completeness and professional-grade effectiveness.

### Benchmark Targets (Canonical Test Set)
1. **testphp.vulnweb.com** - PHP/MySQL vulnerabilities
2. **testaspnet.vulnweb.com** - ASP.NET/MSSQL vulnerabilities
3. **testhtml5.vulnweb.com** - HTML5/JavaScript vulnerabilities
4. **testasp.vulnweb.com** - Classic ASP vulnerabilities
5. **rest.vulnweb.com** - REST API vulnerabilities

### Success Criteria
- ✅ **500+ unique vulnerabilities** discovered across all targets
- ✅ **All major OWASP Top 10** vulnerability classes found
- ✅ **Advanced techniques** (XXE, SSTI, business logic, race conditions)
- ✅ **Zero false positives** through AI validation
- ✅ **Professional pentest coverage** equivalent to Burp Pro

### 🚨 CRITICAL: "WORKING" MEANS FINDING **ALL** DOCUMENTED VULNERABILITIES

**A scanner is NOT "working" until it finds EVERY known vulnerability in documented labs:**
- **TryHackMe labs**: Must find ALL endpoints and vulnerabilities listed in official walkthroughs
- **VulnWeb targets**: Must discover ALL 500+ documented vulnerabilities
- **DVWA**: Must detect ALL vulnerability categories at all difficulty levels
- **Partial discovery is FAILURE** - finding 80% of vulnerabilities means the scanner is broken

**NEVER claim success until 100% of documented vulnerabilities are found automatically.**

**📊 Track progress in `VULNERABILITY_BENCHMARK.md`**

**⚡ Current Command**: `python3 engine.py --no-ttl testphp.vulnweb.com testaspnet.vulnweb.com testhtml5.vulnweb.com testasp.vulnweb.com rest.vulnweb.com`

## 💾 DATABASE LOCATIONS

**Primary Database**: `lean_recon.db` - Contains all assets, vulnerabilities, and scan data
**Other Database Files**:
- `knowledge.db` - AI knowledge base
- `modscan.db` - Legacy database (mostly unused)
- `database.db`, `recon.db`, `recon_assets.db`, `recon_platform.db` - Empty/unused

**Database Tables**:
- `assets` - All discovered URLs and endpoints
- `vulnerabilities` - All vulnerability findings (use column `type` not `vuln_type`)
- `scope` - Target scope management
- `activities` - Scan activity logs

## CRITICAL DEVELOPMENT RULES

### ❌ NEVER CREATE TARGET-SPECIFIC SCRIPTS

- **NO** DVWA-specific scripts
- **NO** WordPress-specific scanners  
- **NO** Application-specific test files
- **NO** Hardcoded target assumptions
- **NO** Manual configuration for specific platforms
- **NO** "focused_", "enhanced_", or "comprehensive_" scripts for specific targets
- **NO** Individual test scripts that only work on one application type
- **NO** Hardcoded filtering to skip assets (breaks universal scanning)
- **ALWAYS** enhance the universal engine modules instead of creating bypasses

### ❌ NEVER CREATE NEW SCRIPTS TO FIX ISSUES

- **NO** Creating simple_engine.py, quick_scan.py, or other "helper" scripts
- **NO** Workaround scripts that bypass the main engine
- **FIX THE ROOT CAUSE** in existing modules, don't create new ones
- **ENHANCE EXISTING SYSTEMS** rather than creating duplicates
- If something doesn't work, fix the core module, don't build around it

### 🔍 ALWAYS CHECK FOR EXISTING INFRASTRUCTURE FIRST

- **SEARCH BEFORE CREATING** - Use `grep`, `find`, or code search to find existing functionality
- **EXAMINE EXISTING MODULES** - Check modules/, engine.py, dashboard.py for similar features
- **READ THE CODEBASE** - Understand what's already implemented before adding new code
- **ENHANCE, DON'T DUPLICATE** - If 80% of functionality exists, enhance it rather than rewrite

### 🧹 Process Lifecycle & Cleanup (Universal)
- **Spawn Process Groups**: All external tools (`nuclei`, `dalfox`, `ffuf`, browser engines) start in their own process group so we can terminate the entire tree on timeout/cancel.
- **Enforce Timeouts**: Every external command runs under a strict timeout. On timeout, we send `SIGTERM`, then `SIGKILL` to the process group after a short grace period.
- **Track & Reap**: The scanner tracks active process groups and reaps them on engine shutdown to prevent zombie accumulation.
- **Watchdog Sweeps**: The `process_watchdog.py` runs periodically to kill hung/stacked processes and now also covers headless browser executables.
- **Universal, Not Target‑Specific**: These controls apply to all tools generically—no app‑specific logic or assumptions.

#### What changed (high level)
- Centralized `_run_tool()` now uses process groups + timeouts and cleans up on `TimeoutError`/cancellation.
- Nuclei integration switched to `_run_tool()` with a configurable timeout (`MODSCAN_NUCLEI_TIMEOUT`).
- Universal XSS scanner (Dalfox) uses process groups and kills the group on timeout.
- Engine adds a graceful shutdown that closes Playwright, terminates tracked tool processes, and runs a final watchdog health check.
- Removed unused legacy XSS modules (`modules/universal_xss_scanner.py`, `modules/xss_alert_detector.py`, `modules/form_xss_detector.py`) to avoid confusion. All XSS scanning runs through `VulnerabilityScanner` (`_test_xss_vulnerabilities`, `_context_aware_xss_testing`, and Dalfox via `_run_tool`).

#### Operational guidance
- Prefer `_run_tool()` for any new external integrations to inherit safety guarantees.
- Keep Playwright sessions short‑lived or pooled; always close contexts and browsers.
- Avoid bespoke kill logic in modules; let the runner + watchdog enforce lifecycle consistently.

#### 🚨 ZOMBIE PROCESS PREVENTION (2025-09-13 FIX)
- **Engine Startup Cleanup**: ProcessWatchdog initializes FIRST in `_initialize_modules()` and immediately kills zombie processes from previous runs
- **Graceful Shutdown**: Engine runs comprehensive cleanup in `_graceful_shutdown()` method during KeyboardInterrupt or exceptions
- **Final Safety Net**: Main function includes `finally` block that runs ProcessWatchdog as last resort cleanup
- **No Duplicate Watchdogs**: ProcessWatchdog only initialized once in `_initialize_modules()`, not in scan cycle loop
- **Resource Management**: This prevents hundreds of zombie Nuclei/Chromium processes from accumulating across engine restarts

### 🧭 Engine CLI Scope Seeding
- Positional targets: Pass domains or URLs as arguments to `engine.py` to seed scope on startup.
- Flags:
  - `--no-add-scope`: Do not add positional targets to scope.
  - `--no-ttl`: Set `MODSCAN_TTL_HOURS=0` for a fresh run (no discovery TTL).
  - `--max-cycles N`: Override scan cycle limit for this run.
- Behavior: Targets are normalized (strip scheme/port/wildcard) and added via `AssetManager.add_scope_target` universally (no hardcoding).
- **ASK: "Does this already exist?"** - Load balancing, resource management, process monitoring may already be implemented
- **CHECK CLAUDE.MD HISTORY** - Previous implementations may be documented in this file

### ❌ NEVER MANAGE PROCESSES - USER CONTROLS STARTUP

- **NO** Starting/stopping dashboard.py or engine.py processes
- **NO** Killing user processes without explicit permission
- **ONLY** examine logs and database to check status
- **USER** controls when to start/stop dashboard and engine
- **CHECK LOGS** in logs/ directory or use database queries for status
- **NEVER ASSUME** processes need restarting

### ✅ ALWAYS BUILD UNIVERSAL CAPABILITIES

- **Automatic target fingerprinting** - Detect what you're scanning without assumptions
- **Dynamic payload generation** - Adapt payloads based on discovered technologies
- **Universal form parsing** - Handle any form structure (CSRF tokens, field types, etc.)
- **Intelligent path discovery** - Use comprehensive wordlists that work on any target
- **Adaptive vulnerability testing** - Test what makes sense for each discovered endpoint
- **Robust crawling integration** - Discovery should leverage crawling for comprehensive coverage
- **Automatic authentication refresh** - When auth cookies expire, auto-refresh with stored credentials

### 🎯 ALWAYS CODE WITH INTRICATE PRECISION

- **NEVER use lazy, generic solutions** - Every implementation must be purposeful and comprehensive
- **TECHNOLOGY-SPECIFIC INTELLIGENCE** - Adapt behavior based on detected technology stack
- **COVER ALL BASIS** - Consider edge cases, error conditions, and real-world scenarios
- **INTRICATE IMPLEMENTATION** - Build sophisticated, nuanced solutions that handle complexity
- **NO SHORTCUTS** - Generic "admin/admin" approaches are unprofessional and ineffective

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

## Technology-Specific Intelligence

### 🎯 INTELLIGENT AUTHENTICATION TESTING

**NEVER use generic "admin/admin" approaches. ALWAYS adapt based on detected technology stack.**

### ⚡ Core Requirements

- **FINGERPRINT FIRST** - Always detect technology stack before testing anything
- **TECHNOLOGY-SPECIFIC PAYLOADS** - Use appropriate default credentials for PHP/MySQL, ASP.NET/MSSQL, Java/Tomcat, Node.js, Python/Django stacks
- **CONTEXT AWARE** - Different approaches for admin panels vs API endpoints vs database interfaces
- **RATE LIMITED** - Max 3 attempts per technology stack per host to avoid noise
- **INTELLIGENT STOPPING** - Stop on first success, don't continue blindly
- **NO GENERIC FALLBACKS** - If technology can't be detected, skip rather than guess

### 🔍 Implementation Principles

- Detect stack via HTTP headers, response content, URL patterns, and technology fingerprints
- Use technology-appropriate credential sets (PHPMyAdmin defaults for PHP, SQL Server defaults for ASP.NET, etc.)
- Implement technology-specific success detection (Django admin interfaces look different than Tomcat manager)
- Build comprehensive fingerprinting that covers edge cases and mixed technology environments

## Debug and Validation Testing

### 🔧 TEMPORARY DEBUG SCRIPTS ONLY

When debugging core issues, you may create temporary validation scripts, but:

- **ALWAYS DELETE** validation scripts after fixing the core issue
- **FIX THE ROOT CAUSE** in the main modules, don't work around it  
- **NEVER COMMIT** temporary debug/validation scripts to git
- Use simple test URLs like `http://192.168.1.42/dvwa/vulnerabilities/sqli` NOT full parameter URLs

### ✅ Example Debug Approach

```python
# TEMPORARY debug script - DELETE after fixing core issue
# Test authentication on simple URL: http://192.168.1.42/dvwa/vulnerabilities/sqli
# NOT: http://192.168.1.42/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit

# 1. Create temp script to isolate issue
# 2. Fix the actual problem in modules/auth_manager.py or core modules  
# 3. DELETE the temp script immediately
# 4. Test fix works in main application
```

## CRITICAL: BE BRUTALLY HONEST ABOUT PERFORMANCE

### 🚨 NEVER GIVE FALSE POSITIVE ASSESSMENTS 🚨

**When the scanner is broken, SAY IT'S BROKEN. Don't be misleading with "checkmarks" and positive language.**

Example of BRUTAL HONESTY needed:

**THE BRUTAL TRUTH**:
- The scanner is not working at all
- It's not finding the known XSS vulnerabilities in testhtml5.vulnweb.com  
- It's not finding the XXE vulnerabilities
- It's just running in circles, burning CPU, and failing every single vulnerability test
- The TTL system implemented to prevent repeats isn't working
- The engine architecture has fundamental flaws

**ALWAYS be critical and honest**:
- ❌ "✅ Vulnerability scanning completed successfully" (when nothing was found)
- ✅ "Scanner is fundamentally broken - all HTTP requests failing with _ProxySession errors"
- ❌ "Making good progress on vulnerability detection"  
- ✅ "Zero vulnerabilities detected due to async context manager failures"

### 🎯 Performance Validation

Before claiming success, verify:
- Are vulnerabilities actually being detected and stored?
- Do the findings match known vulnerable targets?
- Is the scanner avoiding repetitive work on same assets?
- Are HTTP requests succeeding or silently failing?

### 🚨 COMPLETE DISCOVERY REQUIREMENT

**The scanner is BROKEN until it finds 100% of documented lab vulnerabilities:**

**TryHackMe "Insecure Deserialization" lab MUST find:**
- ✅ Port 8089 Laravel application
- ✅ `/get-key` endpoint for Laravel key disclosure
- ✅ `/who/index.php` for PHP serialization
- ✅ `/cve.php` vulnerability test endpoint
- ✅ Successful Laravel deserialization RCE exploit
- ✅ Successful PHP serialization exploit

**If ANY of these are missing, the scanner is NOT working. Partial success = total failure.**

## Safety Systems and Process Management

### 🔒 COMPREHENSIVE SAFETY ARCHITECTURE

ModScan includes multiple safety systems to prevent and automatically fix issues:

#### URL Validation Safety (`asset_manager.py`)
- **URL Format Validation** - Detects and blocks corrupted URLs before they reach scanners
- **Corruption Pattern Detection** - Identifies patterns like `M11540`, `rieilgakM115411`, `,1,1813,0,active`
- **Domain Structure Validation** - Prevents malformed domains and double HTTP protocols
- **Automatic Rejection** - Corrupted URLs are logged and blocked from database storage

#### Process Watchdog (`process_watchdog.py`)
- **Hung Process Detection** - Kills scanner processes running longer than 10 minutes
- **Process Stacking Prevention** - Limits concurrent processes per tool (max 10 SQLMap, etc.)
- **Corrupted URL Process Cleanup** - Identifies and kills processes running on malformed URLs
- **System Health Monitoring** - Tracks CPU, memory, and active scanner processes
- **Automatic Execution** - Integrated into engine, runs every 5 minutes

#### Database Health Monitor (`database_health.py`)  
- **Corruption Detection** - Finds and removes corrupted asset URLs from database
- **Orphaned Data Cleanup** - Removes vulnerabilities linked to deleted assets
- **Duplicate Asset Consolidation** - Merges duplicate assets and preserves vulnerability data
- **Stale Data Identification** - Identifies assets not scanned in 7+ days
- **Comprehensive Statistics** - Provides database health metrics

### 🚨 SAFETY INTEGRATION

The safety systems are **automatically integrated** into the main engine:

```python
# Engine automatically runs safety checks every 5 minutes
SAFETY_CHECK_INTERVAL = 300  # 5 minutes
self.process_watchdog = ProcessWatchdog()

# During scan cycles
await loop.run_in_executor(None, self.process_watchdog.run_health_check)
```

### 🔧 MANUAL SAFETY OPERATIONS

Run safety checks independently:

```bash
# Process cleanup (kill hung/corrupted processes)
python process_watchdog.py --once

# Database health check and cleanup
python database_health.py

# Check for corrupted URLs in real-time
python -c "from asset_manager import AssetManager; am = AssetManager(); am._should_skip_url('test_url')"
```

### 🛡️ PREVENTION MEASURES

1. **URL Validation** - All URLs validated before database storage
2. **Process Timeouts** - Scanner processes auto-killed after reasonable timeouts
3. **Resource Limits** - Maximum concurrent processes per scanner tool
4. **Pattern Recognition** - Known corruption patterns blocked proactively
5. **Health Monitoring** - Continuous system resource monitoring

### ⚡ AUTOMATIC RECOVERY

The safety systems provide **automatic recovery** from common issues:
- ✅ **Hung SQLMap processes** → Automatically detected and killed
- ✅ **Corrupted URLs** → Blocked from reaching scanners  
- ✅ **Database corruption** → Orphaned data cleaned automatically
- ✅ **Process stacking** → Excess processes terminated
- ✅ **Resource leaks** → System health monitored and maintained

This ensures the scanner **never gets stuck** and **always operates efficiently**.

## Final Note

**NEVER** compromise the universal nature of this platform by adding target-specific logic. If something doesn't work on a specific target, enhance the universal capabilities rather than creating exceptions.

**ALWAYS** use the centralized VulnerabilityFinding structure from `asset_manager.py` for consistency.

**ALWAYS** be brutally honest about scanner performance - false positives in assessment are worse than no scanner at all.

**ALWAYS** rely on the integrated safety systems to prevent and fix process/database issues automatically.

The goal is a single platform that works everywhere, not a collection of target-specific tools.
