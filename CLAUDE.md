# 🚨 CLAUDE CRITICAL RULES - MODSCAN PROJECT 🚨

## 📍 CORRECT PROJECT LOCATION:
**WORKING DIRECTORY: `/home/michael/recon-platform/modscan/`**
- This is the ACTIVE project directory
- Database file: `lean_recon.db` in this directory
- Dashboard: `dashboard.py` in this directory  
- ALL work must be done in `/home/michael/recon-platform/modscan/`

## ⛔ NEVER DO THESE THINGS - WILL BREAK EVERYTHING ⛔

### 1. DATABASE PROTECTION - ABSOLUTELY FORBIDDEN:
- **NEVER** run `DELETE FROM assets` or any bulk delete commands
- **NEVER** run `DROP TABLE` or `VACUUM` on production database
- **NEVER** run database cleanup scripts without explicit user approval
- **NEVER** clear/reset the database without asking first
- **NEVER** run schema upgrade scripts that modify existing data
- **NEVER** query databases outside of `/home/michael/recon-platform/modscan/` directory
- **NEVER** access lean_scanner database - that is the OLD implementation
- **ONLY** work with modscan database through asset_manager.py

### 2. MAPPING SYSTEM - HANDS OFF:
- **NEVER** modify `asset_mapping.json` field names
- **NEVER** change field mappings in `asset_manager.py`
- **NEVER** hardcode database field names in modules
- **NEVER** hardcode database field names in `dashboard.py`
- **NEVER** create setup/initialization scripts - scope should be managed through dashboard UI
- **ONLY ADD** new mappings, never change existing ones
- **ALL** database field references MUST go through `asset_manager.py`
- **ALL** database operations (scope, assets, vulnerabilities) MUST use `asset_manager.py` methods
- **NO** direct database queries outside of `asset_manager.py`

### 3. PROCESS MANAGEMENT - CRITICAL:
- **ALWAYS** check for existing engine processes before starting new ones
- **NEVER** start multiple engines simultaneously  
- **NEVER** kill and restart processes without checking what's running first
- **ONLY ONE** `engine.py` process should run at a time
- **CHECK** with `ps aux | grep` before killing any processes

## ✅ SAFE OPERATIONS - THESE ARE OK:

### Database Operations:
- Adding new columns with `ALTER TABLE ADD COLUMN`
- Inserting new data with `INSERT INTO`
- Reading data with `SELECT` queries
- Creating indexes for performance

### Mapping Operations:
- Adding new field mappings to `asset_mapping.json`
- Adding new methods to `asset_manager.py`
- Creating new modules that use `asset_manager` for all DB operations

### Module Development:
- Create new scanning modules in `modules/` directory
- Use `self.asset_manager` for ALL database operations
- NO hardcoded SQL field names in modules
- Use `self.asset_manager.get_asset_fields()` for field mappings

## 🏗️ CORRECT ARCHITECTURE:

```
┌─ asset_mapping.json ────────────────────┐
│  (GLOBAL FIELD MAPPING CONFIG)          │
└──────────────┬───────────────────────────┘
               │
┌─ asset_manager.py ──────────────────────┐
│  - get_asset_fields()                   │
│  - All database operations              │
│  - Field mapping logic                  │
└──────────────┬───────────────────────────┘
               │
┌─ modules/ ──────────────────────────────┐
│  - discovery_engine.py                  │
│  - vulnerability_scanner.py             │
│  - technology_detector.py               │
│  - ALL use asset_manager for DB ops     │
└─────────────────────────────────────────┘
```

## 🚨 EMERGENCY RECOVERY PROCEDURES:

### If Database Gets Corrupted:
1. **STOP** - Check for backups first
2. **NEVER** recreate from scratch
3. **ASK USER** before any recovery operations
4. Document what went wrong

### If Engine Won't Start:
1. Check for multiple engine processes: `ps aux | grep engine`
2. Kill existing engines: `pkill -f engine.py`  
3. Wait 5 seconds before starting new engine
4. Start only ONE engine: `python3 engine.py &`

### If Dashboard Breaks:
1. **NEVER** copy templates from other projects
2. Check API endpoints first: `curl localhost:8000/api/assets/summary`
3. Verify asset_manager is working
4. Check browser console for JavaScript errors

## 📋 PRE-FLIGHT CHECKLIST:

Before making ANY changes:
- [ ] Is this adding functionality WITHOUT changing existing mappings?
- [ ] Will this preserve all existing data?
- [ ] Am I using asset_manager for all database operations?
- [ ] Have I checked for running engine processes?
- [ ] Did I test on a small scale first?

## 🔧 DEBUGGING WORKFLOW:

1. **Read-Only Investigation**:
   - Check database counts: `sqlite3 lean_recon.db "SELECT COUNT(*) FROM assets"`
   - Check running processes: `ps aux | grep python`
   - Check logs for errors

2. **Safe Modifications**:
   - Add new columns only
   - Add new mapping entries only
   - Create new modules using asset_manager

3. **NEVER**:
   - Delete existing data
   - Modify existing mappings
   - Start multiple engines

---

# ⚠️ LESSON LEARNED: 
**On [DATE], Claude accidentally deleted 4000+ discovered assets by running database cleanup commands. This MUST NEVER happen again. Always preserve existing data and only ADD, never MODIFY or DELETE.**

---

## 🎯 KEY PRINCIPLES:
1. **PRESERVE** existing data at all costs
2. **ADD** new functionality without breaking existing 
3. **USE** asset_manager for ALL database operations
4. **ASK** before any destructive operations
5. **TEST** on small scale before wide deployment

**Remember: The user's discovered assets are VALUABLE and took hours/days to collect. Treat them like precious data that can never be recovered if lost.**

---

# 🗺️ MODSCAN SYSTEM ARCHITECTURE MAP

## 📊 Complete System Architecture
```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                            🎯 MODSCAN BUG BOUNTY PLATFORM                           │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                              │
                        ┌─────────────────────┼─────────────────────┐
                        │                     │                     │
                        ▼                     ▼                     ▼
        ┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────────────┐
        │   🌐 DASHBOARD       │   │   ⚙️ ENGINE.PY       │   │   📊 DATABASE       │
        │   dashboard.py       │   │   Main Controller    │   │   lean_recon.db     │
        │   Port 8000          │   │   Single Instance    │   │   SQLite + WAL      │
        │   Flask Web UI       │   │   Kill Existing      │   │   Progressive       │
        │                     │   │   Before Start       │   │   Scanning Schema   │
        └─────────────────────┘   └─────────────────────┘   └─────────────────────┘
                │                           │                           │
                │                           │                           │
                ▼                           ▼                           ▼
        ┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────────────┐
        │   📋 ASSET_MANAGER   │   │   🕷️ DISCOVERY       │   │   🔍 PROGRESSIVE    │
        │   asset_manager.py   │◄──│   discovery_engine   │   │   SCANNING STAGES   │
        │   ALL DB Operations  │   │   - CT Discovery     │   │   - discovered      │
        │   Field Mappings     │   │   - SecLists        │   │   - basic_complete  │
        │   INSERT OR REPLACE  │   │   - URL Profiling    │   │   - deep_complete   │
        └─────────────────────┘   └─────────────────────┘   └─────────────────────┘
                ▲                           │
                │                           ▼
                │                   ┌─────────────────────┐
                │                   │   🛡️ SCANNING       │
                │                   │   MODULES           │
                │                   │   - vuln_scanner    │
                └───────────────────┤   - waf_bypass      │
                                    │   - screenshot      │
                                    │   - tech_detect     │
                                    └─────────────────────┘
```

## 🔄 Data Flow Sequence
```
1. SCOPE INPUT 
   ├── Dashboard UI → scope table
   └── temu.com, centene.com configured

2. ENGINE STARTUP
   ├── Kill existing processes
   ├── Initialize shared proxy manager
   └── Start discovery_engine.py

3. DISCOVERY PHASE
   ├── Certificate Transparency API
   ├── SecLists wordlist scanning  
   ├── Subdomain enumeration
   └── URL collection

4. PROFILING PHASE ⚠️ BROKEN HERE
   ├── HTTP status codes
   ├── Page titles
   ├── Response times
   ├── Content analysis
   └── Tech stack detection

5. ASSET STORAGE
   ├── asset_manager.py processes data
   ├── INSERT OR REPLACE into database
   └── Progressive scan flags updated

6. FRONTEND DISPLAY
   ├── Dashboard fetches via API
   ├── asset_mapping.json field translation
   └── Real-time UI updates
```

## 🚨 ROOT CAUSE ANALYSIS - NULL DATA ISSUE

### Current Problem:
- **Discovery**: ✅ Working (562 assets found)
- **Profiling**: ❌ BROKEN (all status codes, titles null)
- **Frontend**: Shows empty data due to null backend fields

### Key Issue Chain:
1. `discovery_engine.py` finds URLs via CT/SecLists
2. Calls `asset_manager.add_asset()` with minimal data 
3. Later profiling should UPDATE these records
4. **BUT**: Profiling never runs or fails silently
5. Result: Assets exist but have no status_code, title, etc.

### Technical Root Cause:
**The `_discover_and_profile_target()` method in discovery_engine.py may be:**
- Not being called for existing assets
- Failing silently during HTTP requests
- Not updating discovered assets with full profile data
- Proxy/session issues preventing HTTP profiling

## 🔧 CRITICAL DEBUGGING CHECKLIST

### Immediate Actions Required:
1. ✅ Fixed INSERT OR REPLACE (done but didn't work)
2. ⏳ Check if discovery_engine actually calls profiling methods
3. ⏳ Verify HTTP session/proxy setup in discovery_engine  
4. ⏳ Test if discovered assets get updated with profile data
5. ⏳ Check if engine.py properly initializes discovery_engine

### Module Responsibilities:
- **asset_manager.py**: ✅ Database operations, field mappings
- **discovery_engine.py**: ❌ URL discovery AND profiling (BROKEN)
- **dashboard.py**: ✅ API endpoints, frontend serving  
- **engine.py**: ✅ Process management, module coordination

## 🗺️ FIELD MAPPING ARCHITECTURE
```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              📊 DATA MAPPING FLOW                                   │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  asset_mapping.json (GLOBAL CONFIG) ──┐                                            │
│                                        │                                            │
│  ┌─────────────────────────────────────▼────────────────────────────────────────┐   │
│  │                        asset_manager.py                                     │   │
│  │  get_asset_fields() returns:                                                │   │
│  │  ├── 'url' → 'url'                                                          │   │
│  │  ├── 'status' → 'status_code'                                               │   │
│  │  ├── 'title' → 'title'                                                      │   │
│  │  ├── 'time' → 'response_time'                                               │   │
│  │  └── 'screenshot' → 'screenshot_path'                                       │   │
│  └──────────────────────────────────────────────────────────────────────────────┘   │
│                                        │                                            │
│                                        ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────────────┐   │
│  │                     discovery_engine.py                                    │   │
│  │  Uses: self.asset_manager.build_asset_insert_query()                       │   │
│  │  Maps: (url, host, status_code, title, response_time...)                   │   │
│  └─────────────────────────────────────────────────────────────────────────────┘   │
│                                        │                                            │
│                                        ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────────────┐   │
│  │                        lean_recon.db                                        │   │
│  │  Stores: url, status_code, title, response_time, screenshot_path...         │   │
│  └─────────────────────────────────────────────────────────────────────────────┘   │
│                                        │                                            │
│                                        ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────────────┐   │
│  │                       dashboard.py API                                      │   │
│  │  Returns: Raw database fields (no mapping in backend)                      │   │
│  └─────────────────────────────────────────────────────────────────────────────┘   │
│                                        │                                            │
│                                        ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────────────┐   │
│  │              Frontend JavaScript                                            │   │
│  │  Uses: asset_mapping.json to translate raw DB fields to display            │   │
│  │  Maps: database.status_code → frontend display                             │   │
│  └─────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

## 🎯 NEXT DEBUGGING STEPS

### Priority 1 - Check Discovery Engine Profiling:
1. Examine `discovery_engine.py` → `_discover_and_profile_target()` method
2. Verify it actually makes HTTP requests to get status codes  
3. Check if profiling results are passed to asset_manager properly
4. Test if proxy/session setup works for HTTP profiling

### Priority 2 - Database Update Verification:
1. Check if `INSERT OR REPLACE` actually updates existing records
2. Verify the database schema has all required columns
3. Test asset_manager methods manually with real data
4. Ensure field mappings are applied correctly during updates