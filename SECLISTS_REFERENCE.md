# SecLists Wordlist Reference Guide

## 📍 Available SecLists Wordlists

### Discovery/Web-Content (Main Directory Discovery)
```
~/SecLists/Discovery/Web-Content/
├── raft-large-directories-lowercase.txt      # ~120K directories
├── raft-large-files-lowercase.txt           # ~70K files
├── common.txt                                # ~4K common paths
├── directory-list-2.3-medium.txt           # ~220K directories
├── directory-list-2.3-big.txt              # ~1M+ directories
├── combined_words.txt                        # Mixed content
├── versioning_metafiles.txt                 # Version control files
└── UnixDotfiles.fuzz.txt                    # Unix hidden files
```

### Discovery/Web-Content/CMS (CMS-Specific)
```
~/SecLists/Discovery/Web-Content/CMS/
├── wordpress.fuzz.txt                       # WordPress paths
├── drupal_plugins.fuzz.txt                  # Drupal discovery
└── joomla.fuzz.txt                          # Joomla paths
```

### Fuzzing (Vulnerability Testing)
```
~/SecLists/Fuzzing/
├── LFI/                                     # Local File Inclusion
├── SQLi/                                    # SQL Injection
├── XSS/                                     # Cross-Site Scripting
└── file-extensions.txt                      # All file extensions
```

## 🎯 SecListsManager Wordlist Types

The `get_intelligent_wordlist(target_info, wordlist_type, limit)` method supports:

### Standard Types
- `'directory'` - Directory paths from Discovery/Web-Content
- `'files'` - File paths and names
- `'admin_paths'` - Administrative interfaces
- `'api_endpoints'` - API discovery paths
- `'backup_files'` - Backup and archive detection
- `'subdomains'` - Subdomain wordlists

### Technology-Specific Types
- `'wordpress'` - WordPress-specific paths
- `'drupal'` - Drupal CMS paths
- `'joomla'` - Joomla CMS paths

## ⚡ Usage Examples

```python
from modules.seclists_manager import SecListsManager

seclists = SecListsManager(None, {})

# Get comprehensive directory wordlist
dirs = seclists.get_intelligent_wordlist({}, 'directory', limit=50000)

# Get file discovery wordlist
files = seclists.get_intelligent_wordlist({}, 'files', limit=20000)

# Get admin panel discovery
admin = seclists.get_intelligent_wordlist({}, 'admin_paths', limit=5000)
```

## 🚫 NEVER HARDCODE PATHS

❌ **WRONG**:
```python
hardcoded_paths = ['admin.php', 'config.php', 'get-key']  # FORBIDDEN
```

✅ **CORRECT**:
```python
paths = seclists.get_intelligent_wordlist({}, 'files', limit=10000)  # Use SecLists
```

## 📊 Wordlist Size Guidelines

- **Fast Discovery**: 1K-5K paths
- **Comprehensive Discovery**: 10K-50K paths
- **Exhaustive Discovery**: 100K+ paths

## 🔍 Finding Specific Wordlists

```bash
# Find all discovery wordlists
find ~/SecLists/Discovery -name "*.txt" | head -20

# Find vulnerability-specific wordlists
find ~/SecLists/Fuzzing -name "*.txt" | grep -E "(php|web|exploit)"

# Find the largest wordlists
find ~/SecLists -name "*.txt" -exec wc -l {} + | sort -nr | head -10
```

## ⚠️ Critical Rules

1. **NEVER HARDCODE PATHS** - Always use SecLists wordlists
2. **NEVER HARDCODE ENDPOINTS** - No `get-key`, `cve.php`, or target-specific paths
3. **USE SECLISTS OR GITHUB SCRIPTS** - If searching for specific patterns, use existing wordlists or open-source tools
4. **NO EXCEPTIONS** - Even "universal" patterns like `admin.php` are forbidden hardcoding
5. **USE EXTERNAL TOOLS** - Consider GitHub scripts, Nuclei templates, or other tools for specific vulnerability classes
6. **Use appropriate limits** - Don't load 1M+ wordlists without limits
7. **Check wordlist exists** - Handle missing SecLists gracefully
8. **Technology-aware selection** - Use CMS-specific wordlists when detected
9. **Progressive discovery** - Start small, scale up based on findings

## 🚫 ABSOLUTELY FORBIDDEN

### ❌ Hardcoded Path Lists
```python
# FORBIDDEN - DO NOT DO THIS
hardcoded_paths = [
    'get-key', 'cve.php', 'admin.php', 'config.php',
    'test.php', 'debug.php', 'api.php'
]
```

### ❌ Hardcoded Vulnerability Testing
```python
# FORBIDDEN - DO NOT DO THIS
vuln_endpoints = ['sqli.php', 'xss.php', 'lfi.php']
```

### ❌ Target-Specific Logic
```python
# FORBIDDEN - DO NOT DO THIS
if 'tryhackme' in domain:
    test_endpoints = ['/get-key', '/cve.php']
```

## ✅ PROPER ALTERNATIVES

### ✅ Use SecLists Wordlists
```python
# CORRECT - Use existing wordlists
from modules.seclists_manager import SecListsManager
seclists = SecListsManager(None, {})
paths = seclists.get_intelligent_wordlist({}, 'files', limit=10000)
```

### ✅ Use GitHub Tools
```python
# CORRECT - Integrate external tools
await self._run_nuclei_scan(url, templates="deserialization")
await self._run_custom_github_script("phpggc", url)
```

### ✅ Use Technology Detection
```python
# CORRECT - Detect and adapt
tech_stack = detect_technology(url)
if 'laravel' in tech_stack:
    wordlist_type = 'laravel_specific'
```