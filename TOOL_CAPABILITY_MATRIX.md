# ModScan Tool Capability Matrix

## Philosophy: Tool-First Vulnerability Detection

**Core Principle**: Use proven tools for each vulnerability class instead of reinventing detection logic. Focus our custom code on orchestration, context understanding, and novel pattern detection.

## Vulnerability Type Breakdown & Tool Recommendations

### 🔓 SQL Injection
**Industry Standard Tools:**
- **SQLMap** ⭐ (Best in class)
  - Usage: `sqlmap -u "URL" --batch --risk=3 --level=5`
  - Strengths: 100+ DB engines, advanced techniques, time-based, boolean, error-based
  - Integration: Already in ModScan via `_run_sqlmap_scan()`
  - Output: JSON format with detailed findings

**Alternative Tools:**
- **NoSQLMap** (for NoSQL injection)
- **SQLiDetector** (lightweight detection)

**Custom Logic Needed:**
- Form parsing and parameter extraction
- Authentication context preservation
- Result parsing and validation

---

### 🚨 Cross-Site Scripting (XSS)
**Industry Standard Tools:**
- **Dalfox** ⭐ (Modern XSS scanner)
  - Usage: `dalfox url "URL" --format json`
  - Strengths: WAF bypass, DOM XSS, reflected/stored detection
  - Integration: Already in ModScan via `_run_dalfox_scan()`
  - Output: JSON with payload details

- **XSSHunter** (Blind XSS)
  - Usage: Custom payload injection + callback monitoring
  - Strengths: Out-of-band detection, admin panel testing
  - Integration: ModScan has XSSHunterEnhanced module

**Alternative Tools:**
- **XSStrike** (Advanced XSS)
- **BruteXSS** (Parameter fuzzing)
- **XSSCon** (Automation framework)

**Custom Logic Needed:**
- Form discovery and context analysis
- Payload customization based on input type
- Callback monitoring infrastructure

---

### 📁 Local File Inclusion (LFI) / Path Traversal
**Industry Standard Tools:**
- **DotDotPwn** ⭐ (Directory traversal)
  - Usage: `dotdotpwn -m http -h target.com -x 8080 -f /etc/passwd`
  - Strengths: Multiple protocols, comprehensive payloads
  - Not integrated: Need to add

- **Nuclei Templates** ⭐ (LFI detection)
  - Usage: `nuclei -u "URL" -t lfi/`
  - Strengths: 50+ LFI templates, active maintenance
  - Integration: ModScan has Nuclei integration

- **LFISuite** (Comprehensive LFI)
  - Usage: `python3 lfisuite.py -u "URL"`
  - Strengths: Log poisoning, filter bypass
  - Not integrated: Consider adding

**Current Problem:**
- ModScan's custom LFI detection has false positives
- **SOLUTION**: Replace with DotDotPwn + Nuclei LFI templates

---

### 🌐 Server-Side Request Forgery (SSRF)
**Industry Standard Tools:**
- **SSRFmap** ⭐
  - Usage: `python3 ssrfmap.py -r request.txt`
  - Strengths: AWS metadata, internal service discovery
  - Not integrated: Need to add

- **Nuclei SSRF Templates**
  - Usage: `nuclei -u "URL" -t ssrf/`
  - Strengths: Cloud-specific payloads
  - Integration: Available via ModScan Nuclei

- **Interactsh** (Out-of-band SSRF)
  - Usage: Payload injection + callback monitoring
  - Strengths: DNS/HTTP callback detection
  - Not integrated: Consider adding

---

### 🔑 Authentication Bypass
**Industry Standard Tools:**
- **Hydra** ⭐ (Brute force)
  - Usage: `hydra -L users.txt -P pass.txt target.com http-post-form`
  - Strengths: Multiple protocols, parallel processing
  - Not integrated: Need to add

- **Patator** (Advanced brute forcing)
  - Usage: `patator http_fuzz url=URL method=POST`
  - Strengths: Custom payloads, rate limiting
  - Not integrated: Consider adding

- **Nuclei Auth Templates**
  - Usage: `nuclei -u "URL" -t default-logins/`
  - Integration: Available via ModScan Nuclei

---

### 🔧 Command Injection
**Industry Standard Tools:**
- **Commix** ⭐ (Command injection)
  - Usage: `python commix.py --url="URL" --data="param=value"`
  - Strengths: OS detection, technique variety
  - Not integrated: Need to add

- **Nuclei Command Injection Templates**
  - Usage: `nuclei -u "URL" -t injection/`
  - Integration: Available via ModScan Nuclei

---

### 🏢 Business Logic Flaws
**Industry Standard Tools:**
- **Authz** (Authorization testing)
- **Burp Extensions** (Custom logic testing)
- **Custom scripting** (Application-specific)

**Approach:**
- Mostly requires custom logic
- Use tools for discovery, custom code for testing

---

### 📊 Information Disclosure
**Industry Standard Tools:**
- **Nuclei Info Disclosure Templates** ⭐
  - Usage: `nuclei -u "URL" -t exposures/`
  - Strengths: 200+ templates for leaks
  - Integration: Available via ModScan Nuclei

- **GitLeaks** (Git secret scanning)
- **TruffleHog** ⭐ (Secret detection)
  - Integration: ModScan has secret scanner

---

### 🔍 Directory/File Discovery
**Industry Standard Tools:**
- **ffuf** ⭐ (Fast fuzzing)
  - Usage: `ffuf -u "URL/FUZZ" -w wordlist.txt`
  - Integration: Already in ModScan

- **Dirsearch** (Directory brute force)
- **Gobuster** (Go-based fuzzing)

---

### 🌍 Subdomain Enumeration
**Industry Standard Tools:**
- **Subfinder** ⭐
- **Amass** ⭐
- **Sublist3r**

Integration: ModScan has discovery engine

---

## Tool Integration Priority Matrix

### ✅ ALREADY INTEGRATED
1. **Nuclei** - Template-based scanning
2. **Dalfox** - XSS detection
3. **SQLMap** - SQL injection
4. **ffuf** - Directory fuzzing
5. **TruffleHog** - Secret scanning
6. **GAU** - URL discovery

### 🔥 HIGH PRIORITY TO ADD
1. **DotDotPwn** - Replace broken LFI detection
2. **Commix** - Command injection
3. **SSRFmap** - SSRF detection
4. **Hydra** - Authentication brute force

### 🎯 MEDIUM PRIORITY
1. **Sublist3r** - Enhanced subdomain discovery
2. **Interactsh** - Out-of-band interaction
3. **GitLeaks** - Enhanced secret detection

### 🔮 FUTURE CONSIDERATION
1. **Burp Professional API** - Enterprise scanning
2. **OWASP ZAP API** - Open source alternative
3. **Custom ML models** - Novel pattern detection

## Implementation Strategy

### Phase 1: Fix Immediate Issues (Week 1)
1. **Replace broken LFI detection** with DotDotPwn + Nuclei
2. **Add Commix** for command injection
3. **Enhance tool result parsing** and validation

### Phase 2: Expand Coverage (Week 2-3)
1. **Add SSRFmap** for SSRF detection
2. **Add Hydra** for auth brute force
3. **Create unified tool orchestration** framework

### Phase 3: Advanced Features (Week 4+)
1. **Tool result correlation** and chaining
2. **AI-powered result analysis** and validation
3. **Custom payloads** based on context

## Tool Integration Patterns

### Standard Integration Pattern
```python
async def run_tool_scan(self, tool_name: str, url: str, options: dict) -> List[VulnerabilityFinding]:
    """Universal tool runner pattern"""

    # 1. Prepare command and options
    cmd = self._build_tool_command(tool_name, url, options)

    # 2. Execute with timeout and process management
    result = await self._run_tool(cmd, timeout=300)

    # 3. Parse output to VulnerabilityFinding objects
    findings = self._parse_tool_output(tool_name, result)

    # 4. Validate and filter results
    validated_findings = await self._validate_findings(findings)

    return validated_findings
```

### Tool-Specific Configurations
```yaml
tools:
  sqlmap:
    timeout: 600
    risk_level: 3
    technique: "BEUSTQ"

  dalfox:
    timeout: 300
    silence: true
    format: "json"

  nuclei:
    timeout: 180
    rate_limit: 150
    templates: ["cves/", "vulnerabilities/"]
```

## Success Metrics

### Quality Metrics
- **Zero false positives** from tool-based detection
- **Coverage comparison** vs manual testing
- **Time to detection** for known vulnerabilities

### Performance Metrics
- **Scan time per vulnerability type**
- **Resource utilization** (CPU, memory, network)
- **Tool success rate** and error handling

## Conclusion

**Tool-first approach benefits:**
1. ✅ **Eliminates false positives** from broken custom logic
2. ✅ **Leverages community expertise** and maintenance
3. ✅ **Provides comprehensive coverage** via templates/payloads
4. ✅ **Allows focus on unique value** (orchestration, AI analysis)

**Custom logic should focus on:**
1. 🎯 **Tool orchestration** and result correlation
2. 🧠 **AI-powered analysis** and validation
3. 🔍 **Context-aware testing** (auth preservation, session handling)
4. 🔗 **Vulnerability chaining** and exploit development
5. 📊 **Business logic testing** where tools can't help

This approach transforms ModScan from a "reimplementation of existing tools" into a "intelligent orchestrator of proven tools" - which is far more valuable and reliable.