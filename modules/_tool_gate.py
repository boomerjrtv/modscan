import os, re, shlex, subprocess, asyncio
from urllib.parse import urlparse
from asset_manager import AssetManager

AM = AssetManager()
def _ttl():
    try: return int(os.environ.get("MODSCAN_TTL_HOURS","24"))
    except Exception: return 24

TOOLS = {"gau","gauplus","wayback","waybackurls","subfinder","katana","httpx"}  # add more if needed
DOMAIN_RX = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b")

def _pick_host_from_argv(argv):
    # Common flags: -d/-domain/-host/-root/-target ; -u/-url
    it = iter(range(len(argv)))
    for i in it:
        a = argv[i]
        if a in ("-d","-domain","-host","-root","-target") and i+1 < len(argv):
            cand = argv[i+1]; 
            if cand: return _hostify(cand)
        if a in ("-u","-url") and i+1 < len(argv):
            cand = argv[i+1]; 
            if cand: 
                h = _host_from_url(cand)
                if h: return h
    # Any explicit URL token?
    for a in argv:
        if a.startswith(("http://","https://")):
            h = _host_from_url(a)
            if h: return h
    # Fallback: first domain-looking token
    for a in argv:
        m = DOMAIN_RX.search(a or "")
        if m: return m.group(0).lower().lstrip(".")
    return None

def _host_from_url(u):
    try:
        h = urlparse(u).hostname
        if h: return h.lower().lstrip(".")
    except Exception:
        pass
    return None

def _hostify(s):
    if s.startswith(("http://","https://")):
        return _host_from_url(s)
    m = DOMAIN_RX.search(s or "")
    return m.group(0).lower().lstrip(".") if m else None

def _is_tool(cmd):
    exe = (cmd or "").split()[:1]
    if not exe: return None
    base = exe[0]
    base = base.rsplit("/",1)[-1]  # strip path
    base = base.split()[0]
    base = base.lower()
    # heuristic: accept aliases like python -m gau (handled by argv below)
    return base if base in TOOLS else None

# ------------------ subprocess.run gate ------------------
_orig_run = subprocess.run
def _gate_run(*p, **kw):
    args = kw.get("args", p[0] if p else None)
    if args is None:
        return _orig_run(*p, **kw)

    if isinstance(args, str):
        argv = shlex.split(args)
        cmd0 = argv[0] if argv else ""
        cmdline = args
    else:
        argv = list(args)
        cmd0 = argv[0] if argv else ""
        cmdline = " ".join(argv)

    tool = _is_tool(cmd0) or (argv and _is_tool(argv[0]))
    # if script wrapper like "python gau.py ..." detect second token
    if not tool and len(argv) > 1:
        tool = _is_tool(argv[1])

    if tool:
        host = _pick_host_from_argv(argv)
        if host and hasattr(AM, "should_scan_host") and not AM.should_scan_host(host, ttl_hours=_ttl()):
            msg = f"[gate] ⏭️  Skipping {tool} for {host}: scanned within {_ttl()}h"
            try:
                print(msg)
            except Exception:
                pass
            # Return an "empty success"
            text_mode = kw.get("text") or kw.get("universal_newlines")
            stdout = "" if text_mode else b""
            stderr = "" if text_mode else b""
            return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr=stderr)

    return _orig_run(*p, **kw)
subprocess.run = _gate_run

# -------- asyncio.create_subprocess_* gates (shell & exec) --------
async def _empty_process_result(text_mode=False):
    class _Dummy:
        pid = 0
        returncode = 0
        async def communicate(self): 
            return (("" if text_mode else b""), ("" if text_mode else b""))
        async def wait(self): 
            return 0
        def __await__(self):
            async def _done(): return self
            return _done().__await__()
        # provide minimal stdout/stderr attrs when PIPE used
        stdout = None
        stderr = None
    return _Dummy()

_orig_cps = asyncio.create_subprocess_shell
async def _gate_shell(cmd, *a, **kw):
    try:
        argv = shlex.split(cmd or "")
        tool = _is_tool(argv[0] if argv else "")
        if not tool and len(argv) > 1:
            tool = _is_tool(argv[1])
        if tool:
            host = _pick_host_from_argv(argv)
            if host and hasattr(AM, "should_scan_host") and not AM.should_scan_host(host, ttl_hours=_ttl()):
                print(f"[gate] ⏭️  Skipping {tool} for {host}: scanned within {_ttl()}h")
                text_mode = kw.get("text") or kw.get("universal_newlines")
                return await _empty_process_result(text_mode=text_mode)
    except Exception:
        pass
    return await _orig_cps(cmd, *a, **kw)
asyncio.create_subprocess_shell = _gate_shell

try:
    _orig_cpe = asyncio.create_subprocess_exec
    async def _gate_exec(*argv, **kw):
        tool = _is_tool(argv[0] if argv else "")
        if not tool and len(argv) > 1:
            tool = _is_tool(argv[1])
        if tool:
            host = _pick_host_from_argv(list(argv))
            if host and hasattr(AM, "should_scan_host") and not AM.should_scan_host(host, ttl_hours=_ttl()):
                print(f"[gate] ⏭️  Skipping {tool} for {host}: scanned within {_ttl()}h")
                text_mode = kw.get("text") or kw.get("universal_newlines")
                return await _empty_process_result(text_mode=text_mode)
        return await _orig_cpe(*argv, **kw)
    asyncio.create_subprocess_exec = _gate_exec
except Exception as e:
    print("[gate] exec hook not applied:", e)

print("[gate] Tool-level TTL gate active")
