#!/usr/bin/env python3
import json, pathlib, os

p = pathlib.Path(os.path.expanduser('~/recon-platform/modscan/config.json'))
cfg = {}
if p.exists():
    try:
        cfg = json.loads(p.read_text(encoding='utf-8') or '{}')
    except Exception:
        cfg = {}

cfg.setdefault("rescan_ttl_hours", 24)
cfg.setdefault("xss_dom_phase", False)         # browser DOM confirm (opt-in; requires Playwright)
cfg.setdefault("collaborator", {
    "enabled": False,
    "base_domain": "",     # e.g. oob.yourdomain.tld
    "auth_token": "",      # optional if you run a receiver
    "https": True
})

p.write_text(json.dumps(cfg, indent=2, sort_keys=True), encoding='utf-8')
print("[config] ensured keys: rescan_ttl_hours, xss_dom_phase, collaborator")