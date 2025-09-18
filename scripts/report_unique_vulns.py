#!/usr/bin/env python3
import sqlite3
from urllib.parse import urlparse, parse_qsl
from collections import defaultdict
import sys

DB_PATH = 'lean_recon.db'
ONLY_BOUNTY = False
args = [a for a in sys.argv[1:]]
if args:
    for a in args:
        if a == '--bounty':
            ONLY_BOUNTY = True
        else:
            DB_PATH = a

def normalize_endpoint(url: str) -> str:
    try:
        p = urlparse(str(url or '').strip())
        path = p.path or '/'
        if len(path) > 1 and path.endswith('/'):
            path = path[:-1]
        host = (p.netloc or '').lower()
        scheme = (p.scheme or 'http').lower()
        return f"{scheme}://{host}{path}"
    except Exception:
        return str(url or '').strip()

def guess_location(evidence: str, asset_url: str) -> str:
    ev = (evidence or '').lower()
    url = (asset_url or '').lower()
    if 'header parameter' in ev:
        return 'header'
    if 'cookie parameter' in ev or 'set-cookie' in ev:
        return 'cookie'
    if 'body parameter' in ev or 'form field' in ev:
        return 'body'
    if '?' in url:
        return 'query'
    return 'path'

def extract_param(payload: str, evidence: str, asset_url: str) -> str:
    try:
        if ':' in (payload or '') and (payload or '').split(':', 1)[0].strip().lower().startswith((
            'x-','true-','forwarded','content-','accept','client','host','origin','referer','user-agent','cookie'
        )):
            return (payload or '').split(':', 1)[0].strip()
    except Exception:
        pass
    # Prefer URL query param when present
    try:
        qs = urlparse(asset_url or '').query
        params = [name for name, _ in parse_qsl(qs, keep_blank_values=True)]
        if params:
            lp = (payload or '').lower()
            for name in params:
                if name.lower() in lp:
                    return name
            return params[0]
    except Exception:
        pass
    try:
        if 'parameter ' in (evidence or ''):
            after = (evidence or '').split('parameter ', 1)[1].strip()
            token = after.split()[0].strip().strip(':').strip()
            if token:
                return token
    except Exception:
        pass
    try:
        if '=' in (payload or ''):
            left = (payload or '').split('=', 1)[0]
            candidate = left.strip().split()[-1] if left.strip() else left
            candidate = candidate.strip("'\";&:,{}[]()")
            if candidate:
                return candidate
    except Exception:
        pass
    try:
        qs = urlparse(asset_url or '').query
        params = parse_qsl(qs, keep_blank_values=True)
        if params:
            return params[0][0]
    except Exception:
        pass
    return ''

def main():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        SELECT v.id, v.type, v.evidence, v.payload, a.url
        FROM vulnerabilities v
        JOIN assets a ON v.asset_id=a.id
    """)
    rows = cur.fetchall()
    total = len(rows)
    clusters = defaultdict(list)
    bounty_types = {
        'sql_injection','sql-injection','sqli',
        'xss','xss_reflection','blind_xss','blind_xss_probe','dom_xss',
        'csrf','lfi','rfi','ssrf','command_injection','rce','ssti',
        'idor','authentication_bypass','auth_bypass','open_redirect','xxe','path_traversal'
    }
    def canon_type(t: str) -> str:
        t = (t or '').lower()
        if t in {'sql-injection','sql_injection','sqli','sql-injection-error'}: return 'sql_injection'
        if t in {'xss','xss_reflection','blind_xss','blind_xss_probe','dom_xss'}: return 'xss'
        if t in {'file_inclusion','lfi','rfi'}: return 'lfi'
        if t in {'cmd_injection','command_injection','rce','os_command_injection'}: return 'command_injection'
        if t in {'auth_bypass','authentication_bypass'}: return 'auth_bypass'
        if t in {'path_traversal','directory_traversal'}: return 'path_traversal'
        if t in {'open_redirect','redirect'}: return 'open_redirect'
        return t
    for vid, vtype, evidence, payload, aurl in rows:
        vnorm = canon_type(vtype)
        if ONLY_BOUNTY and vnorm not in bounty_types:
            continue
        endpoint = normalize_endpoint(aurl)
        location = guess_location(evidence, aurl)
        param = extract_param(payload, evidence, aurl)
        key = (vnorm, endpoint, (param or ''), (location or ''))
        clusters[key].append(vid)

    uniques = len(clusters)
    by_size = sorted(((k, len(v)) for k, v in clusters.items()), key=lambda kv: kv[1], reverse=True)

    print(f"Total vulnerability rows: {total}")
    print(f"Canonical unique vulns:  {uniques}")
    print(f"Duplicate rows collapsed: {total - uniques}")
    print("\nTop duplicate clusters (type endpoint [location:param] -> count):")
    for (vtype, endpoint, param, location), count in by_size[:20]:
        print(f"- {vtype} {endpoint} [{location}:{param or '-'}] -> {count}")

    # Unique counts by host (canonical)
    from urllib.parse import urlparse
    host_counts = defaultdict(int)
    for (vtype, endpoint, param, location) in clusters.keys():
        try:
            host = urlparse(endpoint).netloc.lower()
        except Exception:
            host = ''
        host_counts[host] += 1
    print("\nCanonical uniques by host:")
    for host, cnt in sorted(host_counts.items(), key=lambda kv: kv[1], reverse=True):
        print(f"- {host}: {cnt}")

if __name__ == '__main__':
    main()
