#!/usr/bin/env python3
"""
Universal Auth CLI for ModScan

Manage per-domain authentication policies and cookies in a target-agnostic way.

Commands:
  - set-login: Save login policy (url, username, password)
  - refresh:   Perform generic login and persist cookie
  - status:    Show saved policy and cookie snippet
  - validate:  Validate current/locked cookie against a URL
  - lock:      Persist current cookie as locked (optional hardening)
  - clear:     Remove cookie and/or policy for a domain

This tool relies exclusively on universal heuristics (no app-specific logic).
"""
from __future__ import annotations

import argparse
import json
import os
from urllib.parse import urlparse

from asset_manager import AssetManager
from modules.auth_manager import AuthManager


def _domain_key(s: str) -> str:
    if '://' in s:
        try:
            return (urlparse(s).hostname or s).lower()
        except Exception:
            return s
    return s.lower()


def cmd_set_login(args) -> int:
    am = AssetManager()
    _, policy = AuthManager(am, {}).load_policy(args.domain)
    pol = (policy or {})
    pol['login'] = {
        'url': args.url,
        'username': args.username,
        'password': args.password,
    }
    key = _domain_key(args.domain)
    with am._get_db() as db:
        db.execute(
            """
            INSERT INTO cookies(domain, policy, last_updated)
            VALUES(?,?,datetime('now'))
            ON CONFLICT(domain) DO UPDATE SET policy=excluded.policy, last_updated=excluded.last_updated
            """,
            (key, json.dumps(pol))
        )
        db.commit()
    print(f"✅ Saved login policy for {key}")
    return 0


def cmd_refresh(args) -> int:
    am = AssetManager()
    key = _domain_key(args.domain)
    mgr = AuthManager(am, {})
    cookie, policy = mgr.load_policy(key)
    if not policy or not policy.get('login'):
        print("❌ No login policy found. Use set-login first.")
        return 2
    import asyncio
    new_cookie = asyncio.run(mgr.refresh_session(key, policy))
    if not new_cookie:
        print("❌ Login failed or no cookie produced.")
        return 3
    print(f"✅ Refreshed cookie for {key}: {new_cookie[:120]}…")
    return 0


def cmd_status(args) -> int:
    am = AssetManager()
    key = _domain_key(args.domain)
    mgr = AuthManager(am, {})
    cookie, policy = mgr.load_policy(key)
    print(json.dumps({
        'domain': key,
        'has_cookie': bool(cookie),
        'cookie_preview': (cookie[:200] + '…') if cookie else None,
        'policy': policy or {},
    }, ensure_ascii=False, indent=2))
    return 0


def cmd_validate(args) -> int:
    am = AssetManager()
    key = _domain_key(args.domain)
    mgr = AuthManager(am, {})
    cookie, _ = mgr.load_policy(key)
    # Allow override via env lock
    locked = mgr.get_locked_cookie(key)
    if locked:
        cookie = locked
    if not cookie:
        print("❌ No cookie available. Try refresh.")
        return 2
    import asyncio
    ok = asyncio.run(mgr.validate_session(args.url, cookie))
    print("✅ Session valid" if ok else "⚠️ Session invalid")
    return 0 if ok else 4


def cmd_lock(args) -> int:
    am = AssetManager()
    key = _domain_key(args.domain)
    mgr = AuthManager(am, {})
    cookie, _ = mgr.load_policy(key)
    if not cookie:
        print("❌ No current cookie found to lock. Try refresh.")
        return 2
    mgr.persist_locked_cookie(key, cookie)
    print(f"🔒 Locked cookie for {key} (env override MODSCAN_AUTH_LOCK_MODE=1 to enforce)")
    return 0


def cmd_clear(args) -> int:
    am = AssetManager()
    key = _domain_key(args.domain)
    with am._get_db() as db:
        if args.policy and args.cookie:
            db.execute("DELETE FROM cookies WHERE domain=?", (key,))
            print(f"🧹 Removed cookie+policy for {key}")
        else:
            if args.cookie:
                db.execute("UPDATE cookies SET cookie=NULL WHERE domain=?", (key,))
                print(f"🧹 Cleared cookie for {key}")
            if args.policy:
                db.execute("UPDATE cookies SET policy=NULL WHERE domain=?", (key,))
                print(f"🧹 Cleared policy for {key}")
        db.commit()
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="ModScan Universal Auth Manager")
    sub = p.add_subparsers(dest='cmd', required=True)

    sp = sub.add_parser('set-login', help='Save universal login policy for a domain')
    sp.add_argument('--domain', required=True, help='Domain or base URL')
    sp.add_argument('--url', required=True, help='Login URL')
    sp.add_argument('--username', required=True)
    sp.add_argument('--password', required=True)
    sp.set_defaults(func=cmd_set_login)

    sp = sub.add_parser('refresh', help='Perform login using saved policy and persist cookie')
    sp.add_argument('--domain', required=True)
    sp.set_defaults(func=cmd_refresh)

    sp = sub.add_parser('status', help='Show saved policy and cookie preview')
    sp.add_argument('--domain', required=True)
    sp.set_defaults(func=cmd_status)

    sp = sub.add_parser('validate', help='Validate cookie/session against a URL')
    sp.add_argument('--domain', required=True)
    sp.add_argument('--url', required=True, help='Protected URL to validate access')
    sp.set_defaults(func=cmd_validate)

    sp = sub.add_parser('lock', help='Persist current cookie as locked for this domain')
    sp.add_argument('--domain', required=True)
    sp.set_defaults(func=cmd_lock)

    sp = sub.add_parser('clear', help='Clear cookie and/or policy for a domain')
    sp.add_argument('--domain', required=True)
    sp.add_argument('--cookie', action='store_true', help='Clear cookie')
    sp.add_argument('--policy', action='store_true', help='Clear policy')
    sp.set_defaults(func=cmd_clear)

    args = p.parse_args()
    return int(args.func(args))


if __name__ == '__main__':
    raise SystemExit(main())

