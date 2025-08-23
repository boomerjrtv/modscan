#!/usr/bin/env python3
"""
Universal Auth Manager

Loads per-domain auth policy (cookie, headers, bearer, login flow) from the database
and can refresh session cookies by replaying a generic login flow with CSRF token extraction.

No target-specific logic — uses common heuristics that work across many apps.
"""

import asyncio
import aiohttp
import sqlite3
from typing import Optional, Dict, Tuple
import re

class AuthManager:
    def __init__(self, asset_manager, config: Dict):
        self.asset_manager = asset_manager
        self.config = config

    def load_policy(self, domain: str) -> Tuple[Optional[str], Optional[Dict]]:
        """Return (cookie_string, policy_dict) for domain from DB if present."""
        try:
            with self.asset_manager._get_db() as db:
                row = db.execute("SELECT cookie, policy FROM cookies WHERE domain=?", (domain,)).fetchone()
                cookie = row[0] if row and len(row) > 0 else None
                pol = None
                if row and len(row) > 1 and row[1]:
                    import json
                    try:
                        pol = json.loads(row[1])
                    except Exception:
                        pol = None
                return cookie, pol
        except Exception:
            return None, None

    async def refresh_session(self, domain: str, policy: Dict) -> Optional[str]:
        """Attempt generic login based on policy: returns new cookie string or None."""
        login_cfg = (policy or {}).get('login') or {}
        login_url = login_cfg.get('url')
        username = login_cfg.get('username')
        password = login_cfg.get('password')
        if not (login_url and username and password):
            return None

        jar = aiohttp.CookieJar(unsafe=True)
        async with aiohttp.ClientSession(cookie_jar=jar) as session:
            # GET login page to collect CSRF tokens
            try:
                async with session.get(login_url, timeout=20) as resp:
                    html = await resp.text()
            except Exception:
                return None

            # Extract common CSRF or anti-forgery tokens
            tokens: Dict[str, str] = {}
            try:
                for name in [
                    'csrf', 'csrf_token', 'authenticity_token', 'request_verification_token',
                    'anti_csrf', 'xsrf_token', 'user_token'
                ]:
                    m = re.search(rf'name=[\"\']{name}[\"\']\s+value=[\"\']([^\"\']+)[\"\']', html, re.I)
                    if m:
                        tokens[name] = m.group(1)
            except Exception:
                tokens = {}

            # Build form; include generic submit name variants
            form = {
                'username': username,
                'email': username,
                'user': username,
                'password': password,
                'pass': password,
                'Login': 'Login',
                'submit': 'Login'
            }
            # Merge tokens (both key=value; also try frameworks like ASP.NET)
            for k, v in tokens.items():
                form[k] = v

            # POST login
            try:
                async with session.post(login_url, data=form, allow_redirects=True, timeout=25) as r2:
                    _ = await r2.text()
            except Exception:
                return None

            # Extract cookie string from jar
            parts = []
            for c in session.cookie_jar:
                parts.append(f"{c.key}={c.value}")
            new_cookie = '; '.join(parts)
            if not new_cookie:
                return None

            # Persist cookie back to DB (keep persistent merges to backend endpoints elsewhere)
            try:
                with self.asset_manager._get_db() as db:
                    db.execute(
                        "INSERT INTO cookies(domain, cookie, last_updated) VALUES(?,?,datetime('now'))\n                         ON CONFLICT(domain) DO UPDATE SET cookie=excluded.cookie, last_updated=excluded.last_updated",
                        (domain, new_cookie)
                    )
                    db.commit()
            except Exception:
                pass
            return new_cookie

    @staticmethod
    def looks_like_login(html: str) -> bool:
        if not html:
            return False
        h = html.lower()
        if 'type="password"' in h or 'name="password"' in h:
            return True
        if 'signin' in h or 'log in' in h or 'login' in h:
            return True
        return False

