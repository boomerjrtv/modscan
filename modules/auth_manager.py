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
import logging

logger = logging.getLogger(__name__)

class AuthManager:
    def __init__(self, asset_manager, config: Dict):
        self.asset_manager = asset_manager
        self.config = config

    # ---------- Cookie Lock / Minimization Utilities ----------
    def _env(self, key: str, default: Optional[str] = None) -> Optional[str]:
        import os
        return os.environ.get(key, default)

    def get_locked_cookie(self, domain: str) -> Optional[str]:
        """Return a locked cookie string if configured (env or DB policy)."""
        # Highest priority: environment override
        env_locked = self._env('MODSCAN_LOCKED_COOKIES')
        if env_locked:
            return env_locked.strip()
        # DB policy
        try:
            _, pol = self.load_policy(domain)
            if pol and isinstance(pol, dict):
                lc = pol.get('locked_cookies') or pol.get('locked_cookie')
                if isinstance(lc, str) and lc.strip():
                    return lc.strip()
        except Exception:
            pass
        return None

    def persist_locked_cookie(self, domain: str, cookie: str) -> None:
        """Persist a cookie as both current and locked in the cookies table policy JSON (universal)."""
        try:
            import json
            with self.asset_manager._get_db() as db:
                row = db.execute("SELECT policy FROM cookies WHERE domain=?", (domain,)).fetchone()
                pol = {}
                if row and row[0]:
                    try:
                        pol = json.loads(row[0]) or {}
                    except Exception:
                        pol = {}
                pol['locked_cookies'] = cookie
                db.execute(
                    """
                    INSERT INTO cookies(domain, cookie, policy, last_updated)
                    VALUES(?,?,?,datetime('now'))
                    ON CONFLICT(domain) DO UPDATE SET cookie=excluded.cookie, policy=excluded.policy, last_updated=excluded.last_updated
                    """,
                    (domain, cookie, json.dumps(pol))
                )
                db.commit()
        except Exception:
            pass

    @staticmethod
    def minimize_cookie(cookie: str, keep_keys: Optional[list] = None) -> str:
        """Return a minimized cookie string keeping only selected keys (universal)."""
        if not cookie:
            return cookie
        keep = set([k.strip().lower() for k in (keep_keys or []) if k.strip()])
        parts = []
        for seg in cookie.split(';'):
            seg = seg.strip()
            if '=' not in seg:
                continue
            name, value = seg.split('=', 1)
            n = name.strip()
            if keep and n.lower() not in keep:
                continue
            parts.append(f"{n}={value.strip()}")
        return '; '.join(parts)

    def load_policy(self, domain: str) -> Tuple[Optional[str], Optional[Dict]]:
        """Return (cookie_string, policy_dict) for domain from DB if present.

        Robust to how the key was saved (full URL vs host). Tries:
        1) Exact key
        2) Host-only key
        3) Any row whose domain contains the host
        Falls back to config/env login policy if none found.
        """
        try:
            with self.asset_manager._get_db() as db:
                import json
                # 1) Exact key
                row = db.execute("SELECT cookie, policy FROM cookies WHERE domain=?", (domain,)).fetchone()
                # 2) Host-only key
                if not row and domain:
                    host = domain
                    try:
                        from urllib.parse import urlparse
                        host = (urlparse(domain).hostname or domain)
                    except Exception:
                        host = domain
                    row = db.execute("SELECT cookie, policy FROM cookies WHERE domain=?", (host,)).fetchone()
                # 3) Contains host anywhere (last resort)
                if not row and domain:
                    try:
                        from urllib.parse import urlparse
                        host = (urlparse(domain).hostname or domain)
                    except Exception:
                        host = domain
                    row = db.execute("SELECT cookie, policy FROM cookies WHERE domain LIKE ? ORDER BY last_updated DESC", (f"%{host}%",)).fetchone()

                cookie = row[0] if row and len(row) > 0 else None
                pol = None
                if row and len(row) > 1 and row[1]:
                    try:
                        pol = json.loads(row[1])
                    except Exception:
                        pol = None
                # If no DB policy, fall back to universal config/env values (works for any target)
                if not pol:
                    cfg = self.config or {}
                    login_url = cfg.get('login_url')
                    login_user = cfg.get('login_username')
                    login_pass = cfg.get('login_password')
                    if login_url and login_user and login_pass:
                        pol = {
                            'login': {
                                'url': login_url,
                                'username': login_user,
                                'password': login_pass,
                            }
                        }
                return cookie, pol
        except Exception:
            return None, None

    async def refresh_session(self, domain: str, policy: Dict) -> Optional[str]:
        """Attempt robust login based on policy: returns new cookie string or None.

        Improvements:
        - Fetch login page and parse the first form using universal_form_parser
        - Use discovered username/password field names and CSRFs
        - Follow redirects and capture final cookies
        """
        login_cfg = (policy or {}).get('login') or {}
        login_url = login_cfg.get('url')
        username = login_cfg.get('username')
        password = login_cfg.get('password')
        if not (login_url and username and password):
            return None

        jar = aiohttp.CookieJar(unsafe=True)
        timeout = aiohttp.ClientTimeout(total=35)
        async with aiohttp.ClientSession(cookie_jar=jar, timeout=timeout) as session:
            # GET login page (capture base for action resolution)
            try:
                async with session.get(login_url, allow_redirects=True) as resp:
                    base_url = str(resp.url)
                    html = await resp.text()
            except Exception as e:
                logger.debug(f"Login GET failed for {login_url}: {e}")
                return None

            # Parse form with universal parser
            try:
                from .universal_form_parser import parse_forms, build_form_data
                forms = parse_forms(html, base_url=base_url)
            except Exception:
                forms = []

            target_form = None
            for f in forms or []:
                ins = f.get('inputs') or {}
                if any('pass' in (k or '').lower() for k in ins.keys()):
                    target_form = f
                    break
            if not target_form:
                # Fallback to post directly to login_url with generic names
                target_action = login_url
                method = 'POST'
                inputs = {'username': {'type':'text','value':''}, 'password': {'type':'password','value':''}}
            else:
                target_action = target_form.get('action') or base_url
                method = (target_form.get('method') or 'POST').upper()
                inputs = target_form.get('inputs') or {}

            # Identify likely username/password field names
            user_field = next((n for n in inputs.keys() if any(tok in (n or '').lower() for tok in ['user','username','email','login'])), 'username')
            pass_field = next((n for n in inputs.keys() if 'pass' in (n or '').lower()), 'password')

            payload = {user_field: username, pass_field: password}
            try:
                data = build_form_data(inputs, payload)
            except Exception:
                data = payload

            # Set Referer/Origin
            headers = {}
            try:
                from urllib.parse import urlparse
                pu = urlparse(target_action)
                headers['Referer'] = base_url
                headers['Origin'] = f"{pu.scheme}://{pu.netloc}"
            except Exception:
                pass

            # Submit login
            try:
                if method == 'POST':
                    async with session.post(target_action, data=data, allow_redirects=True, headers=headers) as r2:
                        _ = await r2.text()
                else:
                    async with session.get(target_action, params=data, allow_redirects=True, headers=headers) as r2:
                        _ = await r2.text()
            except Exception as e:
                logger.debug(f"Login POST failed for {target_action}: {e}")
                return None

            # Build cookie string only for this domain scope (avoid setting unrelated cookies)
            parts = []
            try:
                # Prefer cookies set for the target domain and parent
                for c in session.cookie_jar:
                    parts.append(f"{c.key}={c.value}")
            except Exception:
                pass
            new_cookie = '; '.join(parts)
            if not new_cookie:
                return None

            # Persist cookie
            try:
                with self.asset_manager._get_db() as db:
                    from urllib.parse import urlparse
                    host = (urlparse(domain).hostname or domain) if '://' in domain else domain
                    for key in {domain, host, host.lstrip('www.')}:
                        db.execute(
                            "INSERT INTO cookies(domain, cookie, last_updated) VALUES(?,?,datetime('now'))\n                             ON CONFLICT(domain) DO UPDATE SET cookie=excluded.cookie, last_updated=excluded.last_updated",
                            (key, new_cookie)
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
        # Universal session expiration indicators
        session_expired_patterns = [
            'session expired', 'session timeout', 'please log in again',
            'login required', 'authentication required', 'access denied',
            'unauthorized access', 'please sign in', 'your session has expired'
        ]
        if any(pattern in h for pattern in session_expired_patterns):
            return True
        # Universal redirect patterns to login pages
        login_redirect_patterns = ['login.php', 'login.html', 'signin.php', 'auth.php', '/login', '/signin']
        if any(pattern in h and ('redirect' in h or 'location.href' in h or 'window.location' in h) 
               for pattern in login_redirect_patterns):
            return True
        return False
        
    async def validate_session(self, url: str, cookie: str) -> bool:
        """Universal session validation - tests if cookie is still valid for any target"""
        try:
            async with aiohttp.ClientSession() as session:
                headers = {"Cookie": cookie}
                async with session.get(url, headers=headers, timeout=10, allow_redirects=False) as response:
                    # Check HTTP status codes that indicate invalid sessions
                    if response.status in [401, 403]:  # Unauthorized/Forbidden
                        return False
                        
                    if response.status == 302:  # Redirect (often to login)
                        location = response.headers.get('Location', '').lower()
                        login_indicators = ['login', 'signin', 'auth', 'logon']
                        if any(indicator in location for indicator in login_indicators):
                            return False
                    
                    # Check response content for session invalidity indicators
                    html = await response.text()
                    html_lower = html.lower()
                    
                    # Universal patterns indicating invalid/expired sessions
                    invalid_session_patterns = [
                        'please log in', 'login required', 'session expired',
                        'session timeout', 'authentication required', 'access denied',
                        'unauthorized', 'please sign in', 'your session has expired',
                        'session invalid', 'please login', 'login to continue'
                    ]
                    
                    if any(pattern in html_lower for pattern in invalid_session_patterns):
                        return False
                        
                    # Check if we're seeing a login form (indicates session lost)
                    if ('type="password"' in html_lower or 'name="password"' in html_lower) and \
                       ('type="text"' in html_lower and any(field in html_lower for field in ['username', 'email', 'user'])):
                        return False
                    
                    return True  # Session appears valid
                    
        except Exception as e:
            logger.debug(f"Session validation failed for {url}: {e}")
            return False  # Assume invalid if we can't test
    
    async def ensure_valid_session(self, url: str, domain: str) -> Optional[str]:
        """Universal session management - validate and refresh if needed for any target"""
        try:
            # Check if auth validation is disabled in config
            if self.config.get('disable_auth_validation', False):
                # Auth validation disabled - return security cookies only
                return self._get_security_cookies_for_domain(domain)
            
            cookie, policy = self.load_policy(domain)
            # Optional override: always refresh before each URL (strict targets)
            import os as _os
            force_refresh = str(_os.environ.get('MODSCAN_FORCE_REFRESH_EVERY_URL', '0')).lower() in ('1','true','yes','on')
            if force_refresh and policy and policy.get('login'):
                new_cookie = await self.refresh_session(domain, policy)
                if new_cookie and await self.validate_session(url, new_cookie):
                    return new_cookie
            # Cookie lock mode: prefer locked cookie if provided
            lock_mode = str(self._env('MODSCAN_AUTH_LOCK_MODE', '0')).lower() in ('1','true','yes','on')
            locked = self.get_locked_cookie(domain) if lock_mode else None
            if locked:
                return locked
            if not cookie:
                return None
                
            # Test if current session is valid
            is_valid = await self.validate_session(url, cookie)
            
            if is_valid:
                return cookie  # Current session is good
                
            # Session is invalid, try to refresh if we have login policy
            if policy and policy.get('login'):
                logger.info(f"🔄 Session invalid for {domain}, attempting refresh")
                new_cookie = await self.refresh_session(domain, policy)
                if new_cookie:
                    # Validate the new session
                    if await self.validate_session(url, new_cookie):
                        # Optionally persist refreshed cookie as locked
                        if str(self._env('MODSCAN_PERSIST_REFRESHED_COOKIE', '0')).lower() in ('1','true','yes','on'):
                            self.persist_locked_cookie(domain, new_cookie)
                        return new_cookie
                        
            logger.warning(f"⚠️ Could not establish valid session for {domain}")
            return None
            
        except Exception as e:
            logger.debug(f"Failed to ensure valid session for {domain}: {e}")
            return None

    def _get_security_cookies_for_domain(self, domain: str) -> Optional[str]:
        """Get security-level cookies for domain without authentication validation"""
        try:
            # Get cookie overrides from config
            cookie_overrides = self.config.get('cookie_overrides', {})
            domains = cookie_overrides.get('domains', {})
            
            if domain in domains:
                domain_config = domains[domain]
                default_level = domain_config.get('default_level', 'low')
                security_levels = domain_config.get('security_levels', {})
                
                if default_level in security_levels:
                    cookie_string = security_levels[default_level]
                    logger.debug(f"🍪 Using security cookie for {domain}: {cookie_string}")
                    return cookie_string
            
            # Check global overrides
            global_overrides = cookie_overrides.get('global_overrides', {})
            if global_overrides:
                cookie_parts = []
                for key, value in global_overrides.items():
                    cookie_parts.append(f"{key}={value}")
                if cookie_parts:
                    cookie_string = "; ".join(cookie_parts)
                    logger.debug(f"🍪 Using global override cookies for {domain}: {cookie_string}")
                    return cookie_string
            
            logger.debug(f"No security cookies configured for {domain}")
            return None
            
        except Exception as e:
            logger.debug(f"Error getting security cookies for {domain}: {e}")
            return None
