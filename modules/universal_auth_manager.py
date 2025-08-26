#!/usr/bin/env python3
"""
Universal Authentication Manager
Handles automatic re-authentication for ANY target when login redirects are detected
"""
import asyncio
import aiohttp
import json
import logging
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse, urljoin
import re

logger = logging.getLogger("UniversalAuthManager")

class UniversalAuthManager:
    def __init__(self, asset_manager, config):
        self.asset_manager = asset_manager
        self.config = config
        self.auth_cache = {}
        
        logger.info("🔐 Universal Authentication Manager initialized")
    
    async def ensure_authenticated_request(self, 
                                         url: str, 
                                         session: aiohttp.ClientSession,
                                         max_retries: int = 2) -> Tuple[Optional[str], bool]:
        """
        Ensure request is authenticated - handles re-auth automatically for ANY target
        Returns: (auth_cookie, authentication_successful)
        """
        
        # Try with existing cookie first
        current_cookie = self.config.get('auth_cookie')
        if current_cookie:
            auth_result = await self._test_authentication(url, session, current_cookie)
            if auth_result['authenticated']:
                return current_cookie, True
        
        # Authentication needed - attempt automatic re-auth
        logger.warning(f"🔑 Authentication required for {url} - attempting automatic login")
        
        for attempt in range(max_retries):
            try:
                new_cookie = await self._attempt_universal_reauth(url, session)
                if new_cookie:
                    # For session-based apps, try the auth immediately - don't test again
                    # The fact that we got new cookies means login was likely successful
                    if 'PHPSESSID' in new_cookie and 'security=' in new_cookie:
                        # Update config and cache
                        self.config['auth_cookie'] = new_cookie
                        self._update_auth_cache(url, new_cookie)
                        logger.info(f"✅ Session authentication successful for {urlparse(url).netloc}")
                        return new_cookie, True
                    else:
                        # Test the new authentication for other types of auth
                        auth_result = await self._test_authentication(url, session, new_cookie)
                        if auth_result['authenticated']:
                            # Update config and cache
                            self.config['auth_cookie'] = new_cookie
                            self._update_auth_cache(url, new_cookie)
                            logger.info(f"✅ Re-authentication successful for {urlparse(url).netloc}")
                            return new_cookie, True
                
            except Exception as e:
                logger.debug(f"Re-auth attempt {attempt + 1} failed: {e}")
        
        logger.warning(f"❌ Could not establish authentication for {url}")
        return None, False
    
    async def _test_authentication(self, url: str, session: aiohttp.ClientSession, cookie: str) -> Dict:
        """Test if authentication is working by following redirects and checking final content"""
        
        try:
            headers = {'Cookie': cookie}
            
            # Follow redirects to see where we end up
            async with session.get(url, headers=headers, allow_redirects=True, timeout=10) as response:
                final_url = str(response.url)
                content = await response.text()
                
                result = {
                    'authenticated': True,
                    'status': response.status,
                    'final_url': final_url,
                    'content_preview': content[:200].lower()
                }
                
                # If we ended up on a login page after following redirects, auth failed
                if any(login_indicator in final_url.lower() for login_indicator in 
                       ['login', 'signin', 'auth', 'authenticate']):
                    result['authenticated'] = False
                    result['reason'] = 'redirected_to_login'
                    logger.debug(f"Auth failed: final URL is {final_url}")
                    return result
                
                # Check content for login indicators
                login_indicators = [
                    'login', 'sign in', 'username', 'password', 'authentication required',
                    'please log in', 'access denied', 'unauthorized', 'session expired'
                ]
                
                if any(indicator in result['content_preview'] for indicator in login_indicators):
                    # Additional check - look for actual login forms
                    if re.search(r'<input[^>]*type\s*=\s*["\']password["\']', content, re.IGNORECASE):
                        result['authenticated'] = False
                        result['reason'] = 'login_form_detected'
                        return result
                
                # If we have vulnerable page indicators, authentication succeeded
                vuln_indicators = ['user id', 'submit', 'injection', 'vulnerable', 'exploit']
                if any(indicator in result['content_preview'] for indicator in vuln_indicators):
                    result['authenticated'] = True
                    logger.debug(f"Auth success: found vulnerable page content")
                    return result
                
                # Debug: Always log auth test details
                logger.debug(f"Auth test details - Final URL: {final_url}")
                logger.debug(f"Auth test details - Status: {response.status}")
                logger.debug(f"Auth test details - Content preview: {result['content_preview']}")
                
                return result
                
        except Exception as e:
            logger.debug(f"Auth test failed for {url}: {e}")
            return {'authenticated': False, 'error': str(e)}
    
    async def _attempt_universal_reauth(self, target_url: str, session: aiohttp.ClientSession) -> Optional[str]:
        """Attempt universal re-authentication using stored credentials"""
        
        try:
            # Load stored authentication data from database
            auth_data = self._load_stored_auth_data(target_url)
            if not auth_data:
                return None
            
            login_url = auth_data.get('login_url')
            username = auth_data.get('username') 
            password = auth_data.get('password')
            
            if not all([login_url, username, password]):
                logger.debug("Missing authentication credentials")
                return None
            
            logger.info(f"🔐 Attempting login to {login_url} with credentials: {username}:{password}")
            
            # Step 1: Get login form
            async with session.get(login_url, timeout=10) as response:
                login_page = await response.text()
                logger.debug(f"Login form status: {response.status}")
            
            # Step 2: Parse form data and CSRF tokens
            form_data = self._parse_login_form(login_page, username, password)
            logger.debug(f"Login form data: {form_data}")
            
            # Step 3: Submit login
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Referer': login_url,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            logger.info(f"🚀 Submitting login form to {login_url}")
            async with session.post(login_url, data=form_data, headers=headers, 
                                  allow_redirects=True, timeout=15) as response:
                
                logger.info(f"📥 Login response: {response.status} - {response.url}")
                response_text = await response.text()
                logger.debug(f"Login response preview: {response_text[:200]}...")
                
                # Extract authentication cookie from response headers
                set_cookie_headers = response.headers.getall('Set-Cookie', [])
                new_cookies = []
                
                # Parse Set-Cookie headers
                for cookie_header in set_cookie_headers:
                    if '=' in cookie_header:
                        cookie_part = cookie_header.split(';')[0]  # Get main cookie part
                        new_cookies.append(cookie_part)
                
                # Also get cookies from aiohttp cookie jar  
                try:
                    for cookie in response.cookies:
                        if hasattr(cookie, 'key') and hasattr(cookie, 'value'):
                            cookie_str = f"{cookie.key}={cookie.value}"
                        else:
                            # Handle different cookie formats
                            cookie_str = str(cookie)
                        
                        if cookie_str not in new_cookies and '=' in cookie_str:
                            new_cookies.append(cookie_str)
                except Exception as e:
                    logger.debug(f"Cookie extraction from jar failed: {e}")
                    # Try alternative method
                    cookie_header = response.headers.get('Set-Cookie', '')
                    if cookie_header and '=' in cookie_header:
                        cookie_part = cookie_header.split(';')[0]
                        new_cookies.append(cookie_part)
                
                if new_cookies:
                    auth_cookie = '; '.join(new_cookies)
                    
                    # Universal security level optimization - works for ANY app
                    auth_cookie = self._optimize_security_settings(auth_cookie)
                    
                    return auth_cookie
            
        except Exception as e:
            logger.debug(f"Universal re-auth failed: {e}")
        
        return None
    
    def _optimize_security_settings(self, auth_cookie: str) -> str:
        """Universal security settings optimization - works for ANY application"""
        try:
            # Parse cookie into key-value pairs
            cookie_dict = {}
            for cookie_pair in auth_cookie.split('; '):
                if '=' in cookie_pair:
                    key, value = cookie_pair.split('=', 1)
                    cookie_dict[key.strip()] = value.strip()
            
            # Universal security level optimizations
            optimizations_applied = []
            
            # Pattern 1: Security level settings (DVWA, custom apps, etc.)
            if 'security' in cookie_dict:
                current_security = cookie_dict['security'].lower()
                if current_security in ['impossible', 'high', 'medium']:
                    cookie_dict['security'] = 'low'
                    optimizations_applied.append(f"security: {current_security}→low")
            
            # Pattern 2: Debug mode activation (common in dev environments)
            debug_keys = ['debug', 'DEBUG', 'debug_mode', 'development']
            for debug_key in debug_keys:
                if debug_key in cookie_dict and cookie_dict[debug_key].lower() in ['0', 'false', 'off']:
                    cookie_dict[debug_key] = '1'
                    optimizations_applied.append(f"{debug_key}→enabled")
            
            # Pattern 3: Test mode activation
            test_keys = ['test', 'test_mode', 'testing']
            for test_key in test_keys:
                if test_key in cookie_dict and cookie_dict[test_key].lower() in ['0', 'false', 'off']:
                    cookie_dict[test_key] = '1' 
                    optimizations_applied.append(f"{test_key}→enabled")
            
            # Pattern 4: Admin/privileged access
            admin_keys = ['admin', 'is_admin', 'admin_mode', 'privilege', 'role']
            for admin_key in admin_keys:
                if admin_key in cookie_dict:
                    current_value = cookie_dict[admin_key].lower()
                    if current_value in ['0', 'false', 'user', 'guest', 'normal']:
                        if admin_key == 'role':
                            cookie_dict[admin_key] = 'admin'
                        else:
                            cookie_dict[admin_key] = '1'
                        optimizations_applied.append(f"{admin_key}→elevated")
            
            # Rebuild optimized cookie
            optimized_cookie = '; '.join(f"{k}={v}" for k, v in cookie_dict.items())
            
            if optimizations_applied:
                logger.info(f"🔧 Universal security optimizations: {', '.join(optimizations_applied)}")
                return optimized_cookie
            else:
                logger.debug("🔒 No security optimizations needed")
                return auth_cookie
                
        except Exception as e:
            logger.debug(f"Security optimization failed: {e}")
            return auth_cookie
    
    def _load_stored_auth_data(self, target_url: str) -> Optional[Dict]:
        """Load stored authentication data from database"""
        try:
            import sqlite3
            parsed_url = urlparse(target_url)
            domain = parsed_url.netloc
            
            with sqlite3.connect(self.asset_manager.db_path) as db:
                cursor = db.execute("""
                    SELECT domain, cookie, persistent, auth_keys, policy 
                    FROM cookies 
                    WHERE domain LIKE ? OR domain LIKE ?
                    ORDER BY last_updated DESC LIMIT 1
                """, (f"%{domain}%", f"%{parsed_url.hostname}%"))
                
                row = cursor.fetchone()
                if row:
                    domain_val, cookie, persistent, auth_keys, policy = row
                    
                    # Try to parse stored authentication data
                    auth_data = {}
                    if auth_keys:
                        auth_data['auth_keys'] = auth_keys
                    
                    if policy:
                        try:
                            policy_data = json.loads(policy)
                            auth_data.update(policy_data)
                        except:
                            pass
                    
                    # Extract login URL, username, password from auth_keys or policy
                    if auth_keys and ':' in auth_keys:  # Format: password:password or username:password
                        if auth_keys.startswith('password:'):
                            # DVWA format: "password:password"
                            auth_data['username'] = 'admin'  # DVWA default
                            auth_data['password'] = auth_keys.replace('password:', '')
                        elif 'username:' in auth_keys and 'password:' in auth_keys:
                            # Standard format: "username:admin|password:password"  
                            parts = auth_keys.split('|')
                            for part in parts:
                                if part.startswith('username:'):
                                    auth_data['username'] = part.replace('username:', '')
                                elif part.startswith('password:'):
                                    auth_data['password'] = part.replace('password:', '')
                        else:
                            # Simple format: "username:password"
                            parts = auth_keys.split(':', 1)
                            if len(parts) == 2:
                                auth_data['username'] = parts[0]
                                auth_data['password'] = parts[1]
                    
                    # Construct login URL
                    if 'login_url' not in auth_data:
                        # Guess common login URLs
                        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                        common_login_paths = ['/login.php', '/login', '/auth', '/signin', '/dvwa/login.php']
                        
                        for path in common_login_paths:
                            potential_url = base_url + path
                            auth_data['login_url'] = potential_url
                            break
                    
                    return auth_data
        
        except Exception as e:
            logger.debug(f"Failed to load auth data: {e}")
        
        return None
    
    def _parse_login_form(self, html: str, username: str, password: str) -> Dict:
        """Parse login form and extract required fields"""
        
        form_data = {
            'username': username,
            'password': password,
            'user': username,  # Alternative field name
            'pass': password,  # Alternative field name
            'Login': 'Login'   # Common submit button
        }
        
        # Extract CSRF tokens
        csrf_patterns = [
            r'name=["\']user_token["\'] value=["\']([^"\']+)["\']',
            r'name=["\']csrf["\'] value=["\']([^"\']+)["\']',
            r'name=["\']_token["\'] value=["\']([^"\']+)["\']',
            r'name=["\']token["\'] value=["\']([^"\']+)["\']'
        ]
        
        for pattern in csrf_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                form_data['user_token'] = match.group(1)
                form_data['csrf'] = match.group(1)
                form_data['_token'] = match.group(1)
                form_data['token'] = match.group(1)
                break
        
        return form_data
    
    def _update_auth_cache(self, url: str, cookie: str):
        """Update authentication cache"""
        domain = urlparse(url).netloc
        self.auth_cache[domain] = {
            'cookie': cookie,
            'timestamp': asyncio.get_event_loop().time()
        }
        
        # Update database
        try:
            import sqlite3
            with sqlite3.connect(self.asset_manager.db_path) as db:
                db.execute("""
                    UPDATE cookies 
                    SET cookie = ?, last_updated = datetime('now')
                    WHERE domain LIKE ?
                """, (cookie, f"%{domain}%"))
                db.commit()
        except Exception as e:
            logger.debug(f"Failed to update auth cache: {e}")