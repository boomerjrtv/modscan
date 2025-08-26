#!/usr/bin/env python3
"""
Ultimate Discovery Engine - ML-Powered, Multi-Tiered Discovery System
Replaces the garbage SecLists wordlist approach with intelligent discovery
"""

import asyncio
import aiohttp
import subprocess
import json
import logging
import tempfile
import os
import re
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from urllib.parse import urljoin
from datetime import datetime
from urllib.parse import urlparse, urljoin, urlsplit

# === MODSCAN TTL GUARD (auto-injected) ===
try:
    import os, time, json
    from pathlib import Path
    _TTL_H = int(os.environ.get("MODSCAN_TTL_HOURS", "24"))
    def _normalize_host(h):
        try:
            h = (h or "").strip().lower()
            if h.startswith("*."): h = h[2:]
            return h.lstrip(".")
        except Exception:
            return h
    def _recent_gate(host: str) -> bool:
        """
        Returns True if host should be scanned now (outside TTL),
        False if we should SKIP (already scanned within TTL).
        """
        try:
            host = _normalize_host(host)
            base_dir = Path(__file__).resolve().parents[1]  # project root
            reg_path = base_dir / 'scan_registry.json'
            reg = {}
            if reg_path.exists():
                try:
                    reg = json.loads(reg_path.read_text(encoding='utf-8') or '{}')
                except Exception:
                    reg = {}
            entry = reg.get(host) or reg.get("https://" + host) or reg.get("http://" + host)
            now = int(time.time())
            if entry and isinstance(entry, dict):
                last = int(entry.get('last_scan_ts', 0))
                if now - last < _TTL_H * 3600:
                    print("[ttl] ⏭️  Skip discovery for {}: within {}h (last {}s ago)".format(host, _TTL_H, now - last))
                    return False
            # record/update immediately so concurrent cycles won’t double start
            reg[host] = {'last_scan_ts': now, 'content_hash': None, 'meta': {'phase': 'discovery'}}
            try:
                reg_path.write_text(json.dumps(reg, ensure_ascii=False, indent=2), encoding='utf-8')
            except Exception:
                pass
            return True
        except Exception as _e:
            print("[ttl] guard error:", _e)
            return True
except Exception as _e:
    def _recent_gate(host):  # fail-open
        return True
# === /MODSCAN TTL GUARD ===

# Skip TTL gate for fast discovery - we want fresh results every time
def _bypass_ttl_gate(host):
    return True

logger = logging.getLogger("UltimateDiscovery")

class UltimateDiscoveryEngine:
    def __init__(self, asset_manager, config):
        self.asset_manager = asset_manager
        self.config = config
        self.discovery_cache = set()
        self.auth_cookie = config.get('auth_cookie')
        self.auth_domain = config.get('auth_domain')
        
        # Tool paths
        self.gau_path = config.get("tools", {}).get("gau_path", "gau")
        self.waybackurls_path = config.get("tools", {}).get("waybackurls_path", "waybackurls")
        self.katana_path = config.get("tools", {}).get("katana_path", "katana")
        self.subfinder_path = config.get("tools", {}).get("subfinder_path", "subfinder")
        self.rustscan_path = config.get("tools", {}).get("rustscan_path", "rustscan")
        self.nmap_path = config.get("tools", {}).get("nmap_path", "nmap")
        
        # ML patterns for intelligent discovery
        self.ml_patterns = self._load_ml_patterns()

    def _find_binary(self, name: str, config_key: Optional[str] = None, env_key: Optional[str] = None) -> Optional[str]:
        """Locate a binary in a universal way without hardcoding paths.

        Order: config.tools[key] -> env[env_key] -> shutil.which(name)
        """
        try:
            # Config override
            bin_path = None
            if config_key and isinstance(self.config.get("tools"), dict):
                bin_path = self.config["tools"].get(config_key)
            # Env override
            if not bin_path and env_key and os.environ.get(env_key):
                bin_path = os.environ.get(env_key)
            # PATH search
            if not bin_path:
                bin_path = shutil.which(name)
            # Validate existence
            if bin_path and os.path.exists(bin_path):
                return bin_path
        except Exception:
            pass
        return None
        
    def _build_auth_headers_for_host(self, host: str) -> Dict[str, str]:
        """Build latest auth headers for the given host from the cookies table.
        - Pulls fresh cookie and policy
        - Merges persistent cookies (e.g., security=low)
        - Adds bearer/auth headers from policy when present
        """
        headers: Dict[str, str] = {}
        try:
            with self.asset_manager._get_db() as db:
                cookie = persistent = policy = auth_keys = None
                # 1) Exact match
                row = db.execute(
                    "SELECT cookie, persistent, auth_keys, policy FROM cookies WHERE domain=?",
                    (host,)
                ).fetchone()
                # 2) Flexible match: choose best candidate with longest matching suffix
                if not row:
                    all_rows = db.execute(
                        "SELECT domain, cookie, persistent, auth_keys, policy, last_updated FROM cookies"
                    ).fetchall()
                    best = None
                    best_len = -1
                    for r in all_rows:
                        d = (r[0] or '').lower()
                        if not d:
                            continue
                        if host.endswith(d) or d.endswith(host):
                            if len(d) > best_len:
                                best = r
                                best_len = len(d)
                    if best:
                        cookie = best[1] or None
                        persistent = best[2] or None
                        auth_keys = best[3] or None
                        policy = best[4] or None
                else:
                    cookie = row[0] or None
                    persistent = row[1] or None
                    auth_keys = row[2] or None
                    policy = row[3] or None
                # Merge persistent cookies if available
                if cookie:
                    cookie_map = {}
                    try:
                        for part in (cookie or '').split(';'):
                            if '=' in part:
                                k, v = part.strip().split('=', 1)
                                cookie_map[k.strip()] = v.strip()
                    except Exception:
                        pass
                    # Parse auth_keys list (names that are allowed to refresh and should not be overridden)
                    auth_names = set()
                    if auth_keys:
                        import json as _json
                        try:
                            ak = _json.loads(auth_keys)
                            if isinstance(ak, list):
                                auth_names = {str(x).strip() for x in ak if str(x).strip()}
                        except Exception:
                            pass
                    if persistent:
                        import json as _json
                        try:
                            pers_list = _json.loads(persistent)
                            if isinstance(pers_list, list):
                                for kv in pers_list:
                                    if isinstance(kv, str) and '=' in kv:
                                        k, v = kv.split('=', 1)
                                        k = k.strip(); v = v.strip()
                                        if not k or not v:
                                            continue
                                        # If k is marked as auth, do NOT override; otherwise enforce locked value
                                        if k in auth_names:
                                            # Leave refreshed auth cookie value as-is
                                            cookie_map.setdefault(k, v)
                                        else:
                                            cookie_map[k] = v
                        except Exception:
                            pass
                    # Rebuild final cookie string
                    if cookie_map:
                        cookie = '; '.join([f"{k}={v}" for k, v in cookie_map.items()])
                # Apply to headers
                if cookie:
                    headers['Cookie'] = cookie
                    # Update engine-wide memory so subsequent calls reuse
                    self.auth_cookie = cookie
                # Merge additional policy headers/bearer
                if policy:
                    import json as _json
                    try:
                        pol = _json.loads(policy)
                        if isinstance(pol, dict):
                            if pol.get('headers') and isinstance(pol['headers'], dict):
                                for k, v in pol['headers'].items():
                                    headers[str(k)] = str(v)
                            if pol.get('bearer'):
                                headers['Authorization'] = f"Bearer {pol['bearer']}"
                    except Exception:
                        pass
                # DEBUG: Log which cookies/header keys are being used (names only, not values)
                try:
                    cookie_names = []
                    if headers.get('Cookie'):
                        for p in [s.strip() for s in headers['Cookie'].split(';') if s.strip()]:
                            if '=' in p:
                                cookie_names.append(p.split('=', 1)[0])
                    header_keys = [k for k in headers.keys() if k.lower() != 'cookie']
                    # Highlight if a known persistent cookie was intended but missing
                    missing_persist = []
                    try:
                        if persistent:
                            import json as _json
                            pers_list = _json.loads(persistent)
                            names_only = []
                            if isinstance(pers_list, list):
                                for kv in pers_list:
                                    if isinstance(kv, str) and '=' in kv:
                                        names_only.append(kv.split('=',1)[0].strip())
                            for name in names_only:
                                if name and name not in cookie_names:
                                    missing_persist.append(name)
                    except Exception:
                        pass
                    if missing_persist:
                        logger.info(f"[auth] {host}: cookies={cookie_names} headers={header_keys} (missing persistent {missing_persist})")
                    else:
                        logger.info(f"[auth] {host}: cookies={cookie_names} headers={header_keys}")
                except Exception:
                    pass
        except Exception:
            # Fall back to in-memory cookie if present
            if self.auth_cookie:
                headers['Cookie'] = self.auth_cookie
        return headers

    async def _refresh_cookie_if_login(self, host: str, html: str) -> Optional[str]:
        """If page looks like login and a policy exists, refresh the cookie using AuthManager.

        Returns a new cookie string or None.
        """
        try:
            # Lazy import to avoid circulars
            from .auth_manager import AuthManager
            if not html:
                return None
            am = AuthManager(self.asset_manager, self.config)
            if not am.looks_like_login(html):
                return None
            cookie, pol = am.load_policy(host)
            if not pol or not (pol.get('login') and pol['login'].get('url')):
                return None
            new_cookie = await am.refresh_session(host, pol)
            if new_cookie:
                self.auth_cookie = new_cookie
                return new_cookie
        except Exception:
            return None
        return None

    def _load_ml_patterns(self) -> Dict:
        """Load ML-trained patterns for intelligent discovery"""
        return {
            "common_endpoints": [
                "/api/", "/admin/", "/login", "/dashboard/", "/wp-admin/",
                "/api/v1/", "/api/v2/", "/graphql", "/swagger/", "/.env",
                "/config/", "/backup/", "/test/", "/dev/", "/staging/"
            ],
            "tech_specific": {
                "php": ["/wp-content/", "/phpmyadmin/", "/index.php", "/config.php"],
                "nodejs": ["/node_modules/", "/package.json", "/.env", "/dist/"],
                "python": ["/admin/", "/api/", "/static/", "/media/", "/requirements.txt"],
                "java": ["/WEB-INF/", "/META-INF/", "/servlet/", "/struts/"],
                "apache": ["/server-status", "/server-info", "/.htaccess"],
                "nginx": ["/nginx_status", "/status"],
                "docker": ["/.dockerenv", "/docker-compose.yml"],
                "kubernetes": ["/healthz", "/metrics", "/api/v1/"]
            },
            "sensitive_files": [
                "/.env", "/.git/", "/backup.zip", "/config.json", "/secrets.yaml",
                "/id_rsa", "/private.key", "/database.sql", "/.aws/", "/.ssh/"
            ]
        }
    
    async def comprehensive_discovery(self, domain: str) -> List[str]:
        """Fast SecLists-powered directory discovery with recursion - PRIMARY METHOD"""
        logger.info(f"🚀 FAST SECLISTS DISCOVERY: {domain}")
        discovered_urls = set()
        
        # PRIMARY: Fast SecLists Directory Brute Force with Recursion
        seclists_urls = await self._fast_seclists_discovery(domain)
        discovered_urls.update(seclists_urls)
        logger.info(f"⚡ Fast SecLists: {len(seclists_urls)} URLs discovered")
        
        # SECONDARY: Authenticated crawling if available (use freshest DB cookie/policy)
        auth_headers_probe = self._build_auth_headers_for_host(domain)
        if auth_headers_probe.get('Cookie'):
            same_domain_seeds = self._existing_urls_for_domain(domain)
            crawled_urls = await self._auth_smart_crawl(domain, extra_seeds=same_domain_seeds)
            discovered_urls.update(crawled_urls)
            logger.info(f"🔐 Auth Crawl: {len(crawled_urls)} additional URLs")
        
        # TERTIARY: Historical discovery for external targets only
        if not self._is_internal_ip(domain):
            historical_urls = await self._tier1_historical_discovery(domain)
            discovered_urls.update(historical_urls)
            logger.info(f"📚 Historical: {len(historical_urls)} URLs from GAU/Wayback")

        # Avoid target-specific priority paths; rely on SecLists + smart crawling
        
        final_urls = list(discovered_urls)
        logger.info(f"🎯 DISCOVERY COMPLETE: {len(final_urls)} total URLs for {domain}")
        return final_urls
    
    def _is_internal_ip(self, domain: str) -> bool:
        """Check if domain is internal IP (skip external tools like GAU/waymore)"""
        return any(internal in domain for internal in ['192.168.', '10.', '172.16.', '127.0.0.1', 'localhost'])
    
    async def _fast_seclists_discovery(self, domain: str) -> Set[str]:
        """FAST SecLists directory brute-force with recursion and high concurrency"""
        urls = set()

        try:
            # Use existing intelligent SecListsManager for smart wordlist selection
            wordlists = await self._get_intelligent_seclists(domain)
            if not wordlists:
                logger.warning("No SecLists found, using fallback paths")
                return await self._fallback_discovery(domain)

            # Base URLs to test
            base_urls = [f"https://{domain}", f"http://{domain}"]

            # Use ffuf for fast, recursive directory enumeration if available
            ffuf_bin = self._find_binary('ffuf', config_key='ffuf_path', env_key='FFUF_PATH')
            for base_url in base_urls:
                try:
                    ffuf_results: Set[str] = set()
                    if ffuf_bin:
                        ffuf_results = await self._run_ffuf_fast(base_url, wordlists, ffuf_bin)
                        urls.update(ffuf_results)
                        logger.info(f"⚡ ffuf on {base_url}: {len(ffuf_results)} paths found")
                    else:
                        logger.debug("ffuf not found in PATH; using internal async enumerator with recursion")
                        ffuf_results = await self._parallel_recursive_bruteforce(base_url, wordlists, max_depth=3)
                        urls.update(ffuf_results)
                        logger.info(f"⚡ Internal recursive brute on {base_url}: {len(ffuf_results)} paths found")

                    # Stop after first successful base URL to avoid duplicates
                    if ffuf_results:
                        break
                        
                except Exception as e:
                    logger.debug(f"ffuf failed on {base_url}: {e}")
                    continue
            
            # Fallback to async parallel testing if ffuf fails
            if not urls:
                logger.info("⚠️ ffuf failed, using parallel async testing")
                for base_url in base_urls:
                    parallel_results = await self._parallel_wordlist_test(base_url, wordlists)
                    urls.update(parallel_results)
                    if parallel_results:
                        break
                        
        except Exception as e:
            logger.error(f"Fast SecLists discovery failed: {e}")
            
        return urls
        
    async def _get_intelligent_seclists(self, domain: str) -> List[str]:
        """Use existing SecListsManager for intelligent wordlist selection"""
        try:
            # Import and initialize SecListsManager
            from .seclists_manager import SecListsManager
            
            seclists_manager = SecListsManager(self.asset_manager, {})
            await seclists_manager.initialize()
            
            # Analyze target characteristics for intelligent selection
            target_info = {
                'domain': domain,
                'technologies': await self._detect_technologies(domain),
                'is_internal': self._is_internal_ip(domain)
            }
            
            # Get intelligent wordlists based on target analysis (comprehensive limits)
            directory_words = seclists_manager.get_intelligent_wordlist(target_info, 'directories', limit=120000)
            file_words = seclists_manager.get_intelligent_wordlist(target_info, 'files', limit=30000)
            admin_words = seclists_manager.get_intelligent_wordlist(target_info, 'admin_paths', limit=20000)
            api_words = seclists_manager.get_intelligent_wordlist(target_info, 'api_endpoints', limit=20000)
            # UNIVERSAL AUGMENTATION: also reuse SecLists subdomain tokens as potential directory names  
            # Process subdomain tokens in chunks to avoid memory issues with massive wordlists
            subdomain_tokens = seclists_manager.wordlists.get('subdomains', [])
            
            # Efficiently process subdomain tokens in chunks to avoid hang on massive lists
            subdomain_paths = []
            chunk_size = 10000  # Process 10K at a time
            total_subdomains = len(subdomain_tokens)
            logger.info(f"🔄 Processing {total_subdomains} subdomain tokens in chunks of {chunk_size}")
            
            for i in range(0, min(total_subdomains, 50000), chunk_size):  # Cap at 50K for performance
                chunk = subdomain_tokens[i:i + chunk_size]
                chunk_paths = ['/' + t for t in chunk if t and len(t) <= 18 and t.isalnum()]
                subdomain_paths.extend(chunk_paths)
                
                # Log progress for large chunks
                if i % 50000 == 0 and i > 0:
                    logger.info(f"📊 Processed {i}/{min(total_subdomains, 50000)} subdomain tokens")
            
            logger.info(f"✅ Converted {len(subdomain_paths)} subdomain tokens to directory paths")
            
            # UNIVERSAL AUGMENTATION: scrape target-visible keywords (HTML, links, robots, 404 page)
            scraped_tokens = await self._scrape_target_keywords(domain)
            scraped_paths = ['/' + t for t in scraped_tokens if t]

            # Combine all intelligent wordlists efficiently
            logger.info(f"📊 Combining wordlists: {len(directory_words)} dirs, {len(file_words)} files, {len(admin_words)} admin, {len(api_words)} api, {len(scraped_paths)} scraped, {len(subdomain_paths)} subdomain-derived")
            all_words = directory_words + file_words + admin_words + api_words + scraped_paths + subdomain_paths
            
            # Remove duplicates and normalize paths properly
            normalized_paths = set()
            for word in all_words:
                if word and isinstance(word, str):
                    # Clean and normalize the path
                    path = word.strip()
                    if path:
                        # Ensure single leading slash
                        if not path.startswith('/'):
                            path = '/' + path
                        # Remove double slashes and normalize
                        path = re.sub(r'/+', '/', path)
                        # Remove trailing slash unless it's root
                        if len(path) > 1 and path.endswith('/'):
                            path = path.rstrip('/')
                        normalized_paths.add(path)
            
            unique_paths = list(normalized_paths)
            
            logger.info(f"🧠 Intelligent SecLists: {len(unique_paths)} paths selected for {domain}")
            logger.info(f"   📁 Directories: {len(directory_words)}, 📄 Files: {len(file_words)}")
            logger.info(f"   🔐 Admin: {len(admin_words)}, 🔌 API: {len(api_words)}")
            logger.info(f"   🧩 Scraped tokens: {len(scraped_tokens)}")
            
            return unique_paths
            
        except Exception as e:
            logger.warning(f"Intelligent SecLists failed: {e}")
            return []

    async def _scrape_target_keywords(self, domain: str) -> List[str]:
        """Scrape same-origin pages to extract meaningful tokens for directory enumeration.

        Universal approach:
        - GET http/https root, robots.txt, and a random 404 path
        - Extract path segments from href/src/action
        - Extract alnum tokens 3+ chars from titles, meta, visible text
        - Weight by frequency and return deduped top-N tokens
        """
        tokens: Dict[str, int] = {}
        def add(tok: str):
            t = (tok or '').strip('/').strip()
            if not t:
                return
            if len(t) < 3:
                return
            if any(c in t for c in ' \t\r\n\"\'<>'):  # keep simple
                return
            tokens[t.lower()] = tokens.get(t.lower(), 0) + 1

        timeout = aiohttp.ClientTimeout(total=6, connect=2)
        headers = self._build_auth_headers_for_host(domain)
        urls = [f"http://{domain}/", f"https://{domain}/"]
        rnd = f"/__modscan_probe_{int(asyncio.get_event_loop().time()*1000)}__"
        urls += [f"http://{domain}/robots.txt", f"https://{domain}/robots.txt", f"http://{domain}{rnd}", f"https://{domain}{rnd}"]

        for u in urls:
            try:
                async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                    async with session.get(u, allow_redirects=True) as resp:
                        txt = await resp.text(errors='ignore')
                        base = str(resp.url)
                        # Pull href/src/action paths
                        for m in re.findall(r"(?:href|src|action)=[\"']([^\"'#>\s]+)", txt, re.I):
                            try:
                                absu = urljoin(base, m)
                                sp = urlsplit(absu)
                                if sp.netloc and sp.netloc.split(':')[0] == domain:
                                    # add each path segment
                                    for seg in [p for p in sp.path.split('/') if p]:
                                        add(seg)
                            except Exception:
                                continue
                        # Titles/meta/visible-ish words
                        for w in re.findall(r"[A-Za-z0-9_\-]{3,}", txt):
                            add(w)
                        # robots rules
                        if u.endswith('robots.txt'):
                            for line in txt.splitlines():
                                s = line.strip()
                                if not s or s.startswith('#'):
                                    continue
                                if s.lower().startswith(('allow:', 'disallow:')):
                                    path = s.split(':', 1)[1].strip()
                                    for seg in [p for p in path.split('/') if p]:
                                        add(seg)
            except Exception:
                continue
        # Rank high to low; cap to keep large but sane
        ranked = sorted(tokens.items(), key=lambda kv: kv[1], reverse=True)
        return [k for k, _ in ranked[:5000]]
    
    async def _detect_technologies(self, domain: str) -> List[str]:
        """Quick technology detection for intelligent wordlist selection"""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://{domain}", timeout=5) as response:
                    headers = dict(response.headers)
                    body = await response.text()
                    
                    technologies = []
                    
                    # Server header analysis
                    server = headers.get('Server', '').lower()
                    if 'apache' in server:
                        technologies.append('apache')
                    if 'nginx' in server:
                        technologies.append('nginx')
                    if 'iis' in server:
                        technologies.append('iis')
                    
                    # Technology detection from response
                    body_lower = body.lower()
                    if 'wp-content' in body_lower or 'wordpress' in body_lower:
                        technologies.append('wordpress')
                    if 'drupal' in body_lower:
                        technologies.append('drupal')
                    if 'joomla' in body_lower:
                        technologies.append('joomla')
                    if 'django' in body_lower:
                        technologies.append('django')
                    if 'react' in body_lower:
                        technologies.append('react')
                    if 'api' in body_lower or 'rest' in body_lower:
                        technologies.append('api')
                        
                    return technologies
                    
        except Exception as e:
            logger.debug(f"Technology detection failed for {domain}: {e}")
            return []

    def _existing_urls_for_domain(self, domain: str, limit: int = 200) -> List[str]:
        """Seed discovery with existing same-domain URLs from the database (universal)."""
        seeds = []
        try:
            existing = self.asset_manager.get_existing_urls(limit=5000)  # pull more, filter down
            host_variants = {domain, f"www.{domain}"}
            for url in existing:
                try:
                    u = urlparse(url)
                    host = (u.netloc or '').split(':')[0]
                    if host in host_variants:
                        # normalize to absolute and include
                        seeds.append(url)
                        if len(seeds) >= limit:
                            break
                except Exception:
                    continue
        except Exception:
            pass
        return seeds
    
    def _load_fast_seclists(self) -> List[str]:
        """Load large SecLists wordlists for fast comprehensive discovery"""
        import os
        from pathlib import Path
        
        all_paths = set()
        
        # Find SecLists directory
        seclists_base = None
        possible_paths = [
            "/home/michael/recon-platform/modscan/SecLists",  # Correct path for this system
            "/home/michael/SecLists",
            "./SecLists",
            "/usr/share/seclists", 
            "/opt/seclists",
            "../SecLists"
        ]
        
        for path in possible_paths:
            expanded_path = Path(path).expanduser()
            if expanded_path.exists():
                seclists_base = expanded_path
                break
        
        if not seclists_base:
            return []
            
        logger.info(f"📚 Loading fast SecLists from: {seclists_base}")
        
        # Use ALL the largest wordlists for MAXIMUM coverage  
        priority_lists = [
            "Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt",  # 1.27M entries
            "Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",  # 220K entries
            "Discovery/Web-Content/Common-DB-Backups.txt",  # Database backups
            "Discovery/Web-Content/ActiveDirectory-small.txt",  # AD specific
            "Discovery/Web-Content/AdobeXML.fuzz.txt",  # Adobe specific
        ]
        
        for wordlist_file in priority_lists:
            wordlist_path = seclists_base / wordlist_file
            if wordlist_path.exists():
                try:
                    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                        paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                        # Ensure paths start with /
                        paths = ['/' + path.lstrip('/') for path in paths if path]
                        all_paths.update(paths)
                        logger.info(f"📋 Loaded {len(paths)} paths from {wordlist_file}")
                        
                        # Keep loading ALL wordlists for maximum coverage
                        # No early break - we want EVERYTHING
                            
                except Exception as e:
                    logger.warning(f"Failed to load {wordlist_file}: {e}")
                    continue
        
        final_paths = list(all_paths)[:300000]  # Up to 300K paths for massive coverage
        logger.info(f"⚡ MASSIVE SecLists loaded: {len(final_paths)} paths for ultra-fast discovery")
        return final_paths
    
    async def _run_ffuf_fast(self, base_url: str, wordlist_paths: List[str], ffuf_bin: str) -> Set[str]:
        """Run ffuf with high concurrency and recursion for fast discovery"""
        urls = set()
        
        try:
            import tempfile
            import subprocess
            import os
            import json
            
            # Create temporary wordlist file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                for path in wordlist_paths:
                    # ffuf expects token after FUZZ; avoid leading '/'
                    token = path.lstrip('/')
                    if token:
                        f.write(token + '\n')
                temp_wordlist = f.name
            logger.info(f"🧾 ffuf wordlist prepared with {len(wordlist_paths)} entries for {base_url}")
            
            # Authentication headers (fresh from DB for this host)
            from urllib.parse import urlsplit
            host = (urlsplit(base_url).netloc or '').split(':')[0]
            auth_headers = self._build_auth_headers_for_host(host)
            headers = []
            for hk, hv in auth_headers.items():
                if hk.lower() == 'cookie':
                    headers += ["-H", f"Cookie: {hv}"]
                elif hk.lower() == 'authorization':
                    headers += ["-H", f"Authorization: {hv}"]
                else:
                    headers += ["-H", f"{hk}: {hv}"]
            
            # ffuf command for maximum speed and recursion
            cmd = [
                ffuf_bin,
                "-u", f"{base_url}/FUZZ",
                "-w", temp_wordlist,
                "-recursion",
                "-recursion-depth", "2",  # 2 levels deep
                "-mc", "200,201,202,204,301,302,307,401,403",  # Include useful codes
                "-t", "150",  # 150 threads for maximum speed
                "-timeout", "8",
                "-v",  # Verbose for better output parsing
                "-o", "/tmp/ffuf_output.json",
                "-of", "json"
            ] + headers
            
            logger.info(f"🚀 Running fast ffuf: {len(wordlist_paths)} paths, 150 threads, 2-level recursion")
            
            # Run with timeout
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,  # 3 minute timeout
                cwd="/tmp"
            )
            
            if result.returncode == 0 and os.path.exists("/tmp/ffuf_output.json"):
                with open("/tmp/ffuf_output.json", 'r') as f:
                    ffuf_data = json.load(f)
                    
                if 'results' in ffuf_data:
                    for entry in ffuf_data['results']:
                        url = entry.get('url', '')
                        status = entry.get('status', 0)
                        
                        if url and status in [200, 201, 202, 204, 301, 302, 307, 401, 403]:
                            urls.add(url)
                            logger.debug(f"✅ ffuf found: {url} [{status}]")
                
                # Cleanup
                os.remove("/tmp/ffuf_output.json")
            else:
                logger.warning(f"ffuf failed: {result.stderr}")
                
            # Cleanup wordlist
            os.unlink(temp_wordlist)
            
        except subprocess.TimeoutExpired:
            logger.warning(f"ffuf timeout on {base_url}")
        except Exception as e:
            logger.error(f"ffuf execution failed: {e}")
            
        return urls

    async def _parallel_wordlist_test(self, base_url: str, paths: List[str]) -> Set[str]:
        """Parallel async testing as ffuf fallback"""
        urls = set()
        
        try:
            # Headers for authentication
            from urllib.parse import urlsplit
            host = (urlsplit(base_url).netloc or '').split(':')[0]
            headers = self._build_auth_headers_for_host(host)
            
            timeout = aiohttp.ClientTimeout(total=5, connect=2)
            connector = aiohttp.TCPConnector(limit=100)
            
            async with aiohttp.ClientSession(headers=headers, timeout=timeout, connector=connector) as session:
                semaphore = asyncio.Semaphore(100)
                
                # Test paths in chunks
                chunk_size = 1000
                for i in range(0, len(paths), chunk_size):
                    chunk = paths[i:i + chunk_size]
                    tasks = []
                    
                    for path in chunk:
                        url = base_url.rstrip('/') + (path if path.startswith('/') else '/' + path)
                        task = self._test_url_async(session, url, semaphore)
                        tasks.append(task)
                    
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    for j, result in enumerate(results):
                        if result is True:
                            token = chunk[j]
                            found_url = base_url.rstrip('/') + (token if token.startswith('/') else '/' + token)
                            urls.add(found_url)
                    
                    logger.info(f"⚡ Parallel chunk {i//chunk_size + 1}: {sum(1 for r in results if r is True)} found")
                    
        except Exception as e:
            logger.error(f"Parallel wordlist test failed: {e}")
            
        return urls

    async def _parallel_recursive_bruteforce(self, base_url: str, all_paths: List[str], max_depth: int = 2, max_fanout: int = 5000) -> Set[str]:
        """Internal async recursive directory brute-force.

        - Starts from base_url and an initial list of candidate paths
        - Recurses into likely directories up to max_depth using pruned candidate set
        - Universal: no target-specific assumptions
        """
        discovered: Set[str] = set()
        visited: Set[str] = set()

        # Helper to decide if token looks like a directory
        def is_dir_token(token: str) -> bool:
            t = token.strip('/')
            if not t:
                return False
            # Treat tokens with an extension as files
            if '.' in t and not t.endswith('.'):
                return False
            return True

        # Level 0: probe initial paths
        initial = all_paths[:max_fanout]
        first_pass = await self._parallel_wordlist_test(base_url, initial)
        discovered.update(first_pass)

        # Build queue of directory bases to recurse into
        dir_bases: List[str] = []
        for url in list(first_pass):
            try:
                sp = urlsplit(url)
                # Keep only plausible directories
                if not sp.path or sp.path.endswith('/'):
                    dir_bases.append(f"{sp.scheme}://{sp.netloc}{sp.path.rstrip('/')}")
                else:
                    # If no extension, consider parent as directory
                    if '/' in sp.path:
                        last = sp.path.rsplit('/', 1)[-1]
                        if is_dir_token(last):
                            dir_bases.append(f"{sp.scheme}://{sp.netloc}{sp.path}")
            except Exception:
                continue

        # Next levels
        for depth in range(1, max_depth + 1):
            if not dir_bases:
                break
            next_dirs: List[str] = []
            # Prune candidates for deeper scans
            # Favor shorter, directory-like tokens to control breadth
            dir_like = [p for p in all_paths if is_dir_token(p)]
            dir_like = dir_like[: max(2000, int(max_fanout/2))]
            for base in dir_bases[:50]:
                if base in visited:
                    continue
                visited.add(base)
                # Scan a subset under this base
                results = await self._parallel_wordlist_test(base, dir_like)
                discovered.update(results)
                # Append newly found deeper directories as potential bases
                for u in list(results):
                    try:
                        sp = urlsplit(u)
                        if sp.path and (sp.path.endswith('/') or is_dir_token(sp.path.rsplit('/', 1)[-1])):
                            base_dir = f"{sp.scheme}://{sp.netloc}{sp.path.rstrip('/')}"
                            if base_dir not in visited:
                                next_dirs.append(base_dir)
                    except Exception:
                        continue
            dir_bases = next_dirs

        return discovered
    
    async def _test_url_async(self, session: aiohttp.ClientSession, url: str, semaphore: asyncio.Semaphore) -> bool:
        """Test single URL with semaphore and authentication"""
        async with semaphore:
            try:
                # Use authentication headers if available for the domain
                headers = self._build_auth_headers_for_host(urlparse(url).hostname or '')
                async with session.get(url, headers=headers, timeout=10) as resp:
                    return resp.status in [200, 201, 202, 204, 301, 302, 307, 401, 403]
            except:
                return False
    
    async def _fallback_discovery(self, domain: str) -> Set[str]:
        """Fallback discovery when SecLists are unavailable, without hardcoded paths.

        Approach: request root and robots.txt, extract same-origin links and rules,
        and probe them quickly using current auth headers.
        """
        urls: Set[str] = set()
        candidates: Set[str] = set()

        base_urls = [f"https://{domain}", f"http://{domain}"]
        timeout = aiohttp.ClientTimeout(total=6, connect=2)
        headers = self._build_auth_headers_for_host(domain)

        async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
            for base in base_urls:
                try:
                    # Root mining
                    async with session.get(base + "/", allow_redirects=True) as resp:
                        if resp.status < 400:
                            text = await resp.text()
                            for m in re.findall(r"(?:href|src)=[\"']([^\"'#>\s]+)", text, re.I):
                                try:
                                    absolute = urljoin(str(resp.url), m)
                                    if urlparse(absolute).netloc.split(':')[0] == domain:
                                        candidates.add(absolute)
                                except Exception:
                                    continue
                    # robots.txt
                    async with session.get(base + "/robots.txt", allow_redirects=True) as rbot:
                        if rbot.status < 400:
                            body = await rbot.text()
                            for line in body.splitlines():
                                s = line.strip()
                                if not s or s.startswith('#'):
                                    continue
                                if s.lower().startswith(('allow:', 'disallow:')):
                                    try:
                                        path = s.split(':', 1)[1].strip()
                                        if path:
                                            candidates.add(urljoin(base, path))
                                    except Exception:
                                        continue
                except Exception:
                    continue

        # Quick probe
        if not candidates:
            return urls

        sem = asyncio.Semaphore(100)
        async def probe(u: str) -> Optional[str]:
            async with sem:
                try:
                    async with aiohttp.ClientSession(headers=headers, timeout=timeout) as sess:
                        async with sess.get(u, allow_redirects=True) as r:
                            if r.status in [200, 201, 202, 204, 301, 302, 307, 401, 403]:
                                return str(r.url)
                except Exception:
                    return None
            return None

        tasks = [probe(u) for u in list(candidates)[:300]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, str):
                urls.add(r)
        return urls

    def _existing_urls_for_domain(self, domain: str, limit: int = 200) -> List[str]:
        """Seed discovery with existing same-domain URLs from the database (universal)."""
        seeds = []
        try:
            existing = self.asset_manager.get_existing_urls(limit=5000)  # pull more, filter down
            host_variants = {domain, f"www.{domain}"}
            for url in existing:
                try:
                    u = urlparse(url)
                    host = (u.netloc or '').split(':')[0]
                    if host in host_variants:
                        # normalize to absolute and include
                        seeds.append(url)
                        if len(seeds) >= limit:
                            break
                except Exception:
                    continue
        except Exception:
            pass
        return seeds

    async def _auth_smart_crawl(self, domain: str, max_urls: int = 250, max_depth: int = 3, extra_seeds: Optional[List[str]] = None) -> Set[str]:
        """Lightweight authenticated same-origin crawl using provided cookie."""
        urls = set()
        try:
            headers = self._build_auth_headers_for_host(domain)
            base_urls = [f"http://{domain}/", f"https://{domain}/"]
            if extra_seeds:
                base_urls.extend(extra_seeds[:100])
            seen = set()
            queue = [(u, 0) for u in base_urls]
            async with aiohttp.ClientSession(headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as session:
                while queue and len(urls) < max_urls:
                    current, depth = queue.pop(0)
                    if current in seen or depth > max_depth:
                        continue
                    seen.add(current)
                    try:
                        async with session.get(current, allow_redirects=True) as resp:
                            if resp.status >= 400:
                                continue
                            text = await resp.text()
                            # If we got a login page and have a policy, refresh cookie and retry once
                            try:
                                from urllib.parse import urlparse as _urlparse
                                host = (_urlparse(current).netloc or '').split(':')[0]
                                new_cookie = await self._refresh_cookie_if_login(host, text)
                                if new_cookie:
                                    # Rebuild session headers with new cookie
                                    headers = self._build_auth_headers_for_host(domain)
                                    async with session.get(current, allow_redirects=True, headers=headers) as r2:
                                        if r2.status >= 400:
                                            continue
                                        text = await r2.text()
                            except Exception:
                                pass
                            urls.add(str(resp.url))
                            # Extract same-origin links (very simple regex)
                            for m in re.findall(r"href=['\"][^'\"]+", text, re.I):
                                try:
                                    href = m.split('=',1)[1].strip().strip('"\'')
                                    link = urljoin(str(resp.url), href)
                                    if urlparse(link).netloc.split(':')[0] == domain and link not in seen:
                                        queue.append((link, depth + 1))
                                except Exception:
                                    continue
                    except Exception:
                        continue
        except Exception as e:
            logger.debug(f"Auth smart crawl failed: {e}")
        return urls
    
    async def _tier1_historical_discovery(self, domain: str) -> Set[str]:
        """Tier 1: Historical URL discovery using GAU and Wayback"""
        urls = set()
        
        try:
            # GAU (Get All URLs)
            logger.info(f"🔍 Running GAU on {domain}")
            gau_urls = await self._run_gau(domain)
            urls.update(gau_urls)
            
            # Wayback URLs
            logger.info(f"📚 Running Wayback on {domain}")
            wayback_urls = await self._run_wayback(domain)
            urls.update(wayback_urls)
            
            logger.info(f"✅ Historical discovery: {len(urls)} URLs")
            
        except Exception as e:
            logger.error(f"Historical discovery failed: {e}")
            
        return urls
    
    async def _run_gau(self, domain: str) -> List[str]:
        """Run GAU to get historical URLs"""
        try:
            cmd = [self.gau_path, domain, "--threads", "10", "--timeout", "30"]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                urls = []
                for line in stdout.decode().strip().split('\n'):
                    url = line.strip()
                    if url and self._is_valid_url(url):
                        urls.append(url)
                return urls[:1000]  # Limit to 1000 URLs
                
        except Exception as e:
            logger.debug(f"GAU failed: {e}")
            
        return []
    
    async def _run_wayback(self, domain: str) -> List[str]:
        """Run waybackurls to get archived URLs"""
        try:
            cmd = [self.waybackurls_path, domain]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                urls = []
                for line in stdout.decode().strip().split('\n'):
                    url = line.strip()
                    if url and self._is_valid_url(url):
                        urls.append(url)
                return urls[:1000]  # Limit to 1000 URLs
                
        except Exception as e:
            logger.debug(f"Wayback failed: {e}")
            
        return []
    
    async def _tier2_subdomain_discovery(self, domain: str) -> Set[str]:
        """Tier 2: Active subdomain discovery"""
        subdomains = set()
        
        try:
            logger.info(f"🔍 Running Subfinder on {domain}")
            
            cmd = [
                self.subfinder_path, 
                "-d", domain,
                "-silent",
                "-timeout", "30",
                "-max-time", "10"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                for line in stdout.decode().strip().split('\n'):
                    subdomain = line.strip()
                    if subdomain:
                        for protocol in ['https', 'http']:
                            url = f"{protocol}://{subdomain}"
                            if self._is_valid_url(url):
                                subdomains.add(url)
                                
        except Exception as e:
            logger.error(f"Subfinder failed: {e}")
            
        return subdomains
    
    async def _tier3_active_crawling(self, domain: str, seed_urls: List[str]) -> Set[str]:
        """Tier 3: Active crawling using Katana"""
        urls = set()
        
        try:
            if not seed_urls:
                seed_urls = [f"https://{domain}", f"http://{domain}"]
                
            # Create temporary file with seed URLs
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                for url in seed_urls[:50]:  # Increased from 20 to 50 for better coverage
                    f.write(f"{url}\n")
                seed_file = f.name
            
            logger.info(f"🕷️ Running Katana crawling on {len(seed_urls[:50])} seed URLs")
            
            cmd = [
                self.katana_path,
                "-list", seed_file,
                "-depth", "4",  # Increased depth for better discovery
                "-concurrent", "15",  # More threads for speed
                "-timeout", "45",  # Longer timeout for thorough crawling
                "-silent",
                "-no-color",
                "-js-crawl",  # Enable JavaScript crawling for SPAs
                "-headless"   # Use headless browser for better coverage
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                for line in stdout.decode().strip().split('\n'):
                    url = line.strip()
                    if url and self._is_valid_url(url):
                        urls.add(url)
            
            # Cleanup
            Path(seed_file).unlink(missing_ok=True)
            
        except Exception as e:
            logger.error(f"Katana crawling failed: {e}")
            
        return urls
    
    async def _tier4_ml_discovery(self, domain: str, existing_urls: Set[str]) -> Set[str]:
        """Tier 4: ML-powered intelligent discovery"""
        urls = set()
        
        try:
            # Analyze existing URLs for patterns
            tech_stack = self._analyze_tech_stack(existing_urls)
            logger.info(f"🧠 Detected technologies: {tech_stack}")
            
            # Generate intelligent endpoints based on detected tech
            base_urls = [f"https://{domain}", f"http://{domain}"]
            
            for parsed_domain in [urlparse(url).netloc for url in existing_urls if urlparse(url).netloc]:
                if parsed_domain not in [domain, f"www.{domain}"]:
                    base_urls.extend([f"https://{parsed_domain}", f"http://{parsed_domain}"])
            
            # Remove duplicates and limit
            base_urls = list(set(base_urls))[:10]
            
            for base_url in base_urls:
                # Common endpoints
                for endpoint in self.ml_patterns["common_endpoints"]:
                    url = urljoin(base_url, endpoint)
                    urls.add(url)
                
                # Technology-specific endpoints
                for tech in tech_stack:
                    if tech.lower() in self.ml_patterns["tech_specific"]:
                        for endpoint in self.ml_patterns["tech_specific"][tech.lower()]:
                            url = urljoin(base_url, endpoint)
                            urls.add(url)
                
                # Sensitive files
                for sensitive in self.ml_patterns["sensitive_files"]:
                    url = urljoin(base_url, sensitive)
                    urls.add(url)
            
            logger.info(f"🧠 ML Discovery generated {len(urls)} intelligent URLs")
            
        except Exception as e:
            logger.error(f"ML discovery failed: {e}")
            
        return urls
    
    async def _tier5_port_service_discovery(self, domain: str) -> Set[str]:
        """Tier 5: Port scanning and service discovery"""
        urls = set()
        
        try:
            logger.info(f"🛡️ Running RustScan + Nmap on {domain}")
            
            # RustScan for fast port discovery
            open_ports = await self._run_rustscan(domain)
            
            if open_ports:
                # Nmap service detection on open ports
                services = await self._run_nmap_services(domain, open_ports)
                
                # Convert services to URLs
                for port, service_info in services.items():
                    if 'http' in service_info.lower():
                        protocol = 'https' if 'ssl' in service_info.lower() or port == 443 else 'http'
                        url = f"{protocol}://{domain}:{port}"
                        urls.add(url)
            
        except Exception as e:
            logger.error(f"Port scanning failed: {e}")
            
        return urls
    
    async def _run_rustscan(self, domain: str) -> List[int]:
        """Run RustScan for fast port discovery"""
        try:
            cmd = [
                self.rustscan_path,
                "-a", domain,
                "--timeout", "3000",
                "--tries", "1",
                "--batch-size", "5000",
                "-g"  # Greppable output
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                ports = []
                for line in stdout.decode().strip().split('\n'):
                    # Parse RustScan output for open ports
                    match = re.search(r'(\d+)/tcp', line)
                    if match:
                        ports.append(int(match.group(1)))
                return ports[:50]  # Limit to 50 ports
                
        except Exception as e:
            logger.debug(f"RustScan failed: {e}")
            
        return []
    
    async def _run_nmap_services(self, domain: str, ports: List[int]) -> Dict[int, str]:
        """Run Nmap service detection on open ports"""
        services = {}
        
        try:
            if not ports:
                return services
                
            port_list = ','.join(map(str, ports))
            
            cmd = [
                self.nmap_path,
                "-sV",  # Service version detection
                "-p", port_list,
                "--version-intensity", "5",
                "--max-rtt-timeout", "3s",
                "--max-retries", "1",
                domain
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                for line in stdout.decode().split('\n'):
                    # Parse Nmap service output
                    match = re.search(r'(\d+)/tcp\s+open\s+(.+)', line)
                    if match:
                        port = int(match.group(1))
                        service_info = match.group(2)
                        services[port] = service_info
                        
        except Exception as e:
            logger.debug(f"Nmap service detection failed: {e}")
            
        return services
    
    def _analyze_tech_stack(self, urls: Set[str]) -> List[str]:
        """Analyze URLs to detect technology stack"""
        technologies = set()
        
        for url in urls:
            url_lower = url.lower()
            
            # File extension analysis
            if '.php' in url_lower:
                technologies.add('php')
            if '.asp' in url_lower or '.aspx' in url_lower:
                technologies.add('asp.net')
            if '.jsp' in url_lower:
                technologies.add('java')
            if '/wp-' in url_lower or 'wordpress' in url_lower:
                technologies.add('wordpress')
            if '/admin' in url_lower:
                technologies.add('admin')
            if '/api' in url_lower:
                technologies.add('api')
            if 'node' in url_lower or 'npm' in url_lower:
                technologies.add('nodejs')
            if 'python' in url_lower or 'django' in url_lower or 'flask' in url_lower:
                technologies.add('python')
                
        return list(technologies)
    
    def _is_valid_url(self, url: str) -> bool:
        """Validate if URL is worth discovering"""
        if not url or len(url) > 500:
            return False
            
        # Skip common file types that aren't useful
        skip_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico', '.svg', '.woff', '.ttf', '.eot']
        url_lower = url.lower()
        
        if any(url_lower.endswith(ext) for ext in skip_extensions):
            return False
            
        # Must be HTTP/HTTPS
        if not (url.startswith('http://') or url.startswith('https://')):
            return False
            
        return True
    
    async def _tier6_intelligent_directory_discovery(self, domain: str, existing_urls: Set[str]) -> Set[str]:
        """Tier 6: Intelligent directory discovery using smart SecLists selection"""
        urls = set()
        
        try:
            logger.info(f"📁 INTELLIGENT DIRECTORY DISCOVERY: {domain}")
            
            # Analyze existing URLs to understand the target
            tech_stack = self._analyze_tech_stack(existing_urls)
            url_patterns = self._analyze_url_patterns(existing_urls)
            
            # Get live base URLs to test against
            base_urls = self._get_live_base_urls(existing_urls, domain)
            
            if not base_urls:
                logger.debug("No live base URLs found for directory discovery")
                return urls
            
            # AI-assisted SecLists selection based on technology and patterns  
            wordlists = await self._ai_select_intelligent_wordlists(tech_stack, url_patterns, domain)
            
            logger.info(f"🧠 Selected {len(wordlists)} intelligent wordlists for {tech_stack}")
            
            # PARALLEL SCANNING: Break up wordlists and run multiple scanners simultaneously
            parallel_tasks = []
            for base_url in base_urls[:15]:  # Increased to 15 base URLs for more parallelism
                for wordlist_name, paths in wordlists.items():
                    logger.info(f"🔍 Setting up parallel scanning for {wordlist_name} on {base_url} ({len(paths)} paths)")
                    
                    # Break large wordlists into chunks for parallel processing
                    chunk_size = 200  # Smaller chunks = more parallelism
                    path_chunks = [paths[i:i + chunk_size] for i in range(0, len(paths), chunk_size)]
                    
                    logger.info(f"🚀 PARALLEL: Breaking {wordlist_name} into {len(path_chunks)} chunks of {chunk_size} paths each")
                    
                    # Create parallel tasks for each chunk  
                    for chunk_num, path_chunk in enumerate(path_chunks[:30]):  # Increased to 30 chunks per wordlist (6000 paths max)
                        task = self._parallel_test_paths_chunk(base_url, path_chunk, f"{wordlist_name}_chunk_{chunk_num}")
                        parallel_tasks.append(task)
            
            # Execute all parallel scanning tasks simultaneously
            if parallel_tasks:
                logger.info(f"🚀 LAUNCHING {len(parallel_tasks)} PARALLEL DISCOVERY TASKS")
                results = await asyncio.gather(*parallel_tasks, return_exceptions=True)
                
                # Collect all discovered paths from parallel results
                total_discovered = 0
                for result in results:
                    if isinstance(result, list):
                        for discovered_url in result:
                            if self._is_valid_url(discovered_url):
                                urls.add(discovered_url)
                                total_discovered += 1
                    elif isinstance(result, Exception):
                        logger.warning(f"Parallel discovery task failed: {result}")
                
                logger.info(f"🎯 PARALLEL DISCOVERY COMPLETE: Found {total_discovered} new URLs from {len(parallel_tasks)} parallel tasks")
            
            logger.info(f"📁 INTELLIGENT DIRECTORY COMPLETE: {len(urls)} new directories found")
            
            # CRITICAL: Add ffuf recursive discovery for proper directory enumeration
            ffuf_urls = await self._run_ffuf_recursive_discovery(base_urls, wordlists)
            urls.update(ffuf_urls)
            logger.info(f"🔁 Ffuf Recursive: {len(ffuf_urls)} additional URLs discovered")
            
        except Exception as e:
            logger.error(f"Intelligent directory discovery failed: {e}")
            
        return urls
    
    async def _tier7_universal_comprehensive_discovery(self, domain: str, existing_urls: Set[str]) -> Set[str]:
        """Tier 7: UNIVERSAL comprehensive path discovery for ANY target type"""
        urls = set()
        
        try:
            logger.info(f"🎯 UNIVERSAL COMPREHENSIVE DISCOVERY: {domain}")
            
            # Analyze existing URLs to detect application types automatically
            app_patterns = self._detect_application_patterns(existing_urls, domain)
            logger.info(f"🔍 Detected application patterns: {list(app_patterns.keys())}")
            
            # Get base URLs from existing discoveries
            base_urls = []
            for url in existing_urls:
                parsed = urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                if base_url not in base_urls:
                    base_urls.append(base_url)
            
            # Add default base URLs if none found
            if not base_urls:
                base_urls = [f"http://{domain}", f"https://{domain}"]
            
            # UNIVERSAL path testing - works for ANY application
            universal_paths = await self._generate_universal_paths(app_patterns, domain)
            
            # Test all paths in parallel
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                tasks = []
                for base_url in base_urls[:5]:  # Limit to 5 base URLs
                    for path in universal_paths:
                        test_url = urljoin(base_url, path)
                        task = self._test_universal_path(session, test_url)
                        tasks.append(task)
                
                logger.info(f"🚀 Testing {len(tasks)} universal paths in parallel")
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in results:
                    if isinstance(result, str):  # Valid URL returned
                        urls.add(result)
            
            logger.info(f"🎯 UNIVERSAL DISCOVERY: Found {len(urls)} additional paths")
            
        except Exception as e:
            logger.error(f"Universal comprehensive discovery failed: {e}")
        
        return urls
    
    def _detect_application_patterns(self, urls: Set[str], domain: str) -> Dict[str, bool]:
        """Automatically detect what type of applications are running"""
        patterns = {
            'php_app': False,
            'wordpress': False, 
            'drupal': False,
            'api_endpoints': False,
            'admin_panels': False,
            'cms_system': False,
            'ecommerce': False,
            'web_framework': False
        }
        
        # Check existing URLs and domain for application indicators
        url_text = ' '.join(urls).lower() + domain.lower()
        
        # PHP detection
        if '.php' in url_text or 'php' in url_text:
            patterns['php_app'] = True
            
        # WordPress detection
        if any(wp in url_text for wp in ['/wp-', 'wordpress', '/wp/', 'wp-content', 'wp-admin']):
            patterns['wordpress'] = True
            
        # Drupal detection  
        if any(dr in url_text for dr in ['drupal', '/node/', '/user/', '/admin/config']):
            patterns['drupal'] = True
            
        # API detection
        if any(api in url_text for api in ['/api/', '/rest/', '/graphql', '/v1/', '/v2/']):
            patterns['api_endpoints'] = True
            
        # Admin panel detection
        if any(admin in url_text for admin in ['/admin', '/panel', '/dashboard', '/manage']):
            patterns['admin_panels'] = True
            
        return patterns
    
    async def _generate_universal_paths(self, app_patterns: Dict[str, bool], domain: str) -> List[str]:
        """Generate candidate paths using SecLists intelligently (no hardcoded paths)."""
        try:
            from .seclists_manager import SecListsManager
            slm = SecListsManager(self.asset_manager, {})
            await slm.initialize()
            target_info = {
                'domain': domain,
                'technologies': []
            }
            words = []
            words.extend(slm.get_intelligent_wordlist(target_info, 'directories', limit=1500))
            words.extend(slm.get_intelligent_wordlist(target_info, 'files', limit=800))
            words.extend(slm.get_intelligent_wordlist(target_info, 'admin_paths', limit=400))
            words.extend(slm.get_intelligent_wordlist(target_info, 'api_endpoints', limit=400))
            # Normalize
            norm = []
            for w in words:
                w = (w or '').strip()
                if not w:
                    continue
                if not w.startswith('/'):
                    w = '/' + w
                if '..' in w:
                    continue
                norm.append(w)
            # Dedupe and cap
            norm = list(dict.fromkeys(norm))[:4000]
            return norm
        except Exception:
            return []
    
    async def _test_universal_path(self, session: aiohttp.ClientSession, url: str) -> str:
        """Test if a universal path is accessible"""
        try:
            async with session.get(url) as response:
                if response.status in [200, 301, 302, 403, 401]:
                    return url
        except:
            pass
        return None
    
    def _analyze_url_patterns(self, urls: Set[str]) -> Dict[str, int]:
        """Analyze URL patterns to understand the application structure"""
        patterns = {
            'api_endpoints': 0,
            'admin_paths': 0,
            'cms_paths': 0,
            'file_extensions': {},
            'path_depth': 0,
            'common_words': {}
        }
        
        for url in list(urls)[:100]:  # Analyze first 100 URLs
            parsed = urlparse(url)
            path = parsed.path.lower()
            
            # Count API patterns
            if '/api/' in path or path.startswith('/api'):
                patterns['api_endpoints'] += 1
                
            # Count admin patterns  
            if any(admin in path for admin in ['/admin', '/dashboard', '/panel', '/manage']):
                patterns['admin_paths'] += 1
                
            # Count CMS patterns
            if any(cms in path for cms in ['/wp-', '/drupal', '/joomla', '/content']):
                patterns['cms_paths'] += 1
                
            # Analyze path depth
            depth = len([p for p in path.split('/') if p])
            patterns['path_depth'] = max(patterns['path_depth'], depth)
            
            # Extract file extensions
            if '.' in path:
                ext = path.split('.')[-1]
                if len(ext) <= 5:  # Valid extension length
                    patterns['file_extensions'][ext] = patterns['file_extensions'].get(ext, 0) + 1
        
        return patterns
    
    def _get_live_base_urls(self, existing_urls: Set[str], domain: str) -> List[str]:
        """Get confirmed live base URLs for directory testing INCLUDING discovered directories for recursive scanning"""
        base_urls = set()
        
        # Add domain variants
        base_urls.add(f"https://{domain}")
        base_urls.add(f"http://{domain}")
        base_urls.add(f"https://www.{domain}")
        
        # RECURSIVE DISCOVERY: Extract directory paths from existing URLs for recursive testing
        for url in existing_urls:
            parsed = urlparse(url)
            if parsed.netloc:
                # Add domain-level base URL
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                base_urls.add(base_url)
                
                # CRITICAL: Add directory paths for recursive discovery
                path_parts = [p for p in parsed.path.split('/') if p]
                current_path = ""
                for i, part in enumerate(path_parts):
                    current_path += "/" + part
                    directory_url = f"{parsed.scheme}://{parsed.netloc}{current_path}"
                    
                    # Add directory paths (not final files)
                    # If this is the last part and it's a file, add the parent directory instead
                    if i == len(path_parts) - 1 and part.endswith(('.php', '.html', '.asp', '.jsp', '.py', '.js', '.css', '.json', '.xml')):
                        # This is a file - add its parent directory 
                        parent_path = current_path.rsplit('/', 1)[0] if '/' in current_path else ""
                        if parent_path:
                            parent_url = f"{parsed.scheme}://{parsed.netloc}{parent_path}"
                            base_urls.add(parent_url)
                            logger.debug(f"🔁 RECURSIVE: Added parent directory {parent_url} from file {directory_url}")
                    else:
                        # This is a directory
                        base_urls.add(directory_url)
                        logger.debug(f"🔁 RECURSIVE: Added directory base URL {directory_url}")
                
        return list(base_urls)[:20]  # Increased to 20 to accommodate recursive directories

    async def _run_ffuf_recursive_discovery(self, base_urls: List[str], wordlists: Dict[str, List[str]]) -> Set[str]:
        """Run ffuf with recursion for proper directory enumeration"""
        urls = set()
        
        try:
            import tempfile
            import subprocess
            import os
            
            ffuf_bin = self._find_binary('ffuf', config_key='ffuf_path', env_key='FFUF_PATH')
            if not ffuf_bin:
                logger.debug("ffuf not found; skipping external recursive ffuf and falling back to internal")
                # Fall back to internal recursive if binary missing
                combined: List[str] = []
                for _, paths in (wordlists or {}).items():
                    combined.extend(paths)
                for base in base_urls[:5]:
                    urls.update(await self._parallel_recursive_bruteforce(base, combined, max_depth=3))
                return urls

            # Create temporary wordlist file combining all intelligent wordlists
            all_paths = set()
            for wordlist_name, paths in wordlists.items():
                all_paths.update(paths)
            
            if not all_paths:
                logger.debug("No wordlists available for ffuf recursion")
                return urls
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_wordlist:
                for path in sorted(all_paths):
                    # Ensure paths start with /
                    token = path.lstrip('/')
                    if token:
                        temp_wordlist.write(token + '\n')
                temp_wordlist_path = temp_wordlist.name
            
            try:
                # Run ffuf with recursion for each base URL
                for base_url in base_urls[:5]:  # Limit to 5 base URLs to avoid too much noise
                    logger.info(f"🔁 Running ffuf recursive discovery on {base_url}")
                    
                    # ffuf command with recursion
                    cmd = [
                        ffuf_bin,
                        "-u", f"{base_url}/FUZZ",
                        "-w", temp_wordlist_path,
                        "-recursion",
                        "-recursion-depth", "3",  # Max 3 levels deep
                        "-recursion-strategy", "greedy",  # Recurse on all matches
                        "-mc", "200,204,301,302,307,403,401",  # Include useful status codes
                        "-t", "100",  # 100 threads for speed
                        "-timeout", "10",
                        "-silent",  # Reduce noise
                        "-o", "/tmp/ffuf_output.json",
                        "-of", "json"
                    ]
                    
                    logger.debug(f"Running ffuf command: {' '.join(cmd)}")
                    
                    # Run ffuf with timeout
                    try:
                        result = subprocess.run(
                            cmd,
                            capture_output=True,
                            text=True,
                            timeout=300,  # 5 minute timeout
                            cwd="/tmp"
                        )
                        
                        if result.returncode == 0:
                            # Parse ffuf JSON output
                            try:
                                if os.path.exists("/tmp/ffuf_output.json"):
                                    with open("/tmp/ffuf_output.json", 'r') as f:
                                        import json
                                        ffuf_data = json.load(f)
                                        
                                    if 'results' in ffuf_data:
                                        for result_entry in ffuf_data['results']:
                                            discovered_url = result_entry.get('url', '')
                                            status = result_entry.get('status', 0)
                                            
                                            if discovered_url and status in [200, 301, 302, 403, 401]:
                                                urls.add(discovered_url)
                                                logger.debug(f"🔁 ffuf discovered: {discovered_url} ({status})")
                                    
                                    # Clean up output file
                                    os.remove("/tmp/ffuf_output.json")
                                    
                            except (json.JSONDecodeError, FileNotFoundError) as e:
                                logger.debug(f"ffuf JSON parsing error: {e}")
                        else:
                            logger.debug(f"ffuf failed with return code {result.returncode}: {result.stderr}")
                            
                    except subprocess.TimeoutExpired:
                        logger.warning(f"ffuf timeout on {base_url}")
                    except Exception as e:
                        logger.debug(f"ffuf execution error: {e}")
                        
            finally:
                # Clean up temporary wordlist
                try:
                    os.unlink(temp_wordlist_path)
                except:
                    pass
                    
        except Exception as e:
            logger.error(f"ffuf recursive discovery failed: {e}")
            
        return urls
    
    def _select_intelligent_wordlists(self, tech_stack: List[str], url_patterns: Dict) -> Dict[str, List[str]]:
        """Select SecLists wordlists based on technology and observed patterns (no hardcoded paths).

        Returns a dict of category -> list(paths) where each list originates from SecLists.
        """
        selected: Dict[str, List[str]] = {}
        seclists_paths = self._load_seclists_wordlists()

        # Always include core SecLists categories when available
        for cat in ('directories', 'files', 'admin_paths', 'api_endpoints'):
            if cat in seclists_paths:
                selected[cat] = seclists_paths[cat]

        # Optionally refine by tech_stack: keep it category-level only (no custom path strings)
        # This keeps selection universal and backed entirely by SecLists content.
        return selected
    
    async def _ai_select_intelligent_wordlists(self, tech_stack: List[str], url_patterns: Dict, domain: str) -> Dict[str, List[str]]:
        """Use AI to intelligently select the best wordlists for the target"""
        
        # Load ALL available SecLists wordlists for AI to analyze
        all_available_wordlists = self._load_all_seclists_wordlists()
        
        # Use AI to select the best wordlists from available options
        selected_wordlists = {}
        try:
            if hasattr(self, 'config') and 'gemini_api_key' in self.config and all_available_wordlists:
                ai_selected = await self._gemini_select_wordlists(domain, tech_stack, url_patterns, all_available_wordlists)
                if ai_selected:
                    selected_wordlists.update(ai_selected)
        except Exception as e:
            logger.debug(f"AI wordlist selection failed, using all available: {e}")
        
        # If AI selection failed, use all available wordlists
        if not selected_wordlists and all_available_wordlists:
            logger.info("🔄 AI selection failed, using all available SecLists")
            for category, data in all_available_wordlists.items():
                selected_wordlists[category] = data['paths']
        
        # Final fallback to rule-based selection
        if not selected_wordlists:
            logger.warning("⚠️ No SecLists found, using fallback wordlists")
            return self._select_intelligent_wordlists(tech_stack, url_patterns)
            
        return selected_wordlists
    
    async def _gemini_select_wordlists(self, domain: str, tech_stack: List[str], url_patterns: Dict, available_wordlists: Dict) -> Dict[str, List[str]]:
        """Use Gemini AI to select the best wordlists from all available options"""
        import aiohttp
        import json
        
        try:
            # Create summary of available wordlists for AI
            wordlist_summary = {}
            for category, data in available_wordlists.items():
                wordlist_summary[category] = {
                    'name': data['name'],
                    'count': data['count'], 
                    'description': data['description'],
                    'sample_paths': data['paths'][:10]  # Show first 10 paths as examples
                }
            
            prompt = f"""
You are a penetration testing expert analyzing target: {domain}

Technology stack detected: {tech_stack}
URL patterns observed: {url_patterns}

Available SecLists wordlist categories:
{json.dumps(wordlist_summary, indent=2)}

Select the 2-3 most effective wordlist categories for this target.
Consider:
- For IP targets: prioritize 'directories' and 'admin'
- For PHP apps: prioritize 'directories', 'admin', 'files'
- For API endpoints: select 'api' category
- For CMS sites: choose 'cms' category

Return JSON with "selected_categories" array containing the category names to use.
Example: {{"selected_categories": ["directories", "admin", "files"]}}
"""

            headers = {'Content-Type': 'application/json'}
            data = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.2,
                    "maxOutputTokens": 512
                }
            }
            
            api_key = self.config.get('gemini_api_key')
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=headers, json=data) as response:
                    if response.status == 200:
                        result = await response.json()
                        ai_text = result['candidates'][0]['content']['parts'][0]['text']
                        
                        # Extract JSON from response
                        import re
                        json_match = re.search(r'\{.*\}', ai_text, re.DOTALL)
                        if json_match:
                            ai_data = json.loads(json_match.group())
                            if 'selected_categories' in ai_data:
                                selected_categories = ai_data['selected_categories']
                                logger.info(f"🤖 AI selected {len(selected_categories)} wordlist categories: {selected_categories}")
                                
                                # Return the selected wordlists
                                selected_wordlists = {}
                                for category in selected_categories:
                                    if category in available_wordlists:
                                        selected_wordlists[category] = available_wordlists[category]['paths']
                                        logger.info(f"📋 Using {category}: {len(available_wordlists[category]['paths'])} paths")
                                
                                return selected_wordlists
                                
        except Exception as e:
            logger.debug(f"Gemini wordlist selection failed: {e}")
            
        return {}
    
    async def _gemini_recommend_wordlists(self, domain: str, tech_stack: List[str], url_patterns: Dict) -> Dict[str, List[str]]:
        """Use Gemini AI to recommend targeted wordlists"""
        import aiohttp
        import json
        
        try:
            prompt = f"""
You are a penetration testing expert analyzing target: {domain}

Technology stack detected: {tech_stack}
URL patterns observed: {url_patterns}

For this target, recommend the most effective directory/file paths to test for discovery.
Focus on paths that are likely to exist based on the technology stack and domain.

For PHP applications, include common admin and configuration paths such as:
/admin/, /login/, /phpmyadmin/, /config.php, /setup.php

Return as JSON with key "paths" containing array of paths to test.
Limit to 100 most promising paths.
Ensure all paths start with /

Example: {{"paths": ["/admin", "/api", "/login", "/config"]}}
"""

            headers = {'Content-Type': 'application/json'}
            data = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.3,
                    "maxOutputTokens": 1024
                }
            }
            
            api_key = self.config.get('gemini_api_key')
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=headers, json=data) as response:
                    if response.status == 200:
                        result = await response.json()
                        ai_text = result['candidates'][0]['content']['parts'][0]['text']
                        
                        # Extract JSON from response
                        import re
                        json_match = re.search(r'\{.*\}', ai_text, re.DOTALL)
                        if json_match:
                            ai_data = json.loads(json_match.group())
                            if 'paths' in ai_data:
                                logger.info(f"🤖 AI recommended {len(ai_data['paths'])} targeted paths")
                                return {'ai_recommended': ai_data['paths']}
                                
        except Exception as e:
            logger.debug(f"Gemini wordlist recommendation failed: {e}")
            
        return {}
    
    def _load_all_seclists_wordlists(self) -> Dict[str, Dict[str, List[str]]]:
        """Load ALL available SecLists wordlists for AI to choose from"""
        import os
        from pathlib import Path
        
        all_wordlists = {}
        
        # Try to find SecLists directory
        seclists_base = None
        possible_paths = [
            "/home/michael/SecLists",  # CORRECT path for this system
            "./SecLists",
            "/usr/share/seclists",
            "/opt/seclists", 
            "../SecLists",
            "~/tools/SecLists"
        ]
        
        for path in possible_paths:
            expanded_path = Path(path).expanduser()
            if expanded_path.exists():
                seclists_base = expanded_path
                break
        
        if not seclists_base:
            logger.warning("SecLists not found, using fallback wordlists")
            return all_wordlists
            
        logger.info(f"📚 Loading ALL SecLists from: {seclists_base}")
        
        # Define all available wordlist categories with their files
        wordlist_categories = {
            'directories': [
                "Discovery/Web-Content/raft-small-directories.txt",
                "Discovery/Web-Content/raft-medium-directories.txt", 
                "Discovery/Web-Content/raft-large-directories.txt",
                "Discovery/Web-Content/raft-large-directories-lowercase.txt",  # Add lowercase for full coverage
                "Discovery/Web-Content/directory-list-lowercase-2.3-big.txt",  # Comprehensive directory list
                "Discovery/Web-Content/common.txt",
                "Discovery/Web-Content/quickhits.txt",
                "Discovery/Web-Content/big.txt"
            ],
            'files': [
                "Discovery/Web-Content/raft-small-files.txt",
                "Discovery/Web-Content/raft-medium-files.txt",
                "Discovery/Web-Content/raft-large-files.txt",
                "Discovery/Web-Content/common.txt"
            ],
            'api': [
                "Discovery/Web-Content/common-api-endpoints-mazen160.txt",
                "Discovery/Web-Content/api/api-endpoints.txt"
            ],
            'admin': [
                "Discovery/Web-Content/Logins.fuzz.txt",
                "Discovery/Web-Content/AdobeCQ-AEM.txt" 
            ],
            'cms': [
                "Discovery/Web-Content/CMS/drupal.txt",
                "Discovery/Web-Content/CMS/wordpress.txt",
                "Discovery/Web-Content/CMS/joomla.txt"
            ],
            'tech_specific': [
                "Discovery/Web-Content/spring-boot.txt",
                "Discovery/Web-Content/tomcat.txt",
                "Discovery/Web-Content/nginx.txt",
                "Discovery/Web-Content/apache.txt"
            ]
        }
        
        # Load each category
        for category, file_list in wordlist_categories.items():
            category_paths = []
            for file_path in file_list:
                full_path = seclists_base / file_path
                if full_path.exists():
                    try:
                        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                            paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                            category_paths.extend(paths)
                            logger.debug(f"📋 Loaded {len(paths)} paths from {file_path}")
                    except Exception as e:
                        logger.warning(f"Failed to load {file_path}: {e}")
            
            if category_paths:
                # Ensure paths start with /
                category_paths = ['/' + path.lstrip('/') for path in category_paths]
                # Remove duplicates and limit for performance
                category_paths = list(dict.fromkeys(category_paths))[:2000]
                all_wordlists[category] = {
                    'name': category,
                    'paths': category_paths,
                    'count': len(category_paths),
                    'description': f"SecLists {category} wordlist"
                }
                logger.info(f"🎯 {category}: {len(category_paths)} unique paths")
        
        logger.info(f"📚 Total wordlist categories available: {len(all_wordlists)}")
        return all_wordlists
    
    def _load_seclists_wordlists(self) -> Dict[str, List[str]]:
        """Load basic SecLists wordlists (fallback method)"""
        all_lists = self._load_all_seclists_wordlists()
        
        # Convert to simple format
        simple_wordlists = {}
        for category, data in all_lists.items():
            simple_wordlists[category] = data['paths']
            
        return simple_wordlists
    
    async def _parallel_test_paths_chunk(self, base_url: str, path_chunk: List[str], chunk_name: str) -> List[str]:
        """Test a chunk of paths in parallel for massive speed"""
        discovered_urls = []
        
        try:
            logger.info(f"🚀 PARALLEL CHUNK {chunk_name}: Testing {len(path_chunk)} paths on {base_url}")
            
            # Create all full URLs for this chunk
            test_urls = []
            for path in path_chunk:
                if not path.startswith('/'):
                    path = '/' + path
                full_url = base_url.rstrip('/') + path
                test_urls.append(full_url)
            
            # Use proxy manager for external targets, direct connection for local targets
            is_local_target = any(local in base_url for local in ['192.168.', '10.', '172.16.', '127.0.0.1', 'localhost'])
            
            if is_local_target:
                # Local target - use direct connection (no proxy needed)
                logger.debug(f"🏠 {chunk_name}: Using direct connection for local target")
                connector = aiohttp.TCPConnector(limit=100, limit_per_host=50)
                timeout = aiohttp.ClientTimeout(total=10, connect=5)
                session = aiohttp.ClientSession(connector=connector, timeout=timeout)
            else:
                # External target - use proxy manager
                logger.debug(f"🌐 {chunk_name}: Using proxy rotation for external target")
                # Get proxy manager session (assuming it exists in the class)
                if hasattr(self, 'proxy_manager') and self.proxy_manager:
                    session = await self.proxy_manager.get_session()
                else:
                    # Fallback to direct connection if no proxy manager
                    logger.warning(f"⚠️ No proxy manager available for external target {base_url}")
                    connector = aiohttp.TCPConnector(limit=50, limit_per_host=25)  # Lower limits for external
                    timeout = aiohttp.ClientTimeout(total=15, connect=10)  # Longer timeouts for external
                    session = aiohttp.ClientSession(connector=connector, timeout=timeout)
            
            async with session:
                # Create semaphore for controlled concurrency within chunk
                semaphore = asyncio.Semaphore(100)  # 100 concurrent requests per chunk
                
                # Test all URLs in this chunk simultaneously
                tasks = [self._test_single_url_parallel(session, url, semaphore) for url in test_urls]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Collect successful discoveries
                for i, result in enumerate(results):
                    if result is True:  # URL responded positively
                        discovered_urls.append(test_urls[i])
                        logger.debug(f"✅ {chunk_name}: Found {test_urls[i]}")
                    elif isinstance(result, Exception):
                        logger.debug(f"❌ {chunk_name}: Error testing {test_urls[i]}: {result}")
            
            logger.info(f"🎯 CHUNK {chunk_name} COMPLETE: {len(discovered_urls)}/{len(path_chunk)} paths found")
            return discovered_urls
            
        except Exception as e:
            logger.error(f"Parallel chunk {chunk_name} failed: {e}")
            return discovered_urls
    
    async def _test_single_url_parallel(self, session: aiohttp.ClientSession, url: str, semaphore: asyncio.Semaphore) -> bool:
        """Test a single URL in parallel with semaphore control"""
        async with semaphore:
            try:
                async with session.get(url) as response:
                    # Consider 200, 301, 302, 403 as positive discoveries
                    if response.status in [200, 301, 302, 403, 401]:
                        return True
                    return False
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return False
    
    async def _test_paths_with_httpx(self, base_url: str, paths: List[str]) -> List[str]:
        """Use HTTPx to quickly test multiple paths"""
        discovered = []
        
        try:
            # Create temporary file with full URLs
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                for path in paths:
                    full_url = urljoin(base_url, path)
                    f.write(f"{full_url}\n")
                url_file = f.name
            
            # Run HTTPx to test all URLs
            cmd = [
                "httpx",
                "-l", url_file,
                "-status-code",
                "-silent",
                "-timeout", "5",
                "-threads", "10",
                "-mc", "200,403,401,302",  # Match these status codes
                "-no-color"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                for line in stdout.decode().strip().split('\n'):
                    if line.strip() and '[' in line:  # HTTPx output format
                        # Extract URL from HTTPx output: "https://example.com/path [200]"
                        url = line.split(' [')[0].strip()
                        if url.startswith(base_url):
                            path = url.replace(base_url, '')
                            if path and path != '/':
                                discovered.append(path)
            
            # Cleanup
            Path(url_file).unlink(missing_ok=True)
            
        except Exception as e:
            logger.debug(f"HTTPx path testing failed: {e}")
            
        return discovered
