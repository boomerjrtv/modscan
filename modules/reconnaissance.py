#!/usr/bin/env python3
"""
Reconnaissance Engine Module - Advanced reconnaissance capabilities with AssetManager
"""

import asyncio
import aiohttp
import logging
import socket
import json
import re
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger("ReconnaissanceEngine")

class ReconnaissanceEngine:
    # --- hardening helpers (idempotent) ---
    
    def _dedupe_list(self, items):
        out = []
        seen = getattr(self, '_local_seen', set())
        setattr(self, '_local_seen', seen)
        gate = getattr(self, '_global_should_scan', None)
        normalizer = getattr(self, '_global_normalize', None)
        for it in (items or []):
            key_raw = str(it)
            if callable(normalizer):
                try:
                    key = normalizer(key_raw)
                except Exception:
                    key = key_raw
            else:
                key = key_raw
            try:
                if callable(gate) and not gate(key):
                    continue
            except Exception:
                pass
            if key in seen:
                continue
            seen.add(key)
            out.append(key)
        return out
    def _batch_size(self, default=200):
        # Choose a safe bounded batch size; prefer config if present
        bs = default
        try:
            cfg = getattr(self, 'config', None)
            if isinstance(cfg, dict):
                bs = int(cfg.get('bounded_batch', bs))
        except Exception:
            pass
        # clamp sensibly
        return max(50, min(800, int(bs)))

    async def _persist_discoveries_to_assets(self, discoveries: dict, session: aiohttp.ClientSession):
        """Insert discovered subdomains (Tier-4) as assets so they appear in dashboard and get scanned."""
        if not discoveries:
            return 0
        subs = set(discoveries.get("subdomains") or [])
        inserted = 0

        async def worker(host):
            nonlocal inserted
            url = f"https://{host.strip().lstrip('.')}/"
            import time
            from datetime import datetime
            import json
            start = time.time()
            ok = False; status=None; headers={}; body=""; rt_ms=None; title=None
            content_length = 0; tech_stack = []; redirect_url = None
            
            proxy = await self._get_proxy()
            try:
                async with self.semaphore:
                    methods_to_try = ['GET', 'HEAD']
                    
                    for method in methods_to_try:
                        try:
                            if method == 'GET':
                                async with session.get(url, timeout=15, allow_redirects=True, proxy=proxy) as r:
                                    status = r.status
                                    headers = dict(r.headers)
                                    # Read body first, then calculate content length
                                    body_bytes = await r.read()
                                    content_length = len(body_bytes)

                                    try:
                                        body = body_bytes.decode('utf-8', errors="ignore")
                                    except Exception:
                                        body = ""
                                    
                                    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I|re.S)
                                    title = re.sub(r"\s+", " ",m.group(1)).strip()[:255] if m else None
                                    
                                    tech_stack = self._detect_technologies_quick(headers, body)
                                    
                                    if str(r.url) != url:
                                        redirect_url = str(r.url)
                                    
                                    ok = True
                                    break
                                    
                            elif method == 'HEAD' and not ok:
                                async with session.head(url, timeout=10, allow_redirects=True, proxy=proxy) as r:
                                    status = r.status
                                    headers = dict(r.headers)
                                    content_length = int(headers.get('content-length', 0))
                                    ok = True
                                    break
                                    
                        except Exception as method_error:
                            continue
                            
            except Exception as _e:
                ok = False
            finally:
                rt_ms = int((time.time() - start) * 1000)

            # Only add assets that have confirmed HTTP responses with valid status codes
            if ok and status is not None and isinstance(status, int) and 100 <= status <= 599:
                try:
                    query, values = self.asset_manager.build_asset_insert_query(
                        url=url,
                        host=host,
                        status_code=status,
                        title=title,
                        tech_stack=', '.join(tech_stack),
                        content_length=content_length,
                        response_time=rt_ms,
                        discovery_method="tier4_advanced",
                        last_scanned=datetime.now().isoformat()
                    )
                    import sqlite3
                    with self.asset_manager._get_db() as db:
                        db.execute(query, values)
                        db.commit()
                        inserted += 1
                except Exception as e:
                    logger.debug(f"persist skip {url}: {e}")

        await asyncio.gather(*(worker(host) for host in subs))
        return inserted

    """Advanced reconnaissance engine using AssetManager field mappings"""
    
    def __init__(self, asset_manager, config: Dict, proxy_manager=None):
        self.asset_manager = asset_manager  # Use YOUR AssetManager
        self.config = config
        self.proxy_manager = proxy_manager
        self.max_concurrent = 25
        
        # Reconnaissance techniques
        self.recon_techniques = [
            'certificate_transparency',
            'dns_enumeration',
            'port_scanning',
            'wayback_analysis',
            'github_dorking',
            'social_media_recon'
        ]
        
        logger.info("🕵️ ReconnaissanceEngine initialized with AssetManager integration")
    
    async def initialize(self):
        """Initialize reconnaissance engine"""
        try:
            # Log initialization using AssetManager
            self.asset_manager.log_activity(
                'RECON_ENGINE_INIT',
                f'ReconnaissanceEngine initialized with {len(self.recon_techniques)} techniques'
            )
            
            logger.info("✅ ReconnaissanceEngine initialization complete")
            
        except Exception as e:
            logger.error(f"ReconnaissanceEngine initialization failed: {e}")
    
    def adjust_performance(self, direction: str, max_concurrent: int):
        """Adjust reconnaissance performance based on CPU usage"""
        if direction == "increase":
            self.max_concurrent = min(40, max_concurrent // 10)
        else:
            self.max_concurrent = max(10, max_concurrent // 20)
        
        logger.debug(f"ReconnaissanceEngine performance adjusted: {self.max_concurrent} concurrent")
    
    
    async def basic_profile_round(self, session: aiohttp.ClientSession, limit: int = 120) -> int:
        """One-shot basic HTTP profiling for assets lacking status_code using AssetManager mappings."""
        fields = self.asset_manager.get_asset_fields()
        
        # Use AssetManager field mappings for query
        query = f"SELECT {fields['url']} FROM assets WHERE {fields['status_code']} IS NULL OR {fields['status_code']}='' ORDER BY {fields['id']} DESC LIMIT ?"
        
        with self.asset_manager._get_db() as db:
            urls = [r[0] for r in db.execute(query, (limit,)).fetchall()]
        if not urls:
            return 0

        sem = asyncio.Semaphore(20)

        async def worker(u):
            """ENHANCED httpx-style verification with comprehensive probing"""
            import time, json
            start = time.time()
            ok = False; status=None; headers={}; body=""; rt_ms=None; title=None
            content_length = 0; tech_stack = []; redirect_url = None
            
            proxy = await self._get_proxy()
            try:
                async with self.semaphore:
                    # Multiple request methods for comprehensive coverage
                    methods_to_try = ['GET', 'HEAD']
                    
                    for method in methods_to_try:
                        try:
                            if method == 'GET':
                                async with session.get(u, timeout=15, allow_redirects=True, proxy=proxy) as r:
                                    status = r.status
                                    headers = dict(r.headers)
                                    # Read body first, then calculate content length
                                    body_bytes = await r.read()
                                    content_length = len(body_bytes)
                                    
                                    try:
                                        body = body_bytes.decode('utf-8', errors="ignore")
                                    except Exception:
                                        body = ""
                                    
                                    # Enhanced title extraction
                                    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I|re.S)
                                    title = re.sub(r"\s+", " ",m.group(1)).strip()[:255] if m else None
                                    
                                    # Technology detection from headers and body
                                    tech_stack = self._detect_technologies_quick(headers, body)
                                    
                                    # Follow redirects info
                                    if str(r.url) != u:
                                        redirect_url = str(r.url)
                                    
                                    ok = True
                                    break  # Success, no need to try other methods
                                    
                            elif method == 'HEAD' and not ok:
                                # HEAD request for basic info if GET failed
                                async with session.head(u, timeout=10, allow_redirects=True, proxy=proxy) as r:
                                    status = r.status
                                    headers = dict(r.headers)
                                    content_length = int(headers.get('content-length', 0))
                                    ok = True
                                    break
                                    
                        except Exception as method_error:
                            continue  # Try next method
                            
            except Exception as _e:
                ok = False
            finally:
                rt_ms = int((time.time() - start) * 1000)

            # Use AssetManager field mappings for all columns
            cols = [f"{fields['last_scanned']}=?", "basic_scan_complete=?", "scanning_stage=?"]
            vals = [__import__("datetime").datetime.now().isoformat(), 0, "new"]
            
            if ok and status:
                cols.extend([f"{fields['status_code']}=?", f"{fields['response_time']}=?", "basic_scan_complete=?", "scanning_stage=?"])
                vals.extend([status, rt_ms, 1, "basic_complete"])
                
                if title:
                    cols.append(f"{fields['title']}=?")
                    vals.append(title)
                    
                if content_length:
                    cols.append(f"{fields['content_length']}=?") 
                    vals.append(content_length)
                    
                if tech_stack:
                    cols.append(f"technologies_detected=?")
                    vals.append(json.dumps(tech_stack))
                    
                if redirect_url:
                    cols.append(f"redirect_url=?")
                    vals.append(redirect_url)

                cols.extend([
                    f"{fields['status_code']}=?",
                    f"{fields['title']}=?",
                    f"{fields['response_body']}=?",
                    f"{fields['content_length']}=?",
                    f"{fields['response_time']}=?",
                    "headers_collected=?",
                    f"{fields['intelligence_score']}=" + ("0.9" if (status==200) else "0.5" if 300<=status<400 else "0.4")
                ])
                vals.extend([status, title, (body or "")[:100000], len(body or ""), rt_ms, __import__("json").dumps(headers or {})])
            else:
                cols.append( "scanning_stage=COALESCE(scanning_stage,'new')" )

            # Use AssetManager field mappings in WHERE clause
            sql = f"UPDATE assets SET {', '.join(cols)} WHERE {fields['url']}=?"
            vals.append(u)
            with self.asset_manager._get_db() as db:
                db.execute(sql, vals); db.commit()

        await asyncio.gather(*(worker(u) for u in urls))
        return len(urls)

    async def perform_advanced_reconnaissance(self, session: aiohttp.ClientSession, limit: int = 25) -> Dict:
        """Perform advanced reconnaissance on scope domains"""
        
        # Get scope domains using AssetManager
        scope_domains = self.asset_manager.get_scope_domains()
        
        if not scope_domains:
            return {"status": "no_domains_in_scope"}
        
        logger.info(f"🕵️ Starting advanced reconnaissance on {len(scope_domains)} domains")
        
        
        # TIER 1.5: Basic profiling (no redirects; captures 3xx/404)
        
        try:
        
            filled = await self.basic_profile_round(session, limit=120)
        
            logger.info(f"🔎 Basic profiling filled {filled} assets")
        
        except Exception as e:
        
            logger.warning(f"basic_profile_round failed: {e}")

        recon_results = {
            "total_domains": len(scope_domains),
            "techniques_used": [],
            "discoveries": {
                "subdomains": [],
                "certificates": [],
                "dns_records": [],
                "open_ports": [],
                "historical_urls": [],
                "technologies": []
            },
            "completed_at": datetime.now().isoformat()
        }
        
        # Limit domains for performance
        domains_to_recon = scope_domains[:limit]
        
        semaphore = asyncio.Semaphore(self.max_concurrent)
        recon_tasks = []
        
        for domain in domains_to_recon:
            recon_tasks.append(
                self._perform_domain_reconnaissance(domain, session, semaphore)
            )
        
        if recon_tasks:
            results = await asyncio.gather(*recon_tasks, return_exceptions=True)
            
            # Aggregate results
            for result in results:
                if isinstance(result, dict):
                    # Merge discoveries
                    for category, items in result.get("discoveries", {}).items():
                        if category in recon_results["discoveries"]:
                            recon_results["discoveries"][category].extend(items)
                    
                    # Track techniques used
                    techniques = result.get("techniques_used", [])
                    recon_results["techniques_used"].extend(techniques)
            
            # Remove duplicates
            for category in recon_results["discoveries"]:
                recon_results["discoveries"][category] = list(set(recon_results["discoveries"][category]))
            
            recon_results["techniques_used"] = list(set(recon_results["techniques_used"]))
        
        total_discoveries = sum(len(items) for items in recon_results["discoveries"].values())
        logger.info(f"✅ Advanced reconnaissance complete: {total_discoveries} total discoveries")
        
        # Log reconnaissance completion using AssetManager
        self.asset_manager.log_activity(
            'ADVANCED_RECON_COMPLETE',
            f'Advanced reconnaissance completed - {total_discoveries} discoveries across {len(domains_to_recon)} domains'
        )
        



        # BEGIN_T4_PERSIST
        _d = recon_results.get('discoveries') if isinstance(recon_results, dict) else None
        if _d:
            try:
                new_rows = await self._persist_discoveries_to_assets(_d, session)
                logger.info(f"🧩 Persisted {new_rows} Tier-4 discoveries into assets")
            except Exception as e:
                logger.warning(f"persist Tier-4 discoveries failed: {e}")
        # END_T4_PERSIST

        return recon_results
    
    async def _perform_domain_reconnaissance(self, domain: str, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore) -> Dict:
        """Perform comprehensive reconnaissance on single domain"""
        async with semaphore:
            
            if domain.startswith('*.'):
                domain = domain[2:]
            
            domain_results = {
                "domain": domain,
                "techniques_used": [],
                "discoveries": {
                    "subdomains": [],
                    "certificates": [],
                    "dns_records": [],
                    "open_ports": [],
                    "historical_urls": [],
                    "technologies": []
                }
            }
            
            try:
                # Certificate Transparency reconnaissance
                ct_results = await self._certificate_transparency_recon(domain, session)
                domain_results["discoveries"]["certificates"].extend(ct_results.get("certificates", []))
                domain_results["discoveries"]["subdomains"].extend(ct_results.get("subdomains", []))
                if ct_results:
                    domain_results["techniques_used"].append("certificate_transparency")
                
                # DNS enumeration
                dns_results = await self._advanced_dns_reconnaissance(domain)
                domain_results["discoveries"]["dns_records"].extend(dns_results.get("records", []))
                if dns_results:
                    domain_results["techniques_used"].append("dns_enumeration")
                
                # Port scanning (limited)
                port_results = await self._lightweight_port_scan(domain)
                domain_results["discoveries"]["open_ports"].extend(port_results)
                if port_results:
                    domain_results["techniques_used"].append("port_scanning")
                
                # Wayback Machine analysis
                wayback_results = await self._wayback_machine_recon(domain, session)
                domain_results["discoveries"]["historical_urls"].extend(wayback_results)
                if wayback_results:
                    domain_results["techniques_used"].append("wayback_analysis")
                
                logger.debug(f"🔍 Domain reconnaissance complete: {domain}")
                
                return domain_results
                
            except Exception as e:
                logger.debug(f"Domain reconnaissance failed for {domain}: {e}")
                return domain_results
    
    async def _certificate_transparency_recon(self, domain: str, session: aiohttp.ClientSession) -> Dict:
        """Advanced Certificate Transparency reconnaissance"""
        results = {
            "certificates": [],
            "subdomains": []
        }
        
        try:
            # Multiple CT log sources
            ct_sources = [
                f"https://crt.sh/?q=%.{domain}&output=json",
                f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
            ]
            
            for ct_url in ct_sources:
                try:
                    headers = {'User-Agent': 'ReconnaissanceEngine/1.0'}
                    
                    proxy = await self._get_proxy()
                    async with self.semaphore:
                        async with session.get(ct_url, headers=headers, timeout=15, proxy=proxy) as response:
                            if response.status == 200:
                                ct_data = await response.json()
                            
                            # Parse crt.sh format
                            if 'crt.sh' in ct_url and isinstance(ct_data, list):
                                for entry in ct_data[:50]:  # Limit results
                                    name_value = entry.get('name_value', '')
                                    
                                    if name_value:
                                        cert_domains = name_value.split('\n')
                                        
                                        for cert_domain in cert_domains:
                                            cert_domain = cert_domain.strip().lower()
                                            
                                            if cert_domain.endswith(f'.{domain}') or cert_domain == domain:
                                                if cert_domain.startswith('*.'):
                                                    results["certificates"].append(f"Wildcard: {cert_domain}")
                                                else:
                                                    results["subdomains"].append(cert_domain)
                            
                            # Parse certspotter format
                            elif 'certspotter' in ct_url and isinstance(ct_data, list):
                                for entry in ct_data[:50]:
                                    dns_names = entry.get('dns_names', [])
                                    
                                    for dns_name in dns_names:
                                        if dns_name.endswith(f'.{domain}') or dns_name == domain:
                                            results["subdomains"].append(dns_name.lower())
                
                except Exception as e:
                    logger.debug(f"CT source {ct_url} failed: {e}")
                    continue
            
            # Deduplicate results
            results["subdomains"] = list(set(results["subdomains"]))
            results["certificates"] = list(set(results["certificates"]))
            
        except Exception as e:
            logger.error(f"Certificate Transparency recon failed for {domain}: {e}")
        
        return results
    
    async def _advanced_dns_reconnaissance(self, domain: str) -> Dict:
        """Advanced DNS reconnaissance"""
        results = {"records": []}
        
        try:
            # DNS record types to query
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS']
            
            for record_type in record_types:
                try:
                    import socket
                    
                    if record_type == 'A':
                        # Get A records (IPv4)
                        try:
                            ip = socket.gethostbyname(domain)
                            results["records"].append(f"{record_type}: {domain} -> {ip}")
                        except socket.gaierror:
                            pass
                    
                    # For other record types, we'd need dnspython
                    # For now, just record the attempt
                    results["records"].append(f"{record_type}: Query attempted for {domain}")
                    
                except Exception:
                    continue
        
        except Exception as e:
            logger.error(f"DNS reconnaissance failed for {domain}: {e}")
        
        return results
    
    async def _lightweight_port_scan(self, domain: str) -> List[str]:
        """Lightweight port scan on common ports"""
        open_ports = []
        
        try:
            # Expanded common ports (using SecLists data)
            common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5985, 5986, 8080, 8443, 8888, 9090]
            
            # Get IP address
            try:
                ip = socket.gethostbyname(domain)
            except socket.gaierror:
                return open_ports
            
            # Enhanced port checks with more coverage
            for port in common_ports[:15]:  # Check top 15 ports instead of 8
                try:
                    future = asyncio.open_connection(ip, port)
                    reader, writer = await asyncio.wait_for(future, timeout=2)
                    
                    writer.close()
                    await writer.wait_closed()
                    
                    open_ports.append(f"{ip}:{port}")
                    
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    continue
        
        except Exception as e:
            logger.error(f"Port scan failed for {domain}: {e}")
        
        return open_ports
    
    async def _wayback_machine_recon(self, domain: str, session: aiohttp.ClientSession) -> List[str]:
        """COMPREHENSIVE Historical URL analysis - waymore/gau equivalent"""
        historical_urls = []
        
        # Multiple archive sources for comprehensive coverage
        sources = [
            # Wayback Machine - comprehensive
            f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=1000&filter=statuscode:200",
            f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&limit=1000&filter=statuscode:200",
            
            # Common Crawl - more recent data
            f"https://index.commoncrawl.org/CC-MAIN-2024-10-index?url={domain}/*&output=json&limit=500",
            
            # AlienVault OTX (if available)
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500"
        ]
        
        for source_url in sources:
            try:
                proxy = await self._get_proxy()
                async with self.semaphore:
                    timeout = aiohttp.ClientTimeout(total=20)
                    async with session.get(source_url, timeout=timeout, proxy=proxy) as response:
                        if response.status == 200:
                            if 'archive.org' in source_url:
                                # Wayback Machine format
                                data = await response.json()
                                if isinstance(data, list) and len(data) > 1:
                                    for entry in data[1:]:  # Skip header
                                        if len(entry) > 2:
                                            url = entry[2]  # URL column
                                            if self._is_interesting_url(url, domain):
                                                historical_urls.append(url)
                                                
                            elif 'commoncrawl.org' in source_url:
                                # Common Crawl format
                                lines = (await response.text()).strip().split('\n')
                                for line in lines:
                                    try:
                                        entry = json.loads(line)
                                        url = entry.get('url', '')
                                        if self._is_interesting_url(url, domain):
                                            historical_urls.append(url)
                                    except:
                                        continue
                                        
                            elif 'alienvault.com' in source_url:
                                # OTX format
                                data = await response.json()
                                for entry in data.get('url_list', []):
                                    url = entry.get('url', '')
                                    if self._is_interesting_url(url, domain):
                                        historical_urls.append(url)
                        
            except Exception as e:
                logger.error(f"Historical recon failed for {source_url}: {e}")
                continue
        
        # Advanced filtering and scoring
        scored_urls = []
        for url in set(historical_urls):
            score = self._score_historical_url(url)
            if score > 0.3:  # Only include interesting URLs
                scored_urls.append((url, score))
        
        # Sort by score and return top URLs
        scored_urls.sort(key=lambda x: x[1], reverse=True)
        final_urls = [url for url, score in scored_urls[:200]]  # Top 200 most interesting
        
        logger.info(f"🕰️ Historical recon found {len(final_urls)} interesting URLs for {domain}")
        return final_urls
    
    def _is_interesting_url(self, url: str, domain: str) -> bool:
        """Determine if URL is worth testing - CONFIGURABLE filtering (default: capture everything)"""
        if not url or not url.startswith('http') or domain not in url:
            return False
            
        # Get filtering mode from config (default: minimal filtering)
        filtering_mode = self.config.get('url_filtering_mode', 'minimal')  # minimal, aggressive, or disabled
        
        if filtering_mode == 'disabled':
            return True  # Capture everything
            
        url_lower = url.lower()
        
        # MINIMAL filtering - only skip obvious static assets that can't have vulns
        if filtering_mode == 'minimal':
            # Only skip binary files that definitely can't contain vulnerabilities
            binary_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.ico', '.woff', '.ttf', '.pdf', '.zip', '.exe', '.dmg']
            if any(url_lower.endswith(ext) for ext in binary_extensions):
                return False
            return True  # Include everything else including CSS/JS which can have secrets
            
        # AGGRESSIVE filtering - original logic (may miss valuable URLs)
        elif filtering_mode == 'aggressive':
            # Skip more file types (potentially missing CSS/JS with secrets)
            skip_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.css', '.ico', '.woff', '.ttf', '.svg']
            if any(url_lower.endswith(ext) for ext in skip_extensions):
                return False
                
            # High-value indicators
            interesting_keywords = [
                'admin', 'api', 'login', 'config', 'backup', 'upload', 'dashboard',
                'panel', 'manage', 'auth', 'token', 'key', 'secret', 'test', 'dev',
                'staging', 'debug', 'internal', 'private', 'hidden', '.env', 'swagger',
                'graphql', 'rest', 'endpoint', 'service', 'micro', 'app', 'mobile'
            ]
            
            # Parameters indicate dynamic content
            has_params = '?' in url and '=' in url
            has_interesting_keywords = any(keyword in url_lower for keyword in interesting_keywords)
            has_interesting_path = len([p for p in url.split('/') if p]) > 3  # Deep paths
            
            return has_params or has_interesting_keywords or has_interesting_path
            
        return True  # Default: include everything
    
    def _score_historical_url(self, url: str) -> float:
        """Score URL by potential interest level"""
        score = 0.5  # Base score
        url_lower = url.lower()
        
        # High-value keywords
        if any(keyword in url_lower for keyword in ['admin', 'api', 'login', 'config']):
            score += 0.4
        if any(keyword in url_lower for keyword in ['backup', 'upload', 'dashboard', 'panel']):
            score += 0.3
        if any(keyword in url_lower for keyword in ['auth', 'token', 'key', 'secret']):
            score += 0.5
        if any(keyword in url_lower for keyword in ['.env', 'swagger', 'graphql']):
            score += 0.6
            
        # Parameters boost
        if '?' in url and '=' in url:
            param_count = url.count('=')
            score += min(param_count * 0.1, 0.3)
            
        # Path depth
        path_depth = len([p for p in url.split('/') if p])
        if path_depth > 4:
            score += 0.2
            
        return min(score, 1.0)
    
    def _detect_technologies_quick(self, headers: dict, body: str) -> List[str]:
        """Quick technology detection from headers and body - httpx style"""
        technologies = []
        
        # Header-based detection
        server = headers.get('server', '').lower()
        if 'nginx' in server:
            technologies.append('Nginx')
        if 'apache' in server:
            technologies.append('Apache')
        if 'cloudflare' in server:
            technologies.append('Cloudflare')
            
        # Framework headers
        if 'x-powered-by' in headers:
            powered_by = headers['x-powered-by'].lower()
            if 'php' in powered_by:
                technologies.append('PHP')
            if 'asp.net' in powered_by:
                technologies.append('ASP.NET')
                
        # Security headers
        if 'strict-transport-security' in headers:
            technologies.append('HSTS')
        if 'x-frame-options' in headers:
            technologies.append('X-Frame-Options')
            
        # Body-based detection (quick check)
        if body:
            body_lower = body.lower()
            if 'wp-content' in body_lower or 'wordpress' in body_lower:
                technologies.append('WordPress')
            if 'drupal' in body_lower:
                technologies.append('Drupal')
            if 'joomla' in body_lower:
                technologies.append('Joomla')
            if 'react' in body_lower or 'reactjs' in body_lower:
                technologies.append('React')
            if 'angular' in body_lower:
                technologies.append('Angular')
            if 'vue' in body_lower or 'vuejs' in body_lower:
                technologies.append('Vue.js')
                
        return list(set(technologies))
    
    async def _get_proxy(self) -> Optional[str]:
        """Get proxy from shared proxy manager with proper rate limiting"""
        if self.proxy_manager:
            return self.proxy_manager.get_random_proxy()
        return None

    def get_reconnaissance_statistics(self) -> Dict:
        """Get reconnaissance engine statistics"""
        return {
            "techniques_available": len(self.recon_techniques),
            "max_concurrent": self.max_concurrent,
            "supported_techniques": self.recon_techniques
        }