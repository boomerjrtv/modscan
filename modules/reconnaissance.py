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
        for it in items or []:
            key = str(it)
            try:
                if callable(gate) and not gate(key):
                    continue
            except Exception:
                pass
            if key in seen:
                continue
            seen.add(key)
            out.append(it)
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

    async def _persist_discoveries_to_assets(self, discoveries: dict):
        """Insert discovered subdomains (Tier-4) as assets so they appear in dashboard and get scanned."""
        if not discoveries:
            return 0
        subs = set(discoveries.get("subdomains") or [])
        inserted = 0
        for host in subs:
            # Build a canonical https URL; trailing slash, no query.
            url = f"https://{host.strip().lstrip('.')}/"
            try:
                query, values = self.asset_manager.build_asset_insert_query(
                    url=url,
                    host=host,
                    status_code=None,
                    title=None,
                    content_length=None,
                    response_time=None,
                    discovery_method="tier4_advanced",
                    last_scanned=None
                )
                import sqlite3
                with self.asset_manager._get_db() as db:
                    db.execute(query, values)
                    db.commit()
                    inserted += 1
            except Exception as e:
                # Most failures here will be UNIQUE collisions; ignore quietly.
                import logging; logging.getLogger(__name__).debug(f"persist skip {url}: {e}")
        return inserted

    """Advanced reconnaissance engine using AssetManager field mappings"""
    
    def __init__(self, asset_manager, config: Dict):
        self.asset_manager = asset_manager  # Use YOUR AssetManager
        self.config = config
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
            import time, json
            start = time.time()
            ok = False; status=None; headers={}; body=""; rt_ms=None; title=None
            try:
                async with self.semaphore:
                    async with session.get(u, timeout=10, allow_redirects=False) as r:
                        status = r.status
                    headers = dict(r.headers)
                    try:
                        body = await r.text(errors="ignore")
                    except Exception:
                        body = (await r.read()).decode("utf-8","ignore")
                    # title
                    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I|re.S)
                    title = re.sub(r"\s+"," ",m.group(1)).strip()[:255] if m else None
                    ok = True
            except Exception as _e:
                ok = False
            finally:
                rt_ms = int((time.time() - start) * 1000)

            # Use AssetManager field mappings for all columns
            cols = [f"{fields['last_scanned']}=?"]
            vals = [__import__("datetime").datetime.now().isoformat()]

            if ok:
                cols += [
                    f"{fields['status_code']}=?",
                    f"{fields['title']}=?",
                    f"{fields['response_body']}=?",
                    f"{fields['content_length']}=?",
                    f"{fields['response_time']}=?",
                    "headers_collected=?",
                    "basic_scan_complete=1",
                    "scanning_stage='basic_complete'",
                    f"{fields['intelligence_score']}=" + ("0.9" if (status==200) else "0.5" if 300<=status<400 else "0.4")
                ]
                vals += [status, title, (body or "")[:100000], len(body or ""), rt_ms, __import__("json").dumps(headers or {})]
            else:
                cols += [ "basic_scan_complete=0", "scanning_stage=COALESCE(scanning_stage,'new')" ]

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
                new_rows = await self._persist_discoveries_to_assets(_d)
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
                    
                    async with self.semaphore:
                        async with session.get(ct_url, headers=headers, timeout=15) as response:
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
            logger.debug(f"Certificate Transparency recon failed for {domain}: {e}")
        
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
            logger.debug(f"DNS reconnaissance failed for {domain}: {e}")
        
        return results
    
    async def _lightweight_port_scan(self, domain: str) -> List[str]:
        """Lightweight port scan on common ports"""
        open_ports = []
        
        try:
            # Common web ports
            common_ports = [21, 22, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
            
            # Get IP address
            try:
                ip = socket.gethostbyname(domain)
            except socket.gaierror:
                return open_ports
            
            # Quick port checks (limited for performance)
            for port in common_ports[:8]:  # Only check top 8 ports
                try:
                    future = asyncio.open_connection(ip, port)
                    reader, writer = await asyncio.wait_for(future, timeout=2)
                    
                    writer.close()
                    await writer.wait_closed()
                    
                    open_ports.append(f"{ip}:{port}")
                    
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    continue
        
        except Exception as e:
            logger.debug(f"Port scan failed for {domain}: {e}")
        
        return open_ports
    
    async def _wayback_machine_recon(self, domain: str, session: aiohttp.ClientSession) -> List[str]:
        """Wayback Machine historical URL analysis"""
        historical_urls = []
        
        try:
            wayback_url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=50"
            
            async with self.semaphore:
                async with session.get(wayback_url, timeout=15) as response:
                    if response.status == 200:
                        wayback_data = await response.json()
                    
                    if isinstance(wayback_data, list) and len(wayback_data) > 1:
                        for entry in wayback_data[1:]:  # Skip header row
                            if len(entry) > 2:
                                url = entry[2]  # URL is in 3rd column
                                
                                if url.startswith('http') and domain in url:
                                    # Extract interesting paths
                                    if any(interesting in url.lower() for interesting in 
                                          ['admin', 'api', 'login', 'config', 'backup']):
                                        historical_urls.append(url)
        
        except Exception as e:
            logger.debug(f"Wayback Machine recon failed for {domain}: {e}")
        
        return list(set(historical_urls))[:20]  # Deduplicate and limit
    
    def get_reconnaissance_statistics(self) -> Dict:
        """Get reconnaissance engine statistics"""
        return {
            "techniques_available": len(self.recon_techniques),
            "max_concurrent": self.max_concurrent,
            "supported_techniques": self.recon_techniques
        }
