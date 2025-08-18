#!/usr/bin/env python3
"""
Proper Recon Engine - Following professional bug hunting methodology
Based on the comprehensive guide: proper subdomain enum → httpx validation → url discovery → testing
"""

import asyncio
import subprocess
import logging
import tempfile
from pathlib import Path
from typing import List, Dict, Set
from datetime import datetime

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

logger = logging.getLogger("ProperReconEngine")

class ProperReconEngine:
    """Professional bug hunting methodology implementation"""
    
    def __init__(self, asset_manager, config):
        self.asset_manager = asset_manager
        self.config = config
        
    async def run_complete_recon(self, domain: str) -> Dict:
        """Run complete professional recon workflow on domain"""
        results = {
            'domain': domain,
            'subdomains_found': 0,
            'live_subdomains': 0,
            'urls_discovered': 0,
            'directories_found': 0,
            'live_assets_saved': 0
        }
        
        try:
            logger.info(f"🎯 PROFESSIONAL RECON: {domain}")
            
            # Step 1: Subdomain Enumeration
            logger.info(f"📡 Step 1: Subdomain enumeration...")
            subdomains = await self._subdomain_enumeration(domain)
            results['subdomains_found'] = len(subdomains)
            logger.info(f"   Found {len(subdomains)} subdomains")
            
            if not subdomains:
                logger.warning(f"No subdomains found for {domain}")
                return results
            
            # Step 2: Live Validation with HTTPx 
            logger.info(f"🌐 Step 2: HTTPx validation...")
            live_subdomains = await self._httpx_validation(subdomains)
            results['live_subdomains'] = len(live_subdomains)
            logger.info(f"   {len(live_subdomains)} live subdomains validated")
            
            if not live_subdomains:
                logger.warning(f"No live subdomains for {domain}")
                return results
            
            # Step 3: URL Discovery on live targets
            logger.info(f"🕷️ Step 3: URL discovery on live targets...")
            discovered_urls = await self._url_discovery(live_subdomains)
            results['urls_discovered'] = len(discovered_urls)
            logger.info(f"   Discovered {len(discovered_urls)} URLs")
            
            # Step 4: Directory bruteforcing
            logger.info(f"📁 Step 4: Directory bruteforcing...")
            directory_urls = await self._directory_bruteforce(live_subdomains[:5])  # Top 5 targets
            results['directories_found'] = len(directory_urls)
            logger.info(f"   Found {len(directory_urls)} directories")
            
            # Step 5: Final HTTPx validation and save
            logger.info(f"✅ Step 5: Final validation and save...")
            all_urls = list(set(discovered_urls + directory_urls))
            
            if all_urls:
                final_live = await self._final_validation_and_save(all_urls, domain)
                results['live_assets_saved'] = len(final_live)
                logger.info(f"   Saved {len(final_live)} validated live assets")
            
            logger.info(f"🎯 RECON COMPLETE: {results}")
            return results
            
        except Exception as e:
            logger.error(f"Professional recon failed: {e}")
            return results
    
    async def _subdomain_enumeration(self, domain: str) -> List[str]:
        """Step 1: Comprehensive subdomain enumeration"""
        all_subdomains = set()
        
        # Method 1: Subfinder
        try:
            logger.info("   Running subfinder...")
            process = await asyncio.create_subprocess_exec(
                'subfinder', '-d', domain, '-all', '-silent',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            if process.returncode == 0:
                subfinder_results = [line.strip() for line in stdout.decode().strip().split('\n') if line.strip()]
                all_subdomains.update(subfinder_results)
                logger.info(f"     Subfinder: {len(subfinder_results)} subdomains")
        except Exception as e:
            logger.debug(f"Subfinder error: {e}")
        
        # Method 2: crt.sh via curl + jq
        try:
            logger.info("   Querying crt.sh...")
            process = await asyncio.create_subprocess_exec(
                'curl', '-s', f'https://crt.sh/?q=%.{domain}&output=json',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            if process.returncode == 0:
                # Parse with jq if available, otherwise basic parsing
                try:
                    import json
                    data = json.loads(stdout.decode())
                    crt_subdomains = []
                    for entry in data:
                        if 'name_value' in entry:
                            names = entry['name_value'].split('\n')
                            for name in names:
                                clean_name = name.replace('*.', '').strip()
                                if clean_name and domain in clean_name:
                                    crt_subdomains.append(clean_name)
                    
                    all_subdomains.update(crt_subdomains)
                    logger.info(f"     crt.sh: {len(crt_subdomains)} subdomains")
                except:
                    logger.debug("crt.sh parsing failed")
        except Exception as e:
            logger.debug(f"crt.sh error: {e}")
        
        # Convert to URLs
        subdomain_urls = []
        for subdomain in all_subdomains:
            if subdomain:
                subdomain_urls.extend([
                    f"https://{subdomain}",
                    f"http://{subdomain}"
                ])
        
        return list(set(subdomain_urls))
    
    async def _httpx_validation(self, subdomains: List[str]) -> List[Dict]:
        """Step 2: HTTPx validation - only keep live targets"""
        if not subdomains:
            return []
        
        try:
            # Create temp file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                for subdomain in subdomains:
                    f.write(f"{subdomain}\n")
                subdomain_file = f.name
            
            # Run HTTPx
            process = await asyncio.create_subprocess_exec(
                'httpx', '-l', subdomain_file, '-json', '-silent',
                '-status-code', '-title', '-tech-detect', '-content-length',
                '-follow-redirects', '-timeout', '5', '-threads', '50',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await process.communicate()
            Path(subdomain_file).unlink(missing_ok=True)
            
            if process.returncode != 0:
                logger.error("HTTPx validation failed")
                return []
            
            # Parse results
            live_subdomains = []
            for line in stdout.decode().strip().split('\n'):
                if not line.strip():
                    continue
                    
                try:
                    import json
                    result = json.loads(line)
                    
                    if result.get('status_code'):
                        live_subdomains.append({
                            'url': result['url'],
                            'status_code': result['status_code'],
                            'title': result.get('title', ''),
                            'tech': result.get('tech', []),
                            'content_length': result.get('content_length', 0)
                        })
                except:
                    continue
            
            return live_subdomains
            
        except Exception as e:
            logger.error(f"HTTPx validation error: {e}")
            return []
    
    async def _url_discovery(self, live_subdomains: List[Dict]) -> List[str]:
        """Step 3: URL discovery using katana on live targets"""
        if not live_subdomains:
            return []
        
        try:
            # Create file with live subdomain URLs
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                for subdomain in live_subdomains:
                    f.write(f"{subdomain['url']}\n")
                live_file = f.name
            
            # Run katana for URL discovery
            process = await asyncio.create_subprocess_exec(
                'katana', '-list', live_file, '-d', '3', '-kf', '-jc', '-fx',
                '-ef', 'woff,pdf,css,png,svg,jpg,woff2,jpeg,gif,ico,mp4,mp3',
                '-silent',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await process.communicate()
            Path(live_file).unlink(missing_ok=True)
            
            if process.returncode != 0:
                logger.debug("Katana not available, skipping URL discovery")
                return [sub['url'] for sub in live_subdomains]  # Return original URLs
            
            # Parse discovered URLs
            discovered = []
            for line in stdout.decode().strip().split('\n'):
                url = line.strip()
                if url and url.startswith(('http://', 'https://')):
                    discovered.append(url)
            
            # Add original live subdomains to discovered URLs
            for subdomain in live_subdomains:
                discovered.append(subdomain['url'])
            
            return list(set(discovered))
            
        except Exception as e:
            logger.debug(f"URL discovery error: {e}")
            return [sub['url'] for sub in live_subdomains]
    
    async def _directory_bruteforce(self, live_subdomains: List[Dict]) -> List[str]:
        """Step 4: Directory bruteforcing using dirsearch"""
        if not live_subdomains:
            return []
        
        discovered_dirs = []
        
        # Run dirsearch on top live targets
        for subdomain in live_subdomains[:3]:  # Limit to 3 targets
            try:
                logger.info(f"     Directory bruteforce: {subdomain['url']}")
                
                process = await asyncio.create_subprocess_exec(
                    'dirsearch', '-u', subdomain['url'], '--format=simple',
                    '-e', 'php,asp,aspx,jsp,txt,bak,backup,config,sql,log,xml,json',
                    '--random-agent', '--timeout=5', '--max-rate=10',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, _ = await process.communicate()
                
                if process.returncode == 0:
                    # Parse dirsearch output for found directories
                    for line in stdout.decode().split('\n'):
                        if 'http' in line and any(code in line for code in ['200', '301', '302', '403']):
                            # Extract URL from dirsearch output
                            parts = line.split()
                            for part in parts:
                                if part.startswith(('http://', 'https://')):
                                    discovered_dirs.append(part)
                                    break
                        
            except Exception as e:
                logger.debug(f"Dirsearch error for {subdomain['url']}: {e}")
                continue
        
        return list(set(discovered_dirs))
    
    async def _final_validation_and_save(self, urls: List[str], domain: str) -> List[Dict]:
        """Step 5: Final HTTPx validation and save to database"""
        if not urls:
            return []
        
        try:
            # Create temp file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                for url in urls:
                    f.write(f"{url}\n")
                url_file = f.name
            
            # Final HTTPx validation
            process = await asyncio.create_subprocess_exec(
                'httpx', '-l', url_file, '-json', '-silent',
                '-status-code', '-title', '-tech-detect', '-content-length',
                '-response-time', '-follow-redirects', '-timeout', '5',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await process.communicate()
            Path(url_file).unlink(missing_ok=True)
            
            if process.returncode != 0:
                return []
            
            # Parse and save results
            live_assets = []
            for line in stdout.decode().strip().split('\n'):
                if not line.strip():
                    continue
                    
                try:
                    import json
                    result = json.loads(line)
                    
                    url = result.get('url')
                    status_code = result.get('status_code')
                    
                    if url and status_code:
                        # Save to database
                        try:
                            self.asset_manager.add_asset(
                                url=url,
                                host=domain,
                                status_code=status_code,
                                title=result.get('title', '').strip()[:200] if result.get('title') else None,
                                tech_stack=', '.join(result.get('tech', [])[:5]) if result.get('tech') else None,
                                content_length=result.get('content_length'),
                                response_time=self._parse_response_time(result.get('time')),
                                discovery_method='professional_recon',
                                discovered_at=datetime.now().isoformat()
                            )
                            
                            live_assets.append({
                                'url': url,
                                'status_code': status_code,
                                'title': result.get('title'),
                                'tech_stack': result.get('tech')
                            })
                            
                        except Exception:
                            # Skip duplicates
                            pass
                            
                except json.JSONDecodeError:
                    continue
            
            return live_assets
            
        except Exception as e:
            logger.error(f"Final validation error: {e}")
            return []
    
    def _parse_response_time(self, time_str: str) -> int:
        """Parse response time to milliseconds"""
        if not time_str:
            return None
            
        try:
            if time_str.endswith('ms'):
                return int(float(time_str[:-2]))
            elif time_str.endswith('s'):
                return int(float(time_str[:-1]) * 1000)
            else:
                return int(float(time_str) * 1000)
        except:
            return None