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
from pathlib import Path
from typing import List, Dict, Optional, Set
from urllib.parse import urljoin
from datetime import datetime
from urllib.parse import urlparse, urljoin

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

logger = logging.getLogger("UltimateDiscovery")

class UltimateDiscoveryEngine:
    def __init__(self, asset_manager, config):
        self.asset_manager = asset_manager
        self.config = config
        self.discovery_cache = set()
        
        # Tool paths
        self.gau_path = config.get("tools", {}).get("gau_path", "gau")
        self.waybackurls_path = config.get("tools", {}).get("waybackurls_path", "waybackurls")
        self.katana_path = config.get("tools", {}).get("katana_path", "katana")
        self.subfinder_path = config.get("tools", {}).get("subfinder_path", "subfinder")
        self.rustscan_path = config.get("tools", {}).get("rustscan_path", "rustscan")
        self.nmap_path = config.get("tools", {}).get("nmap_path", "nmap")
        
        # ML patterns for intelligent discovery
        self.ml_patterns = self._load_ml_patterns()
        
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
        """Run comprehensive multi-tiered discovery for a domain"""
        logger.info(f"🚀 ULTIMATE DISCOVERY: {domain}")
        discovered_urls = set()
        
        # Tier 1: Historical URL Discovery (GAU, Wayback)
        historical_urls = await self._tier1_historical_discovery(domain)
        discovered_urls.update(historical_urls)
        logger.info(f"📚 Tier 1 Historical: {len(historical_urls)} URLs")
        
        # Tier 2: Active Subdomain Discovery  
        subdomains = await self._tier2_subdomain_discovery(domain)
        discovered_urls.update(subdomains)
        logger.info(f"🔍 Tier 2 Subdomains: {len(subdomains)} subdomains")
        
        # Tier 3: Active Crawling (Katana)
        crawled_urls = await self._tier3_active_crawling(domain, list(discovered_urls)[:50])
        discovered_urls.update(crawled_urls)
        logger.info(f"🕷️ Tier 3 Crawling: {len(crawled_urls)} URLs")
        
        # Tier 4: ML-Powered Intelligent Discovery
        ml_urls = await self._tier4_ml_discovery(domain, discovered_urls)
        discovered_urls.update(ml_urls)
        logger.info(f"🧠 Tier 4 ML Discovery: {len(ml_urls)} smart URLs")
        
        # Tier 5: Port Scanning & Service Discovery
        service_urls = await self._tier5_port_service_discovery(domain)
        discovered_urls.update(service_urls)
        logger.info(f"🛡️ Tier 5 Services: {len(service_urls)} service URLs")
        
        # Tier 6: Intelligent Directory Discovery (Smart SecLists)
        directory_urls = await self._tier6_intelligent_directory_discovery(domain, discovered_urls)
        discovered_urls.update(directory_urls)
        logger.info(f"📁 Tier 6 Directories: {len(directory_urls)} intelligent directory URLs")
        
        final_urls = list(discovered_urls)
        logger.info(f"🎯 DISCOVERY COMPLETE: {len(final_urls)} total URLs for {domain}")
        return final_urls
    
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
                for url in seed_urls[:20]:  # Limit seed URLs
                    f.write(f"{url}\n")
                seed_file = f.name
            
            logger.info(f"🕷️ Running Katana crawling on {len(seed_urls)} seed URLs")
            
            cmd = [
                self.katana_path,
                "-list", seed_file,
                "-depth", "3",
                "-concurrent", "10",
                "-timeout", "30",
                "-silent",
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
                    if not path.startswith('/'):
                        path = '/' + path
                    temp_wordlist.write(path + '\n')
                temp_wordlist_path = temp_wordlist.name
            
            try:
                # Run ffuf with recursion for each base URL
                for base_url in base_urls[:5]:  # Limit to 5 base URLs to avoid too much noise
                    logger.info(f"🔁 Running ffuf recursive discovery on {base_url}")
                    
                    # ffuf command with recursion
                    cmd = [
                        "/home/michael/go/bin/ffuf",
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
        """Select intelligent SecLists wordlists based on technology and patterns"""
        wordlists = {}
        
        # Load actual SecLists wordlists
        seclists_paths = self._load_seclists_wordlists()
        
        # Always include common directories from SecLists
        if 'directories' in seclists_paths:
            wordlists['directories'] = seclists_paths['directories']
        else:
            # Fallback hardcoded list
            wordlists['common'] = [
                '/admin', '/api', '/login', '/dashboard', '/config', '/backup',
                '/test', '/dev', '/staging', '/docs', '/help', '/support',
                '/upload', '/uploads', '/files', '/assets', '/static', '/public',
                '/dvwa', '/vulnerabilities', '/setup', '/security', '/database'
            ]
        
        # Technology-specific wordlists
        if 'php' in tech_stack:
            wordlists['php'] = [
                '/phpmyadmin', '/phpinfo.php', '/wp-admin', '/wp-content',
                '/includes', '/inc', '/lib', '/config.php', '/database.php',
                '/setup.php', '/install.php', '/upgrade.php'
            ]
            
        if 'wordpress' in tech_stack or any('wp-' in tech for tech in tech_stack):
            wordlists['wordpress'] = [
                '/wp-admin', '/wp-content', '/wp-includes', '/wp-json',
                '/wp-config.php', '/wp-login.php', '/xmlrpc.php',
                '/wp-content/uploads', '/wp-content/themes', '/wp-content/plugins'
            ]
            
        if 'nodejs' in tech_stack or 'node' in tech_stack:
            wordlists['nodejs'] = [
                '/node_modules', '/.env', '/package.json', '/server.js',
                '/app.js', '/index.js', '/dist', '/build', '/src'
            ]
            
        if 'python' in tech_stack or 'django' in tech_stack:
            wordlists['python'] = [
                '/admin', '/api', '/static', '/media', '/django-admin',
                '/settings.py', '/manage.py', '/requirements.txt', '/.env'
            ]
            
        if 'java' in tech_stack:
            wordlists['java'] = [
                '/WEB-INF', '/META-INF', '/servlet', '/struts',
                '/spring', '/admin', '/manager', '/console'
            ]
            
        # Pattern-based additions
        if url_patterns.get('api_endpoints', 0) > 5:
            wordlists['api_extended'] = [
                '/api/v1', '/api/v2', '/api/docs', '/swagger',
                '/graphql', '/rest', '/api/admin', '/api/users'
            ]
            
        if url_patterns.get('admin_paths', 0) > 3:
            wordlists['admin_extended'] = [
                '/admin/login', '/admin/panel', '/admin/dashboard',
                '/administrator', '/manage', '/control', '/cpanel'
            ]
            
        # Sensitive files and directories
        wordlists['sensitive'] = [
            '/.git', '/.env', '/.aws', '/.ssh', '/backup.zip',
            '/database.sql', '/config.json', '/secrets.yaml',
            '/.htaccess', '/.htpasswd', '/robots.txt', '/sitemap.xml'
        ]
        
        return wordlists
    
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
- For IP addresses like 192.168.1.42: focus on 'directories' and 'admin' 
- For DVWA/PHP apps: prioritize 'directories', 'admin', 'files'
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

For domain like "192.168.1.42" with potential DVWA, include paths like:
/dvwa/, /vulnerabilities/, /setup/, /security/, /database/, /config/

For PHP applications, include:
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