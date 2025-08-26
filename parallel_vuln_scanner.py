#!/usr/bin/env python3
"""
Parallel Vulnerability Scanner
Runs multiple ML-Enhanced scanners concurrently for maximum efficiency
"""
import asyncio
import aiohttp
import sys
import json
import time
from typing import List, Dict
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import multiprocessing

# Import required modules
from asset_manager import AssetManager, VulnerabilityFinding
from modules.enhanced_vuln_scanner import EnhancedVulnerabilityScanner
from modules.ml_reflection_engine import MLReflectionEngine

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')
logger = logging.getLogger(__name__)

class ParallelVulnScanner:
    def __init__(self, max_concurrent: int = 3):
        # Initialize AssetManager
        self.asset_manager = AssetManager()
        
        # Load config
        try:
            with open('config.json', 'r') as f:
                self.config = json.load(f)
        except:
            self.config = {}
        
        # Load authentication universally
        self._load_universal_auth()
        self._load_browser_storage_auth()
        
        self.max_concurrent = min(max_concurrent, multiprocessing.cpu_count())
        
        logger.warning(f"🚀 PARALLEL VULNERABILITY SCANNER initialized")
        logger.warning(f"⚡ Max concurrent scans: {self.max_concurrent}")
        
    def _load_universal_auth(self):
        """Load authentication for ANY target from database"""
        try:
            import sqlite3
            with sqlite3.connect(self.asset_manager.db_path) as db:
                cursor = db.execute("SELECT domain, cookie FROM cookies ORDER BY last_updated DESC LIMIT 1")
                cookie_data = cursor.fetchone()
                if cookie_data:
                    domain, cookie_value = cookie_data
                    self.config['auth_cookie'] = cookie_value
                    logger.info(f"🔐 Universal auth loaded for domain: {domain}")
                else:
                    logger.info("🌐 No auth cookies - universal unauthenticated mode")
        except Exception as e:
            logger.debug(f"Auth loading: {e}")
    
    def _load_browser_storage_auth(self):
        """Load authentication from browser storage states"""
        try:
            import json
            import os
            storage_dir = "storage_states"
            
            # Look for storage state files
            if os.path.exists(storage_dir):
                for filename in os.listdir(storage_dir):
                    if filename.endswith('.json'):
                        storage_path = os.path.join(storage_dir, filename)
                        with open(storage_path, 'r') as f:
                            storage_data = json.load(f)
                        
                        # Extract cookies from storage
                        if 'cookies' in storage_data:
                            cookies = []
                            for cookie in storage_data['cookies']:
                                cookie_str = f"{cookie['name']}={cookie['value']}"
                                cookies.append(cookie_str)
                            
                            if cookies:
                                auth_cookie = '; '.join(cookies)
                                self.config['auth_cookie'] = auth_cookie
                                domain = filename.replace('.json', '')
                                logger.info(f"🔐 Browser storage auth loaded for: {domain}")
                                return
        except Exception as e:
            logger.debug(f"Browser storage auth loading: {e}")
    
    async def scan_urls_parallel(self, urls: List[str]):
        """Parallel vulnerability scanning with multiple instances"""
        start_time = time.time()
        total_vulns = 0
        
        logger.warning(f"⚡ PARALLEL SCAN: {len(urls)} URLs across {self.max_concurrent} concurrent scanners")
        logger.warning(f"🛠️  Each scanner: SQLMap + Nuclei + FFuF + Dalfox + ML Reflection Analysis")
        
        # Create semaphore to limit concurrent scans
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def scan_single_url(url: str) -> int:
            async with semaphore:
                logger.warning(f"🎯 SCANNING: {url}")
                
                # Initialize scanner for this instance
                scanner = EnhancedVulnerabilityScanner(self.asset_manager, self.config.copy())
                ml_engine = MLReflectionEngine()
                
                async with aiohttp.ClientSession() as session:
                    findings = []
                    
                    # Phase 1: ML Reflection Analysis (fast)
                    await self._ml_reflection_phase(url, session, ml_engine)
                    
                    # Phase 2: Enhanced tool-based scanning  
                    tool_findings = await scanner.scan_url_comprehensive(url, session)
                    findings.extend(tool_findings)
                    
                    # Phase 3: Store findings
                    if findings:
                        await self._store_universal_findings(url, findings)
                        
                        for finding in findings:
                            logger.error(f"🚨 VULN FOUND ({url}):")
                            logger.error(f"   Type: {finding.vuln_type}")
                            logger.error(f"   Severity: {finding.severity}")
                            logger.error(f"   Evidence: {finding.evidence[:100]}...")
                        
                        return len(findings)
                    else:
                        logger.info(f"   ✅ No vulnerabilities in {url}")
                        return 0
        
        # Run all scans concurrently
        tasks = [scan_single_url(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Count total vulnerabilities found
        for result in results:
            if isinstance(result, int):
                total_vulns += result
            elif isinstance(result, Exception):
                logger.error(f"Scanner error: {result}")
        
        elapsed = time.time() - start_time
        logger.warning(f"\\n⚡ PARALLEL SCAN COMPLETE!")
        logger.warning(f"📊 Total vulnerabilities: {total_vulns}")
        logger.warning(f"⏱️  Total time: {elapsed:.1f}s ({elapsed/len(urls):.1f}s per URL)")
        logger.warning(f"💾 All findings stored in database → visible in dashboard")
    
    async def _ml_reflection_phase(self, url: str, session: aiohttp.ClientSession, ml_engine):
        """ML-powered reflection analysis phase"""
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            if parsed.query:
                params = list(parse_qs(parsed.query).keys())
                
                for param in params[:2]:  # Quick analysis of top 2 parameters
                    mutations = await ml_engine.analyze_reflection_comprehensive(
                        url, param, session, self.config.get('auth_cookie')
                    )
                    
                    # Store high-confidence ML findings
                    for mutation in mutations:
                        if mutation.success_probability > 0.8:
                            finding = VulnerabilityFinding(
                                url=url,
                                vuln_type='ML_DETECTED_REFLECTION',
                                severity='High' if mutation.success_probability > 0.9 else 'Medium',
                                confidence=mutation.success_probability,
                                payload=mutation.mutated_payload,
                                evidence=f"ML-detected reflection vulnerability (Score: {mutation.success_probability:.2f})",
                                discovered_at=datetime.now(),
                                affected_parameter=param
                            )
                            await self._store_single_finding(url, finding)
        except Exception as e:
            logger.debug(f"ML reflection analysis failed: {e}")
    
    async def _store_universal_findings(self, url: str, findings: List[VulnerabilityFinding]):
        """Store findings universally for ANY target"""
        try:
            asset_id = self.asset_manager.add_asset(url, 200)
            for finding in findings:
                self.asset_manager.add_vulnerability_finding(finding, asset_id)
        except Exception as e:
            logger.error(f"Failed to store findings: {e}")
    
    async def _store_single_finding(self, url: str, finding: VulnerabilityFinding):
        """Store a single finding"""
        try:
            asset_id = self.asset_manager.add_asset(url, 200)
            self.asset_manager.add_vulnerability_finding(finding, asset_id)
        except Exception as e:
            logger.debug(f"Failed to store finding: {e}")

async def main():
    if len(sys.argv) < 2:
        print("⚡ Parallel Universal Vulnerability Scanner")
        print("Runs multiple ML-Enhanced scanners concurrently for maximum efficiency")
        print("🌍 UNIVERSAL: Works on ANY target without hardcoded assumptions")
        print()
        print("Usage:")
        print("  python parallel_vuln_scanner.py <url1> <url2> <url3> ...")
        print("  python parallel_vuln_scanner.py --concurrent=5 <url1> <url2> ...")
        print()
        print("Examples:")
        print("  python parallel_vuln_scanner.py http://192.168.1.42/dvwa/vulnerabilities/sqli http://192.168.1.42/dvwa/vulnerabilities/xss_r")
        print("  python parallel_vuln_scanner.py --concurrent=3 http://target1.com http://target2.com http://target3.com")
        sys.exit(1)
    
    # Parse arguments
    max_concurrent = 3
    urls = []
    
    for arg in sys.argv[1:]:
        if arg.startswith('--concurrent='):
            max_concurrent = int(arg.split('=')[1])
        elif arg.startswith('http'):
            urls.append(arg)
    
    if not urls:
        print("❌ No URLs provided")
        sys.exit(1)
    
    scanner = ParallelVulnScanner(max_concurrent=max_concurrent)
    await scanner.scan_urls_parallel(urls)

if __name__ == "__main__":
    asyncio.run(main())