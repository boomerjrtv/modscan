#!/usr/bin/env python3
"""
ML-Enhanced Universal Vulnerability Scanner
Combines powerful external tools with machine learning and reflection detection
Works on ANY target - no hardcoded assumptions
"""
import asyncio
import aiohttp
import sys
import json
from typing import List, Dict
import logging
from datetime import datetime

# Import required modules
from asset_manager import AssetManager, VulnerabilityFinding
from modules.enhanced_vuln_scanner import EnhancedVulnerabilityScanner
from modules.ml_reflection_engine import MLReflectionEngine

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')
logger = logging.getLogger(__name__)

class MLEnhancedScanner:
    def __init__(self):
        # Initialize AssetManager
        self.asset_manager = AssetManager()
        
        # Load config
        try:
            with open('config.json', 'r') as f:
                self.config = json.load(f)
        except:
            self.config = {}
        
        # Load authentication cookies universally
        self._load_universal_auth()
        self._load_browser_storage_auth()
        
        # Initialize scanners
        self.enhanced_scanner = EnhancedVulnerabilityScanner(self.asset_manager, self.config)
        self.ml_engine = MLReflectionEngine()
        
        logger.info("🧠 ML-Enhanced Universal Scanner initialized")
        
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
    
    async def scan_urls_ml_enhanced(self, urls: List[str]):
        """ML-Enhanced vulnerability scanning for ANY target"""
        logger.warning(f"🚀 ML-ENHANCED SCAN: {len(urls)} URLs with adaptive learning")
        logger.warning(f"🛠️  Tools: SQLMap + Nuclei + FFuF + Dalfox + ML Reflection Analysis")
        
        total_vulns = 0
        
        async with aiohttp.ClientSession() as session:
            for url in urls:
                logger.warning(f"\n🎯 ML-SCANNING: {url}")
                
                # Phase 1: ML Reflection Analysis 
                await self._ml_reflection_phase(url, session)
                
                # Phase 2: Enhanced tool-based scanning
                findings = await self.enhanced_scanner.scan_url_comprehensive(url, session)
                
                # Phase 3: Store and report findings
                if findings:
                    await self._store_universal_findings(url, findings)
                    total_vulns += len(findings)
                    
                    for finding in findings:
                        logger.error(f"🚨 VULNERABILITY FOUND:")
                        logger.error(f"   Type: {finding.vuln_type}")
                        logger.error(f"   Severity: {finding.severity}")
                        logger.error(f"   URL: {finding.url}")
                        logger.error(f"   Payload: {finding.payload}")
                        logger.error(f"   Evidence: {finding.evidence[:150]}...")
                else:
                    logger.info(f"   ✅ No vulnerabilities detected in {url}")
        
        logger.warning(f"\n🎉 ML-ENHANCED SCAN COMPLETE!")
        logger.warning(f"📊 Total vulnerabilities: {total_vulns}")
        logger.warning(f"💾 All findings stored in database → visible in dashboard")
        
    async def _ml_reflection_phase(self, url: str, session: aiohttp.ClientSession):
        """ML-powered reflection analysis phase"""
        try:
            # Extract parameters from URL
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            if parsed.query:
                params = list(parse_qs(parsed.query).keys())
                
                logger.info(f"🧠 ML REFLECTION: Analyzing {len(params)} parameters")
                
                for param in params[:3]:  # Analyze top 3 parameters
                    logger.info(f"🔬 ML analyzing parameter: {param}")
                    
                    # Run ML reflection analysis
                    mutations = await self.ml_engine.analyze_reflection_comprehensive(
                        url, param, session, self.config.get('auth_cookie')
                    )
                    
                    # Convert high-scoring mutations to vulnerability findings
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
                                impact_description=f"ML-identified {mutation.mutation_type} vulnerability",
                                affected_parameter=param
                            )
                            
                            # Store ML finding
                            await self._store_single_finding(url, finding)
                            logger.warning(f"🧠 ML FOUND: {mutation.mutation_type} in {param} (Score: {mutation.success_probability:.2f})")
                            
        except Exception as e:
            logger.debug(f"ML reflection analysis failed: {e}")
    
    async def _store_universal_findings(self, url: str, findings: List[VulnerabilityFinding]):
        """Store findings universally for ANY target"""
        try:
            # Create asset entry for target
            asset_id = self.asset_manager.add_asset(url, 200)
            
            # Store each finding
            for finding in findings:
                self.asset_manager.add_vulnerability_finding(finding, asset_id)
            
            logger.info(f"💾 Stored {len(findings)} vulnerabilities for {url}")
            
        except Exception as e:
            logger.error(f"Failed to store findings: {e}")
    
    async def _store_single_finding(self, url: str, finding: VulnerabilityFinding):
        """Store a single finding"""
        try:
            asset_id = self.asset_manager.add_asset(url, 200)
            self.asset_manager.add_vulnerability_finding(finding, asset_id)
        except Exception as e:
            logger.debug(f"Failed to store finding: {e}")
    
    async def scan_existing_assets_ml(self, limit: int = 5):
        """ML-enhanced scan of existing assets from database"""
        logger.warning(f"🧠 ML-Enhanced scan of existing assets (limit: {limit})")
        
        # Get assets from database universally
        assets = self.asset_manager.get_assets_ready_for_deep_scan(limit)
        if not assets:
            logger.warning("No assets available for ML scanning")
            return
        
        urls = [asset['url'] for asset in assets]
        logger.info(f"Found {len(urls)} assets for ML-enhanced scanning:")
        for url in urls:
            logger.info(f"  - {url}")
        
        await self.scan_urls_ml_enhanced(urls)

async def main():
    if len(sys.argv) < 2:
        print("🧠 ML-Enhanced Universal Vulnerability Scanner")
        print("Uses Machine Learning + SQLMap + Nuclei + FFuF + Dalfox + Reflection Analysis")
        print("🌍 UNIVERSAL: Works on ANY target without hardcoded assumptions")
        print()
        print("Usage:")
        print("  python ml_enhanced_scanner.py --existing [limit]   # Scan existing assets")  
        print("  python ml_enhanced_scanner.py <url1> [url2] ...    # Scan specific URLs")
        print()
        print("Examples:")
        print("  python ml_enhanced_scanner.py --existing 3")
        print("  python ml_enhanced_scanner.py https://target.com/vulnerable")
        print("  python ml_enhanced_scanner.py http://192.168.1.42/dvwa/vulnerabilities/sqli/?id=1")
        print("  python ml_enhanced_scanner.py https://bugbounty.target.com/search?q=test")
        sys.exit(1)
    
    scanner = MLEnhancedScanner()
    
    if sys.argv[1] == "--existing":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 5
        await scanner.scan_existing_assets_ml(limit)
    else:
        urls = sys.argv[1:]
        await scanner.scan_urls_ml_enhanced(urls)

if __name__ == "__main__":
    asyncio.run(main())