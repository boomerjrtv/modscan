#!/usr/bin/env python3
"""
Enhanced Direct Vulnerability Scanner
Uses SQLMap, Nuclei, FFuF, Dalfox and other powerful tools for real vulnerability detection
"""
import asyncio
import aiohttp
import sys
import json
from typing import List, Dict
import logging

# Import required modules
from asset_manager import AssetManager, VulnerabilityFinding
from modules.enhanced_vuln_scanner import EnhancedVulnerabilityScanner

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')
logger = logging.getLogger(__name__)

class EnhancedDirectScanner:
    def __init__(self):
        # Initialize AssetManager
        self.asset_manager = AssetManager()
        
        # Load config
        try:
            with open('config.json', 'r') as f:
                self.config = json.load(f)
        except:
            self.config = {}
        
        # Check for auth cookies in database
        self._load_auth_cookies()
        
        # Initialize Enhanced Vulnerability Scanner
        self.enhanced_scanner = EnhancedVulnerabilityScanner(self.asset_manager, self.config)
        
    def _load_auth_cookies(self):
        """Load authentication cookies from database - UNIVERSAL for any target"""
        try:
            import sqlite3
            with sqlite3.connect(self.asset_manager.db_path) as db:
                cursor = db.execute("SELECT domain, cookie FROM cookies ORDER BY last_updated DESC LIMIT 1")
                cookie_data = cursor.fetchone()
                if cookie_data:
                    domain, cookie_value = cookie_data
                    self.config['auth_cookie'] = cookie_value
                    logger.info(f"🔐 Loaded auth cookie for {domain}: {cookie_value[:30]}...")
                else:
                    logger.info("ℹ️ No authentication cookies found - scanning unauthenticated")
        except Exception as e:
            logger.debug(f"No auth cookies available: {e}")
    
    async def scan_urls_enhanced(self, urls: List[str]):
        """Scan URLs using enhanced tools (SQLMap, Nuclei, FFuF, Dalfox)"""
        logger.warning(f"🚀 ENHANCED DIRECT SCAN: Starting comprehensive scan of {len(urls)} URLs")
        logger.warning(f"🛠️  Using: SQLMap, Nuclei, FFuF, Dalfox, Directory Fuzzing")
        
        total_vulns = 0
        
        async with aiohttp.ClientSession() as session:
            for url in urls:
                logger.warning(f"\n🎯 SCANNING: {url}")
                
                # Run comprehensive enhanced scan
                findings = await self.enhanced_scanner.scan_url_comprehensive(url, session)
                
                if findings:
                    # Store findings in database
                    asset_id = self.asset_manager.add_asset(url, 200)  # Assume accessible
                    
                    for finding in findings:
                        self.asset_manager.add_vulnerability_finding(finding, asset_id)
                        logger.error(f"🚨 VULNERABILITY FOUND:")
                        logger.error(f"   Type: {finding.vuln_type}")
                        logger.error(f"   Severity: {finding.severity}")
                        logger.error(f"   URL: {finding.url}")
                        logger.error(f"   Payload: {finding.payload}")
                        logger.error(f"   Evidence: {finding.evidence[:200]}...")
                        if finding.affected_parameter:
                            logger.error(f"   Parameter: {finding.affected_parameter}")
                    
                    total_vulns += len(findings)
                else:
                    logger.info(f"   ✅ No vulnerabilities found in {url}")
        
        logger.warning(f"\n🎉 ENHANCED SCAN COMPLETE!")
        logger.warning(f"📊 Total vulnerabilities found: {total_vulns}")
        logger.warning(f"💾 All findings stored in database and visible in dashboard")
        
    async def scan_existing_assets_enhanced(self, limit: int = 5):
        """Scan existing assets with enhanced tools"""
        logger.warning(f"🎯 Enhanced scanning of existing assets from database (limit: {limit})")
        
        # Get assets ready for scanning
        assets = self.asset_manager.get_assets_ready_for_deep_scan(limit)
        if not assets:
            logger.warning("No assets ready for enhanced scanning")
            return
        
        urls = [asset['url'] for asset in assets]
        logger.info(f"Found {len(urls)} assets for enhanced scanning:")
        for url in urls:
            logger.info(f"  - {url}")
        
        await self.scan_urls_enhanced(urls)

async def main():
    if len(sys.argv) < 2:
        print("🚀 Enhanced Direct Vulnerability Scanner")
        print("Uses SQLMap, Nuclei, FFuF, Dalfox, and directory fuzzing")
        print()
        print("Usage:")
        print("  python enhanced_direct_scan.py --existing [limit]   # Scan existing assets")
        print("  python enhanced_direct_scan.py <url1> [url2] ...    # Scan specific URLs")
        print()
        print("Examples:")
        print("  python enhanced_direct_scan.py --existing 3")
        print("  python enhanced_direct_scan.py http://192.168.1.42/dvwa/vulnerabilities/sqli/")
        print("  python enhanced_direct_scan.py http://target.com/login.php http://target.com/admin/")
        sys.exit(1)
    
    scanner = EnhancedDirectScanner()
    
    if sys.argv[1] == "--existing":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 5
        await scanner.scan_existing_assets_enhanced(limit)
    else:
        urls = sys.argv[1:]
        await scanner.scan_urls_enhanced(urls)

if __name__ == "__main__":
    asyncio.run(main())