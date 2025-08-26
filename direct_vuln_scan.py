#!/usr/bin/env python3
"""
Direct URL Vulnerability Scanner
Skips asset discovery and goes straight to vulnerability testing
"""
import asyncio
import aiohttp
import sys
import json
from typing import List, Dict
import logging

# Import required modules
from asset_manager import AssetManager, VulnerabilityFinding
from modules.vulnerability_scanner import VulnerabilityScanner

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DirectVulnScanner:
    def __init__(self):
        # Initialize AssetManager (uses config.json database_path)
        self.asset_manager = AssetManager()
        
        # Load config
        try:
            with open('config.json', 'r') as f:
                self.config = json.load(f)
        except:
            self.config = {}
            
        # Initialize VulnerabilityScanner
        self.vuln_scanner = VulnerabilityScanner(self.asset_manager, self.config)
        
    async def scan_existing_assets(self, limit: int = 10):
        """Scan existing assets from database"""
        logger.info(f"🎯 Scanning existing assets from database (limit: {limit})")
        
        # Get assets ready for scanning
        assets = self.asset_manager.get_assets_ready_for_deep_scan(limit)
        if not assets:
            logger.warning("No assets ready for scanning")
            return []
        
        logger.info(f"Found {len(assets)} assets ready for scanning")
        for asset in assets[:3]:  # Show first 3
            logger.info(f"  - {asset['url']}")
        
        async with aiohttp.ClientSession() as session:
            # Run vulnerability scan directly
            results = await self.vuln_scanner.scan_assets_for_vulnerabilities(
                assets, session, semaphore_limit=50
            )
            
            # Process results
            total_vulns = 0
            for asset_findings in results:
                if asset_findings:
                    total_vulns += len(asset_findings)
                    for finding in asset_findings:
                        logger.warning(f"🚨 VULN: {finding.vuln_type} at {finding.url}")
                        logger.info(f"   Severity: {finding.severity}")
                        logger.info(f"   Payload: {finding.payload}")
                        logger.info(f"   Evidence: {finding.evidence[:100]}...")
            
            logger.info(f"✅ Scan complete: {total_vulns} vulnerabilities found")
            return results

    async def scan_urls_direct(self, urls: List[str]):
        """Scan URLs directly without discovery phase"""
        logger.info(f"🎯 Direct vulnerability scanning {len(urls)} URLs")
        
        # Create asset objects for the vulnerability scanner
        assets = []
        for url in urls:
            assets.append({
                'id': len(assets) + 1,
                'url': url,
                'status_code': 200,  # Assume accessible
                'tech_stack': ''     # Will be detected during scanning
            })
        
        async with aiohttp.ClientSession() as session:
            # Run vulnerability scan directly
            results = await self.vuln_scanner.scan_assets_for_vulnerabilities(
                assets, session, semaphore_limit=50
            )
            
            # Process results
            total_vulns = 0
            for asset_findings in results:
                if asset_findings:
                    total_vulns += len(asset_findings)
                    for finding in asset_findings:
                        logger.warning(f"🚨 VULN: {finding.vuln_type} at {finding.url}")
                        logger.info(f"   Payload: {finding.payload}")
                        logger.info(f"   Evidence: {finding.evidence[:100]}...")
            
            logger.info(f"✅ Direct scan complete: {total_vulns} vulnerabilities found")
            return results

async def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python direct_vuln_scan.py --existing [limit]   # Scan existing assets from DB")
        print("  python direct_vuln_scan.py <url1> [url2] ...    # Scan specific URLs")
        print("Examples:")
        print("  python direct_vuln_scan.py --existing 5")
        print("  python direct_vuln_scan.py http://192.168.1.42/dvwa/vulnerabilities/sqli/")
        sys.exit(1)
    
    scanner = DirectVulnScanner()
    
    if sys.argv[1] == "--existing":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 10
        await scanner.scan_existing_assets(limit)
    else:
        urls = sys.argv[1:]
        await scanner.scan_urls_direct(urls)

if __name__ == "__main__":
    asyncio.run(main())