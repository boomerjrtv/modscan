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
    # Flexible inputs: argv, --file, or stdin
    args = sys.argv[1:]
    urls: List[str] = []
    if not args:
        data = sys.stdin.read()
        if data:
            urls = [u.strip() for u in data.replace('\r','\n').split('\n') if u.strip()]
        else:
            print("Usage:")
            print("  python direct_vuln_scan.py --existing [limit]   # Scan existing assets from DB")
            print("  python direct_vuln_scan.py --file urls.txt      # One URL per line")
            print("  python direct_vuln_scan.py <url1> [url2] ...    # Scan specific URLs")
            sys.exit(1)
    elif args and args[0] == '--file' and len(args) > 1:
        with open(args[1], 'r') as f:
            urls = [l.strip() for l in f if l.strip()]
    elif args and args[0] == '--existing':
        limit = int(args[1]) if len(args) > 1 else 10
        scanner = DirectVulnScanner()
        await scanner.scan_existing_assets(limit)
        return
    else:
        urls = [a for a in args if a.startswith('http')]
    
    scanner = DirectVulnScanner()
    await scanner.scan_urls_direct(urls)

if __name__ == "__main__":
    asyncio.run(main())
