#!/usr/bin/env python3
"""
Test vulnerability scanning on a specific URL
"""

import asyncio
import aiohttp
import logging
from modules.vulnerability_scanner import VulnerabilityScanner
from asset_manager import AssetManager
from modules.auth_manager import AuthManager

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def test_vuln_scan(target_url: str):
    """Test vulnerability scanning on a specific URL"""
    
    # Set gentle scanning to avoid overwhelming target
    import os
    os.environ['MODSCAN_MAX_CONCURRENCY'] = '3'
    os.environ['MODSCAN_TIMEOUT'] = '10'
    
    # Initialize components
    asset_manager = AssetManager()
    auth_manager = AuthManager(asset_manager, {})
    
    # Create a mock asset dict like the engine would
    asset = {
        'url': target_url,
        'status_code': 200,
        'title': 'Test Target',
        'tech_stack': 'Apache,PHP',
        'content_type': 'text/html',
        'content_length': 1000
    }
    
    # Initialize vulnerability scanner
    config = {'blind_xss_domain': 'test.local'}
    vuln_scanner = VulnerabilityScanner(asset_manager, config)
    
    print(f"🎯 Testing vulnerability scan on: {target_url}")
    
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(limit=100, limit_per_host=10)
        ) as session:
            
            # Run vulnerability scan on single asset (gentle: only 2 concurrent requests)
            findings = await vuln_scanner._scan_single_asset_enhanced(asset, session, asyncio.Semaphore(2))
            
            print(f"\n✅ Scan completed! Found {len(findings)} potential vulnerabilities:")
            
            for i, finding in enumerate(findings, 1):
                print(f"\n[{i}] {finding.vuln_type} ({finding.severity})")
                print(f"    URL: {finding.url}")
                print(f"    Confidence: {finding.confidence:.2f}")
                print(f"    Payload: {finding.payload[:100]}{'...' if len(finding.payload) > 100 else ''}")
                print(f"    Evidence: {finding.evidence[:100]}{'...' if len(finding.evidence) > 100 else ''}")
                
                # Save to database
                asset_id = asset_manager.add_asset(
                    url=target_url,
                    domain=target_url.split('/')[2] if '://' in target_url else target_url.split('/')[0],
                    status_code=200,
                    title='Test Target'
                )
                asset_manager.add_vulnerability_finding(finding, asset_id)
            
            if not findings:
                print("ℹ️ No vulnerabilities found with current payloads.")
                
    except Exception as e:
        logger.error(f"Error during vulnerability scan: {e}")
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python test_vuln_scan.py <URL>")
        print("Example: python test_vuln_scan.py http://192.168.1.42/dvwa/vulnerabilities/sqli/")
        sys.exit(1)
    
    target_url = sys.argv[1]
    asyncio.run(test_vuln_scan(target_url))