#!/usr/bin/env python3
"""
Direct SQL Injection Test - Simple validation of aggressive methods
This bypasses all the complex scanner infrastructure to test core functionality
"""

import asyncio
import aiohttp
import sys
sys.path.insert(0, '/home/michael/recon-platform/modscan')

from modules.vulnerability_scanner import VulnerabilityScanner
from asset_manager import AssetManager

async def test_direct_sqli():
    """Test aggressive SQL injection directly"""
    print("🧪 DIRECT SQL INJECTION TEST")
    
    # URLs to test
    test_urls = [
        "http://192.168.1.42/dvwa/vulnerabilities/sqli/",
        "http://192.168.1.42/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"
    ]
    
    # Initialize components
    asset_manager = AssetManager()
    scanner = VulnerabilityScanner(asset_manager)
    await scanner.initialize()
    
    async with aiohttp.ClientSession() as session:
        for url in test_urls:
            print(f"\n📍 TESTING: {url}")
            
            # Test our aggressive SQL injection method directly
            try:
                findings = await scanner._test_sql_injection(url, session)
                print(f"✅ SQL Injection findings: {len(findings)}")
                
                for finding in findings:
                    print(f"  - Type: {finding.vuln_type}")
                    print(f"  - Severity: {finding.severity}")
                    print(f"  - Evidence: {finding.evidence[:100]}...")
                    
            except Exception as e:
                print(f"❌ Error testing {url}: {e}")
                import traceback
                traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_direct_sqli())