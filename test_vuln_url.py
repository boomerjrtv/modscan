#!/usr/bin/env python3
"""
Quick URL Vulnerability Tester
Test specific URLs with our enhanced vulnerability scanner
"""
import asyncio
import aiohttp
import sys
import time
from datetime import datetime

# Add current directory to path
sys.path.append('.')

from modules.vulnerability_scanner import VulnerabilityScanner
from asset_manager import AssetManager, VulnerabilityFinding

async def test_url_vulnerabilities(url, auth_cookies=None):
    """Test a specific URL for vulnerabilities"""
    
    print(f"🎯 Testing URL: {url}")
    print("=" * 60)
    
    # Initialize components
    am = AssetManager()
    config = {'blind_xss_domain': 'test.ngrok.io'}
    scanner = VulnerabilityScanner(am, config)
    
    # Create session with optional authentication
    session_kwargs = {'timeout': aiohttp.ClientTimeout(total=30)}
    if auth_cookies:
        session_kwargs['cookies'] = auth_cookies
        print(f"🔐 Using authentication cookies: {list(auth_cookies.keys())}")
    
    total_findings = 0
    
    async with aiohttp.ClientSession(**session_kwargs) as session:
        
        print("\n1. Testing SQL Injection...")
        try:
            sql_findings = await scanner._test_sql_injection(url, session)
            if sql_findings:
                print(f"   ✅ Found {len(sql_findings)} SQL injection vulnerabilities!")
                for finding in sql_findings:
                    print(f"      {finding.vuln_type}: {finding.severity} (confidence: {finding.confidence:.3f})")
                    print(f"      Payload: {finding.payload}")
                    print(f"      Evidence: {finding.evidence[:80]}...")
                total_findings += len(sql_findings)
            else:
                print("   ❌ No SQL injection found")
        except Exception as e:
            print(f"   ⚠️  SQL injection test error: {e}")
        
        print("\n2. Testing XSS...")
        try:
            xss_findings = await scanner._test_xss_vulnerabilities(url, session)
            if xss_findings:
                print(f"   ✅ Found {len(xss_findings)} XSS vulnerabilities!")
                for finding in xss_findings:
                    print(f"      {finding.vuln_type}: {finding.severity} (confidence: {finding.confidence:.3f})")
                    print(f"      Payload: {finding.payload}")
                total_findings += len(xss_findings)
            else:
                print("   ❌ No XSS found")
        except Exception as e:
            print(f"   ⚠️  XSS test error: {e}")
        
        print("\n3. Testing Command Injection...")
        try:
            cmd_findings = await scanner._test_command_injection(url, session)
            if cmd_findings:
                print(f"   ✅ Found {len(cmd_findings)} command injection vulnerabilities!")
                total_findings += len(cmd_findings)
            else:
                print("   ❌ No command injection found")
        except Exception as e:
            print(f"   ⚠️  Command injection test error: {e}")
        
        print("\n4. Testing Path Traversal...")
        try:
            path_findings = await scanner._test_path_traversal(url, session)
            if path_findings:
                print(f"   ✅ Found {len(path_findings)} path traversal vulnerabilities!")
                total_findings += len(path_findings)
            else:
                print("   ❌ No path traversal found")
        except Exception as e:
            print(f"   ⚠️  Path traversal test error: {e}")
        
        # Blind SQLi testing for URLs containing 'sqli_blind'
        if 'sqli_blind' in url.lower():
            print("\n5. Testing Blind SQL Injection...")
            await test_blind_sqli(url, session)

    print(f"\n📊 TESTING COMPLETE!")
    print(f"   Total vulnerabilities found: {total_findings}")

async def test_blind_sqli(url, session):
    """Test for blind SQL injection"""
    print("   🕵️  Testing blind SQLi techniques...")
    
    # Time-based blind SQLi test
    time_payloads = [
        "1' AND SLEEP(3)--",
        "1' OR SLEEP(3)--", 
        "1'; WAITFOR DELAY '0:0:3'--"
    ]
    
    for payload in time_payloads:
        params = {'id': payload, 'Submit': 'Submit'}
        try:
            start_time = time.time()
            async with session.get(url, params=params) as resp:
                elapsed = time.time() - start_time
                
                if elapsed > 2.5:  # Delayed response indicates time-based SQLi
                    print(f"   ✅ TIME-BASED BLIND SQLi DETECTED!")
                    print(f"      Payload: {payload}")
                    print(f"      Response time: {elapsed:.2f}s")
                    return
                    
        except Exception as e:
            print(f"   ⚠️  Error testing {payload}: {e}")
    
    print("   ❌ No blind SQLi detected")

def main():
    """Main function for command line usage"""
    if len(sys.argv) < 2:
        print("Usage: python test_vuln_url.py <URL> [cookie_string]")
        print("\nExamples:")
        print("  python test_vuln_url.py http://example.com/login.php")
        print("  python test_vuln_url.py http://192.168.1.42/dvwa/vulnerabilities/sqli/ 'PHPSESSID=abc123; security=low'")
        sys.exit(1)
    
    url = sys.argv[1]
    
    # Parse optional cookie string
    auth_cookies = None
    if len(sys.argv) > 2:
        cookie_string = sys.argv[2]
        auth_cookies = {}
        for cookie in cookie_string.split(';'):
            if '=' in cookie:
                name, value = cookie.strip().split('=', 1)
                auth_cookies[name] = value
    
    # Run the test
    asyncio.run(test_url_vulnerabilities(url, auth_cookies))

if __name__ == "__main__":
    main()