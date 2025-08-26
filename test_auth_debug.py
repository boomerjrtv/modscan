#!/usr/bin/env python3
"""
Test authentication cookie loading and usage
"""
import asyncio
import aiohttp
from enhanced_direct_scan import EnhancedDirectScanner

async def test_auth():
    scanner = EnhancedDirectScanner()
    
    # Check if auth cookie was loaded
    print(f"🔐 Auth cookie loaded: {scanner.config.get('auth_cookie', 'NOT FOUND')}")
    print(f"🔐 Enhanced scanner auth: {scanner.enhanced_scanner.auth_cookie}")
    
    # Test a simple HTTP request with auth
    test_url = "http://192.168.1.42/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"
    
    async with aiohttp.ClientSession() as session:
        headers = {}
        if scanner.config.get('auth_cookie'):
            headers['Cookie'] = scanner.config['auth_cookie']
            print(f"🍪 Using cookie: {headers['Cookie']}")
        
        async with session.get(test_url, headers=headers) as response:
            content = await response.text()
            print(f"📄 Response status: {response.status}")
            print(f"📄 Content preview: {content[:200]}...")
            
            # Check if we're getting the login page or the actual vulnerable page
            if "login" in content.lower():
                print("❌ Getting login page - authentication failed")
            elif "user id" in content.lower() or "submit" in content.lower():
                print("✅ Getting vulnerable page - authentication working")
            else:
                print("❓ Unknown page content")

if __name__ == "__main__":
    asyncio.run(test_auth())