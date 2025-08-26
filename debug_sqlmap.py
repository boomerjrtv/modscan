#!/usr/bin/env python3
"""
Debug SQLMap output to see why vulnerabilities aren't being detected
"""
import asyncio
import subprocess
import json

async def test_sqlmap():
    url = "http://192.168.1.42/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"
    auth_cookie = "PHPSESSID=tppij2lpok3cv2l1vjfu52bf2p; security=low"
    
    cmd = [
        'sqlmap',
        '-u', url,
        '--batch',
        '--random-agent',
        '--threads', '2',
        '--timeout', '20',
        '--retries', '1',
        '--level', '3',
        '--risk', '2',
        '--technique', 'BEUST',
        '--no-cast',
        '--ignore-code', '404',
        '--cookie', auth_cookie,
        '-p', 'id'
    ]
    
    print(f"🧪 Running SQLMap debug test:")
    print(f"URL: {url}")
    print(f"Cookie: {auth_cookie}")
    print(f"Command: {' '.join(cmd)}")
    print("-" * 80)
    
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=90)
        
        output = stdout.decode('utf-8', errors='ignore')
        error = stderr.decode('utf-8', errors='ignore')
        
        print("📤 STDOUT:")
        print(output)
        print("\n📥 STDERR:")
        print(error)
        print("\n🔍 ANALYSIS:")
        
        # Check for vulnerability indicators
        indicators = ['injectable', 'vulnerable', 'injection', 'parameter', 'payload']
        for indicator in indicators:
            if indicator.lower() in output.lower():
                print(f"✅ Found indicator '{indicator}' in output")
            else:
                print(f"❌ Missing indicator '{indicator}' in output")
        
        print(f"\n⚙️ Process return code: {process.returncode}")
        
    except Exception as e:
        print(f"❌ SQLMap test failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_sqlmap())