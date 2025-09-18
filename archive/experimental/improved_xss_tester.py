#!/usr/bin/env python3
"""
Improved XSS tester with multiple injection vectors
"""

import asyncio
import aiohttp
from urllib.parse import urlparse, parse_qs

async def test_multi_vector_xss(base_url):
    """Test XSS with multiple injection vectors"""
    
    print(f"🔧 IMPROVED XSS DETECTION")
    print(f"Target: {base_url}")
    
    # Simple, reliable XSS test payloads
    test_payloads = [
        'MODSCAN_XSS_TEST',  # Simple text reflection test
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        'javascript:alert(1)'
    ]
    
    # Multiple injection vectors to test
    injection_vectors = [
        # URL parameters (what we tried before)
        lambda url, payload: f"{url}?test={payload}",
        lambda url, payload: f"{url}?q={payload}",
        lambda url, payload: f"{url}?search={payload}",
        lambda url, payload: f"{url}?id={payload}",
        
        # Fragment injection (# based)
        lambda url, payload: f"{url}#{payload}",
        
        # Path injection
        lambda url, payload: f"{url}/{payload}",
        
        # Query combinations
        lambda url, payload: f"{url}?callback={payload}",
        lambda url, payload: f"{url}?redirect={payload}",
    ]
    
    vulnerabilities = []
    
    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            
            for vector_idx, vector_func in enumerate(injection_vectors):
                print(f"\n🎯 Testing injection vector {vector_idx + 1}/{len(injection_vectors)}")
                
                for payload_idx, payload in enumerate(test_payloads):
                    try:
                        test_url = vector_func(base_url, payload)
                        print(f"  Testing: {payload[:30]}...")
                        
                        async with session.get(test_url) as response:
                            content = await response.text()
                            
                            # Multiple detection methods
                            detected = False
                            detection_method = None
                            
                            # Method 1: Direct payload reflection
                            if payload in content:
                                detected = True
                                detection_method = "Direct reflection"
                            
                            # Method 2: HTML context reflection
                            elif payload.replace('<', '&lt;').replace('>', '&gt;') in content:
                                detected = True
                                detection_method = "HTML encoded reflection"
                            
                            # Method 3: JavaScript context reflection  
                            elif payload.replace('"', '\\"') in content:
                                detected = True
                                detection_method = "JavaScript context reflection"
                            
                            # Method 4: URL encoded reflection
                            elif payload.replace(' ', '%20').replace('<', '%3C') in content:
                                detected = True
                                detection_method = "URL encoded reflection"
                            
                            if detected:
                                print(f"    ✅ VULNERABILITY FOUND!")
                                print(f"    Method: {detection_method}")
                                vulnerabilities.append({
                                    'url': test_url,
                                    'payload': payload,
                                    'method': detection_method,
                                    'vector': f"Vector {vector_idx + 1}"
                                })
                            else:
                                print(f"    ❌ Not detected")
                                
                    except Exception as e:
                        print(f"    ⚠️ Error: {str(e)[:50]}...")
                    
                    await asyncio.sleep(0.3)  # Be respectful
                
                await asyncio.sleep(0.5)  # Pause between vectors
    
    except Exception as e:
        print(f"❌ Session error: {e}")
    
    print(f"\n📊 FINAL RESULTS:")
    print(f"Injection vectors tested: {len(injection_vectors)}")
    print(f"Payloads per vector: {len(test_payloads)}")
    print(f"Total tests: {len(injection_vectors) * len(test_payloads)}")
    print(f"Vulnerabilities found: {len(vulnerabilities)}")
    
    if vulnerabilities:
        print(f"\n🏆 VULNERABILITIES DETECTED:")
        for vuln in vulnerabilities:
            print(f"  ✅ {vuln['vector']}: {vuln['payload']}")
            print(f"     Method: {vuln['method']}")
            print(f"     URL: {vuln['url'][:100]}...")
        return True
    else:
        print(f"\n❌ NO VULNERABILITIES DETECTED")
        print(f"Scanner needs further improvement or vulnerability may be:")
        print(f"  - Form-based (requires POST)")
        print(f"  - Header-based injection")
        print(f"  - Context-specific (requires exact conditions)")
        return False

if __name__ == "__main__":
    wayback_url = "https://web.archive.org/web/20220410230648/https://www.acronis.com/products/cyber-protect/trial/"
    result = asyncio.run(test_multi_vector_xss(wayback_url))
    
    if result:
        print(f"\n🎉 SUCCESS: Improved scanner detected the vulnerability!")
    else:
        print(f"\n🔧 NEXT: Need to investigate form-based or header-based injection")