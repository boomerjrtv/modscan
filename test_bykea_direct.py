#!/usr/bin/env python3
"""
Direct test of Bykea domains with our enhanced bypass capabilities
This bypasses the engine complexity and tests the actual bypass functionality
"""

import asyncio
import aiohttp
import json
import logging
from modules.http_bypass import SmartRequester

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_bykea_direct():
    """Test Bykea domains directly with all bypass techniques"""

    # Load proxy config
    try:
        with open('config.json') as f:
            config = json.load(f)
        proxy_list = config.get('proxy_list', [])  # Use ALL 30 proxies
        logger.info(f"🔗 Using ALL {len(proxy_list)} proxies for maximum bypass power")
    except:
        proxy_list = []
        logger.info("⚠️  No proxies available - using direct connection")

    # Test targets from bug bounty scope
    targets = [
        'https://api.bykea.net',
        'https://kronos.bykea.net',
        'https://api.bykea.net/health',
        'https://api.bykea.net/api',
        'https://api.bykea.net/v1/auth/login',
        'https://api.bykea.net/swagger',
        'https://api.bykea.net/docs',
        'https://kronos.bykea.net/admin',
        'https://kronos.bykea.net/api',
        'https://kronos.bykea.net/health'
    ]

    results = []

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        smart_req = SmartRequester(session, default_timeout=15.0, proxy_list=proxy_list)

        for target in targets:
            logger.info(f"🎯 Testing {target}")

            try:
                # Test with our enhanced SmartRequester (200+ bypass techniques)
                response, content, bypass_method = await smart_req.request(
                    'GET',
                    target,
                    timeout=15,
                    max_attempts=20  # Try more bypass attempts
                )

                result = {
                    'url': target,
                    'status': response.status,
                    'server': response.headers.get('Server', 'Unknown'),
                    'cf_ray': response.headers.get('CF-Ray', 'None'),
                    'content_length': len(content) if content else 0,
                    'bypass_method': bypass_method,
                    'headers': dict(response.headers)
                }

                results.append(result)

                print(f"📊 {target}")
                print(f"   Status: {response.status}")
                print(f"   Server: {response.headers.get('Server', 'Unknown')}")

                if bypass_method:
                    print(f"   🎯 BYPASS: {bypass_method}")

                if response.status == 200:
                    print(f"   ✅ SUCCESS! Got through Cloudflare!")
                    if content and 0 < len(content) < 2000:
                        preview = content[:500].decode('utf-8', errors='ignore')
                        print(f"   Content: {preview}...")
                elif response.status == 403:
                    print(f"   🚫 403 FORBIDDEN - Cloudflare blocked all attempts")
                elif response.status in [301, 302]:
                    location = response.headers.get('Location', 'None')
                    print(f"   🔄 REDIRECT to: {location}")
                else:
                    print(f"   ⚠️  Unexpected status: {response.status}")

                print()

            except asyncio.TimeoutError:
                print(f"   ⏰ TIMEOUT after 15 seconds")
                results.append({'url': target, 'status': 'TIMEOUT', 'error': 'Request timeout'})
            except Exception as e:
                print(f"   ❌ ERROR: {e}")
                results.append({'url': target, 'status': 'ERROR', 'error': str(e)})

    # Summary
    print("=" * 80)
    print("🏆 BYKEA BYPASS TEST SUMMARY")
    print("=" * 80)

    successful_bypasses = [r for r in results if r.get('status') == 200]
    blocked_requests = [r for r in results if r.get('status') == 403]

    print(f"✅ Successful bypasses: {len(successful_bypasses)}")
    print(f"🚫 Blocked requests: {len(blocked_requests)}")
    print(f"📊 Total tests: {len(results)}")

    if successful_bypasses:
        print("\n🎯 SUCCESSFUL BYPASS METHODS:")
        for r in successful_bypasses:
            print(f"   {r['url']} -> {r.get('bypass_method', 'Direct')}")

    # Write results to file for analysis
    with open('bykea_test_results.json', 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n📄 Detailed results saved to bykea_test_results.json")

    return results

if __name__ == "__main__":
    asyncio.run(test_bykea_direct())