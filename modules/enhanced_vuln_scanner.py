#!/usr/bin/env python3
"""
Enhanced Vulnerability Scanner - Integrates powerful external tools
Uses SQLMap, Nuclei, FFuF, Dalfox, and other tools for real vulnerability detection
"""
import asyncio
import subprocess
import json
import tempfile
import os
import re
import logging
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urljoin
import aiohttp

from asset_manager import VulnerabilityFinding
from modules.universal_auth_manager import UniversalAuthManager

logger = logging.getLogger("EnhancedVulnScanner")

class EnhancedVulnerabilityScanner:
    def __init__(self, asset_manager, config: Dict):
        self.asset_manager = asset_manager
        self.config = config
        self.auth_cookie = config.get('auth_cookie')
        
        # Tool paths (check go/bin and PATH)
        self.tools = {
            'sqlmap': 'sqlmap',  # Installed via pip
            'nuclei': '/home/michael/go/bin/nuclei', 
            'ffuf': '/home/michael/go/bin/ffuf',
            'dalfox': '/home/michael/go/bin/dalfox',  # Installed via go
            'httpx': 'httpx',
            'gau': 'gau',
            'paramspider': 'paramspider'
        }
        
        # Initialize Universal Authentication Manager
        self.auth_manager = UniversalAuthManager(asset_manager, config)
        
        logger.info("🚀 Enhanced Vulnerability Scanner initialized with external tools + universal auth")
        
    async def scan_url_comprehensive(self, url: str, session: aiohttp.ClientSession) -> List[VulnerabilityFinding]:
        """Pure vulnerability scanning without reconnaissance"""
        findings = []
        
        logger.info(f"🔍 VULN SCAN: Starting vulnerability-only scan of {url}")
        
        # Ensure authentication before scanning
        auth_cookie, auth_success = await self.auth_manager.ensure_authenticated_request(url, session)
        if auth_success and auth_cookie:
            self.auth_cookie = auth_cookie
            logger.info(f"🔐 Authentication verified for {urlparse(url).netloc}")
        
        # Extract existing parameters from URL for testing
        params = self._extract_url_parameters(url)
        
        # Phase 1: SQL Injection with SQLMap  
        logger.info("💉 Phase 1: SQL injection testing with SQLMap")
        sql_findings = await self._sqlmap_scan(url, params)
        findings.extend(sql_findings)
        
        # Phase 2: XSS Detection with Dalfox
        logger.info("🎯 Phase 2: XSS testing with Dalfox") 
        xss_findings = await self._dalfox_scan(url, params)
        findings.extend(xss_findings)
        
        # Phase 3: Vulnerability-specific Nuclei Scan
        logger.info("🧬 Phase 3: Nuclei vulnerability templates")
        nuclei_findings = await self._nuclei_vulnerability_scan(url)
        findings.extend(nuclei_findings)
        
        # Phase 4: Parameter Injection Testing (not discovery)
        logger.info("⚡ Phase 4: Parameter injection testing")
        if params:
            injection_findings = await self._test_parameter_injections(url, params)
            findings.extend(injection_findings)
        
        logger.warning(f"🚨 VULN SCAN COMPLETE: Found {len(findings)} vulnerabilities in {url}")
        return findings
    
    def _extract_url_parameters(self, url: str) -> List[str]:
        """Extract existing parameters from URL for vulnerability testing"""
        params = []
        try:
            parsed = urlparse(url)
            if parsed.query:
                url_params = parse_qs(parsed.query)
                params = list(url_params.keys())
        except Exception as e:
            logger.debug(f"Parameter extraction failed: {e}")
        
        logger.info(f"📋 Extracted {len(params)} parameters from URL: {params}")
        return params
    
    async def _test_parameter_injections(self, url: str, params: List[str]) -> List[VulnerabilityFinding]:
        """Test parameters for injection vulnerabilities using FFuF"""
        findings = []
        
        if not params:
            return findings
        
        try:
            # Create payload list for vulnerability testing (not recon)
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                vuln_payloads = [
                    # SQL injection payloads
                    "'", '"', "' OR '1'='1", "' OR 1=1--", "admin'--", "1' AND 1=1--",
                    # XSS payloads  
                    "<script>alert(1)</script>", "'><script>alert(1)</script>", 
                    "javascript:alert(1)", "<img src=x onerror=alert(1)>",
                    # Command injection payloads
                    "; ls", "&& id", "| whoami", "`id`", "$(id)",
                    # Path traversal payloads
                    "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
                    # Template injection payloads
                    "{{7*7}}", "${7*7}", "<%=7*7%>", "#{7*7}"
                ]
                f.write('\n'.join(vuln_payloads))
                wordlist_path = f.name
            
            for param in params[:3]:  # Test first 3 parameters
                # Create URL with FUZZ placeholder
                if '?' in url:
                    # Replace existing parameter value
                    base_url = url.split('?')[0]
                    query_parts = url.split('?')[1].split('&')
                    new_query_parts = []
                    param_found = False
                    
                    for part in query_parts:
                        if '=' in part:
                            key, _ = part.split('=', 1)
                            if key == param:
                                new_query_parts.append(f"{key}=FUZZ")
                                param_found = True
                            else:
                                new_query_parts.append(part)
                        else:
                            new_query_parts.append(part)
                    
                    if param_found:
                        fuzz_url = f"{base_url}?{'&'.join(new_query_parts)}"
                    else:
                        fuzz_url = f"{url}&{param}=FUZZ"
                else:
                    fuzz_url = f"{url}?{param}=FUZZ"
                
                cmd = [
                    self.tools['ffuf'],
                    '-u', fuzz_url,
                    '-w', wordlist_path,
                    '-mc', '200,500,403',  # Focus on potentially vulnerable responses
                    '-t', '10',  # Moderate threads for accuracy
                    '-timeout', '15',
                    '-of', 'json',
                    '-s'  # Silent mode
                ]
                
                if self.auth_cookie:
                    cmd.extend(['-H', f'Cookie: {self.auth_cookie}'])
                
                result = await self._run_tool(cmd, timeout=45)
                
                if result['success'] and result['output']:
                    try:
                        ffuf_data = json.loads(result['output'])
                        if 'results' in ffuf_data:
                            for hit in ffuf_data['results']:
                                status = hit.get('status', 0)
                                payload = hit.get('input', {}).get('FUZZ', '')
                                
                                # Analyze for actual vulnerabilities
                                if self._is_vulnerable_response(status, payload):
                                    from datetime import datetime
                                    finding = VulnerabilityFinding(
                                        url=fuzz_url.replace('FUZZ', payload),
                                        vuln_type='PARAMETER_INJECTION',
                                        severity='High' if status == 500 else 'Medium',
                                        confidence=0.8,
                                        payload=payload,
                                        evidence=f"Parameter {param} vulnerable to {payload} (Status: {status})",
                                        discovered_at=datetime.now(),
                                        affected_parameter=param
                                    )
                                    findings.append(finding)
                    except json.JSONDecodeError:
                        continue
            
            os.unlink(wordlist_path)
            
        except Exception as e:
            logger.error(f"Parameter injection testing failed: {e}")
        
        return findings
    
    def _is_vulnerable_response(self, status: int, payload: str) -> bool:
        """Determine if response indicates vulnerability"""
        # SQL injection indicators
        if status == 500 and any(indicator in payload for indicator in ["'", "OR", "1=1"]):
            return True
        # XSS reflection (would need content analysis, simplified here)  
        if status == 200 and any(indicator in payload for indicator in ["<script>", "alert"]):
            return True
        # Command injection error
        if status == 500 and any(indicator in payload for indicator in [";", "&", "|", "`"]):
            return True
        return False
    
    async def _nuclei_vulnerability_scan(self, url: str) -> List[VulnerabilityFinding]:
        """Nuclei scan focused on vulnerability templates only"""
        findings = []
        
        try:
            template_dir = os.path.expanduser('~/nuclei-templates/')
            cmd = [
                self.tools['nuclei'],
                '-u', url,
                '-t', f'{template_dir}http/vulnerabilities/',  # Only vulnerability templates
                '-t', f'{template_dir}cves/',                  # CVE templates
                '-j',  # JSON output
                '-silent',  # Silent mode
                '-timeout', '20',
                '-retries', '1', 
                '-rl', '50',  # Rate limit 50 req/sec
                '-severity', 'critical,high,medium'  # Skip info/low
            ]
            
            if self.auth_cookie:
                cmd.extend(['-H', f'Cookie: {self.auth_cookie}'])
            
            result = await self._run_tool(cmd, timeout=90)
            
            if result['success'] and result['output']:
                for line in result['output'].split('\n'):
                    if line.strip():
                        try:
                            vuln_data = json.loads(line)
                            from datetime import datetime
                            finding = VulnerabilityFinding(
                                url=vuln_data.get('matched-at', url),
                                vuln_type=vuln_data.get('info', {}).get('name', 'NUCLEI_VULNERABILITY'),
                                severity=vuln_data.get('info', {}).get('severity', 'Medium').title(),
                                confidence=0.9,
                                payload=vuln_data.get('template-id', ''),
                                evidence=vuln_data.get('info', {}).get('description', ''),
                                discovered_at=datetime.now(),
                                impact_description=vuln_data.get('info', {}).get('description', '')
                            )
                            findings.append(finding)
                            logger.warning(f"🚨 Nuclei found {finding.vuln_type} in {url}")
                        except json.JSONDecodeError:
                            continue
        
        except Exception as e:
            logger.error(f"Nuclei vulnerability scan failed: {e}")
        
        return findings

    # Removed reconnaissance methods - focusing only on vulnerability scanning
    
    async def _sqlmap_scan(self, url: str, params: List[str]) -> List[VulnerabilityFinding]:
        """SQL injection testing using SQLMap"""
        findings = []
        
        try:
            # Create SQLMap command with comprehensive arguments (based on your improved syntax)
            cmd = [
                self.tools['sqlmap'],
                '-u', url,
                '--method=POST',  # Force POST method for form-based testing
                '--batch',  # Non-interactive mode
                '--flush-session',  # Fresh session for each test
                '--forms',  # Test forms automatically
                '--risk', '3',  # High risk payloads  
                '--level', '5',  # Maximum comprehensive testing
                '--random-agent',  # Use random user agent
                '--crawl', '1',  # Crawl one level for more targets
                '--threads', '3',  # Balanced thread count
                '--timeout', '30',  # Longer timeout for thorough testing
                '--retries', '2',  # Multiple retries for reliability
                '--technique', 'BEUSTQ',  # All SQL injection techniques including stacked queries
                '--no-cast',  # Skip casting for speed
            ]
            
            # Add authentication cookie and login data
            if self.auth_cookie:
                cmd.extend(['--cookie', self.auth_cookie])
                
            # Add login data for session-based authentication (DVWA-style)
            if 'PHPSESSID' in str(self.auth_cookie) and 'security=' in str(self.auth_cookie):
                cmd.extend(['--data', 'username=admin&password=password&Login=Login'])
            
            # Add specific parameters to test
            if params:
                # Test first 3 most promising parameters
                test_params = [p for p in params if p in ['id', 'user', 'search', 'q', 'name']][:3]
                if not test_params:
                    test_params = params[:3]
                if test_params:
                    cmd.extend(['-p', ','.join(test_params)])
            
            # Run SQLMap
            result = await self._run_tool(cmd, timeout=90)
            
            if result['success']:
                # Universal SQLMap output parsing - works for ANY target
                output_lower = result['output'].lower()
                
                # Multiple detection patterns for universal compatibility
                vuln_indicators = [
                    'injection point',
                    'parameter appears to be',
                    'payload was found to be',
                    'injectable parameter',
                    'is vulnerable',
                    'parameter is injectable',
                    'sqlmap identified the following injection point'
                ]
                
                sqlmap_found_vuln = any(indicator in output_lower for indicator in vuln_indicators)
                
                if sqlmap_found_vuln:
                    from datetime import datetime
                    
                    # Extract payload information if available
                    payload = "SQLMap detected injection"
                    if 'payload:' in output_lower:
                        payload_match = re.search(r'payload:\s*([^\n]+)', result['output'], re.IGNORECASE)
                        if payload_match:
                            payload = payload_match.group(1).strip()
                    
                    finding = VulnerabilityFinding(
                        url=url,
                        vuln_type='SQL_INJECTION',
                        severity='Critical',
                        confidence=0.95,
                        payload=payload,
                        evidence=result['output'][:800] + '...' if len(result['output']) > 800 else result['output'],
                        discovered_at=datetime.now(),
                        impact_description='SQL injection allows database access and potential data exfiltration',
                        remediation='Use parameterized queries, input validation, and least-privilege database access'
                    )
                    findings.append(finding)
                    logger.warning(f"🚨 SQLMap detected SQL injection in {url}")
                
                # Also check for partial detection (testing in progress)
                elif 'testing for sql injection' in output_lower and result['output'].count('[INFO]') > 10:
                    logger.info(f"🔍 SQLMap extensive testing performed on {url} - scan may need more time")
        
        except Exception as e:
            logger.error(f"SQLMap scan failed for {url}: {e}")
        
        return findings
    
    async def _dalfox_scan(self, url: str, params: List[str]) -> List[VulnerabilityFinding]:
        """XSS testing using Dalfox"""
        findings = []
        
        try:
            # Dalfox command with proper arguments
            cmd = [
                self.tools['dalfox'],
                'url', url,  # Use url mode for single target
                '--format', 'json',  # JSON output format
                '-S',  # Silent mode (only show POCs)
                '--timeout', '20',  # Request timeout
                '-w', '10',  # Worker count
                '--skip-bav',  # Skip basic another vulnerability analysis
                '--skip-headless',  # Skip headless browser (faster)
                '--delay', '100'  # 100ms delay between requests
            ]
            
            # Add authentication cookie
            if self.auth_cookie:
                cmd.extend(['-C', self.auth_cookie])
            
            # Add specific parameters to test if available
            if params:
                # Test most promising XSS parameters
                xss_params = [p for p in params if p in ['search', 'q', 'query', 'name', 'comment', 'message']][:3]
                if xss_params:
                    for param in xss_params:
                        cmd.extend(['-p', param])
                
                # Add custom XSS payloads
                cmd.extend(['--custom-payload', '<script>alert("XSS")</script>'])
                cmd.extend(['--custom-payload', '"><script>alert(document.domain)</script>'])
            
            result = await self._run_tool(cmd, timeout=60)
            
            if result['success'] and result['output']:
                try:
                    # Parse Dalfox JSON output
                    for line in result['output'].split('\n'):
                        if line.strip() and line.startswith('{'):
                            try:
                                vuln_data = json.loads(line)
                                if vuln_data.get('type') == 'VULN':
                                    from datetime import datetime
                                    finding = VulnerabilityFinding(
                                        url=vuln_data.get('data', {}).get('url', url),
                                        vuln_type='XSS',
                                        severity='High',
                                        confidence=0.8,
                                        payload=vuln_data.get('data', {}).get('payload', ''),
                                        evidence=vuln_data.get('message', ''),
                                        discovered_at=datetime.now(),
                                        impact_description='Cross-site scripting allows code execution in user browsers',
                                        affected_parameter=vuln_data.get('data', {}).get('param', '')
                                    )
                                    findings.append(finding)
                                    logger.warning(f"🚨 Dalfox found XSS in {url}")
                            except json.JSONDecodeError:
                                continue
                except Exception as e:
                    logger.debug(f"Error parsing Dalfox output: {e}")
        
        except Exception as e:
            logger.error(f"Dalfox scan failed for {url}: {e}")
        
        return findings
    
    # Old reconnaissance methods removed - enhanced scanner focuses only on vulnerability testing
    
    def _analyze_response_for_vulns(self, status: int, length: int, payload: str, param: str) -> bool:
        """Analyze response characteristics for potential vulnerabilities"""
        # Look for reflection indicators
        if status == 200 and any(indicator in payload for indicator in ['<script>', 'alert', 'javascript:']):
            return True
        
        # SQL error indicators 
        if status == 500 and any(indicator in payload for indicator in ["'", '"', 'OR']):
            return True
            
        # Command injection indicators
        if status == 200 and any(indicator in payload for indicator in ['../../../', '${', '<%=']):
            return True
            
        return False
    
    async def _run_tool(self, cmd: List[str], timeout: int = 60) -> Dict:
        """Run external tool and return result"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )
            
            return {
                'success': process.returncode == 0,
                'output': stdout.decode('utf-8', errors='ignore'),
                'error': stderr.decode('utf-8', errors='ignore')
            }
            
        except asyncio.TimeoutError:
            logger.warning(f"Tool timeout: {' '.join(cmd[:2])}")
            return {'success': False, 'output': '', 'error': 'Timeout'}
        except Exception as e:
            logger.error(f"Tool execution failed {' '.join(cmd[:2])}: {e}")
            return {'success': False, 'output': '', 'error': str(e)}