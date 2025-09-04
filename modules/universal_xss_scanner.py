#!/usr/bin/env python3
"""
Universal XSS Scanner Module
Uses industry-standard tools (Dalfox) for universal, target-agnostic XSS detection.
"""

import asyncio
import json
import logging
import subprocess
import tempfile
import time
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs
import aiohttp

logger = logging.getLogger(__name__)

class UniversalXSSScanner:
    def __init__(self, asset_manager, config):
        self.asset_manager = asset_manager
        self.config = config
        
        # Tool paths
        self.dalfox_path = self._find_dalfox()
        
        # Scan options
        self.timeout = 300  # 5 minutes max per scan
        self.max_concurrent = 3  # Don't overwhelm targets
        
    def _find_dalfox(self) -> Optional[str]:
        """Find Dalfox installation path."""
        possible_paths = [
            '/home/michael/go/bin/dalfox',
            '~/go/bin/dalfox',
            '/usr/local/bin/dalfox',
            '/usr/bin/dalfox',
            'dalfox'
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run([path, 'version'], capture_output=True, timeout=10)
                if result.returncode == 0:
                    logger.info(f"🔍 Found Dalfox at: {path}")
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        logger.warning("⚠️ Dalfox not found - XSS scanning will be limited")
        return None
    
    async def scan_url_for_xss(self, url: str, auth_headers: Dict = None) -> Dict:
        """
        Universal XSS scanning using Dalfox.
        Works on any target without assumptions.
        """
        results = {
            'url': url,
            'xss_findings': [],
            'scan_metadata': {},
            'recommendations': []
        }
        
        if not self.dalfox_path:
            logger.warning(f"⚠️ Skipping Dalfox scan - tool not available")
            return results
        
        try:
            # Prepare Dalfox command
            cmd = [
                self.dalfox_path,
                'url', url,
                '--format', 'json',
                '--timeout', '30',
                '--delay', '100',
                '--worker', '10',
                '--mining-dom',  # DOM-based XSS detection
                '--mining-dict',  # Use built-in parameter dictionary
                '--follow-redirect',  # Follow redirects
                '--ignore-return', '302,404,403',  # Ignore common non-vulnerable responses
                '--user-agent', 'ModScan/1.0 (Universal XSS Scanner)',
                '--silence'  # Reduce noise
            ]
            
            # Add authentication if provided
            if auth_headers:
                for header, value in auth_headers.items():
                    cmd.extend(['--header', f"{header}: {value}"])
            
            # Add custom payloads for better coverage
            cmd.extend([
                '--custom-payload', '<script>alert("MODSCAN_XSS")</script>',
                '--custom-payload', '<img src=x onerror=alert("MODSCAN_XSS")>',
                '--custom-payload', '<svg onload=alert("MODSCAN_XSS")>',
            ])
            
            logger.info(f"🔍 Starting Dalfox XSS scan: {url}")
            
            # Run Dalfox
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=self.timeout
            )
            
            # Parse results
            if process.returncode == 0:
                results = await self._parse_dalfox_output(stdout.decode(), url)
            else:
                logger.warning(f"⚠️ Dalfox scan failed: {stderr.decode()}")
                
        except asyncio.TimeoutError:
            logger.warning(f"⚠️ Dalfox scan timed out after {self.timeout}s")
        except Exception as e:
            logger.error(f"❌ Dalfox scan error: {e}")
            
        return results
    
    async def _parse_dalfox_output(self, output: str, url: str) -> Dict:
        """Parse Dalfox JSON output into standardized format."""
        results = {
            'url': url,
            'xss_findings': [],
            'scan_metadata': {},
            'recommendations': []
        }
        
        try:
            # Dalfox outputs one JSON object per line
            lines = output.strip().split('\n')
            
            for line in lines:
                if not line.strip():
                    continue
                    
                try:
                    data = json.loads(line)
                    
                    # Extract vulnerability findings
                    if data.get('type') == 'found':
                        finding = {
                            'url': data.get('data', {}).get('url', url),
                            'parameter': data.get('data', {}).get('param', ''),
                            'payload': data.get('data', {}).get('payload', ''),
                            'method': data.get('data', {}).get('method', 'GET'),
                            'evidence': data.get('data', {}).get('evidence', ''),
                            'message': data.get('message', ''),
                            'severity': 'High',  # Dalfox findings are typically high severity
                            'confidence': 0.9,  # Dalfox has good accuracy
                            'cwe': 'CWE-79',
                            'tool': 'dalfox'
                        }
                        results['xss_findings'].append(finding)
                        
                    # Extract scan metadata
                    elif data.get('type') == 'info':
                        results['scan_metadata'][data.get('level', 'info')] = data.get('message', '')
                        
                except json.JSONDecodeError:
                    # Handle non-JSON output lines
                    continue
            
            # Generate recommendations based on findings
            if results['xss_findings']:
                results['recommendations'].extend([
                    "🚨 XSS vulnerabilities found - implement input validation and output encoding",
                    "💡 Deploy Content Security Policy (CSP) headers",
                    "🔒 Use secure coding practices for dynamic content"
                ])
            
            logger.info(f"✅ Dalfox scan complete: {len(results['xss_findings'])} XSS vulnerabilities found")
            
        except Exception as e:
            logger.error(f"❌ Failed to parse Dalfox output: {e}")
            
        return results
    
    async def scan_form_for_xss(self, url: str, form_data: Dict, method: str = 'POST', 
                               auth_headers: Dict = None) -> Dict:
        """
        Universal form-based XSS scanning using Dalfox.
        """
        results = {
            'url': url,
            'method': method,
            'form_data': form_data,
            'xss_findings': [],
            'scan_metadata': {},
            'recommendations': []
        }
        
        if not self.dalfox_path:
            return results
        
        try:
            # Create a temporary file with form data
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                # Write form data in format Dalfox expects
                for key, value in form_data.items():
                    f.write(f"{key}={value}\n")
                form_file = f.name
            
            # Prepare Dalfox form command
            cmd = [
                self.dalfox_path,
                'url', url,
                '--method', method.upper(),
                '--data-from-file', form_file,
                '--format', 'json',
                '--timeout', '30',
                '--delay', '100',
                '--mining-dom',
                '--follow-redirect',
                '--user-agent', 'ModScan/1.0 (Universal Form XSS Scanner)',
                '--silence'
            ]
            
            # Add authentication if provided
            if auth_headers:
                for header, value in auth_headers.items():
                    cmd.extend(['--header', f"{header}: {value}"])
            
            logger.info(f"🔍 Starting Dalfox form XSS scan: {method} {url}")
            
            # Run Dalfox
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=self.timeout
            )
            
            # Parse results
            if process.returncode == 0:
                results = await self._parse_dalfox_output(stdout.decode(), url)
                results['method'] = method
                results['form_data'] = form_data
            else:
                logger.warning(f"⚠️ Dalfox form scan failed: {stderr.decode()}")
                
        except asyncio.TimeoutError:
            logger.warning(f"⚠️ Dalfox form scan timed out after {self.timeout}s")
        except Exception as e:
            logger.error(f"❌ Dalfox form scan error: {e}")
        finally:
            # Clean up temporary file
            try:
                import os
                os.unlink(form_file)
            except:
                pass
                
        return results
    
    async def comprehensive_xss_scan(self, url: str, auth_headers: Dict = None) -> Dict:
        """
        Comprehensive XSS scanning combining multiple techniques.
        """
        results = {
            'url': url,
            'scan_summary': {},
            'url_scan': {},
            'form_scans': [],
            'total_findings': 0,
            'recommendations': []
        }
        
        try:
            # 1. URL-based XSS scan
            logger.info(f"🔍 Universal URL XSS scan: {url}")
            results['url_scan'] = await self.scan_url_for_xss(url, auth_headers)
            
            # 2. Discover and scan forms
            forms = await self._discover_forms_simple(url)
            if forms:
                logger.info(f"🔍 Found {len(forms)} forms to scan for XSS")
                
                for form in forms:
                    form_result = await self.scan_form_for_xss(
                        form['action'], 
                        form['data'], 
                        form['method'], 
                        auth_headers
                    )
                    results['form_scans'].append(form_result)
            
            # 3. Compile summary
            total_findings = len(results['url_scan'].get('xss_findings', []))
            for form_scan in results['form_scans']:
                total_findings += len(form_scan.get('xss_findings', []))
            
            results['total_findings'] = total_findings
            results['scan_summary'] = {
                'url_findings': len(results['url_scan'].get('xss_findings', [])),
                'form_findings': sum(len(fs.get('xss_findings', [])) for fs in results['form_scans']),
                'forms_tested': len(results['form_scans'])
            }
            
            # 4. Generate comprehensive recommendations
            if total_findings > 0:
                results['recommendations'].extend([
                    f"🚨 {total_findings} XSS vulnerabilities detected across URL and forms",
                    "💡 Implement comprehensive input validation on all user inputs",
                    "🔒 Deploy Content Security Policy (CSP) with strict settings",
                    "🛡️ Use parameterized queries and prepared statements",
                    "🔍 Regular security testing and code review"
                ])
            
            logger.info(f"✅ Comprehensive XSS scan complete: {total_findings} vulnerabilities found")
            
        except Exception as e:
            logger.error(f"❌ Comprehensive XSS scan failed: {e}")
            
        return results
    
    async def _discover_forms_simple(self, url: str) -> List[Dict]:
        """Simple form discovery for universal scanning."""
        forms = []
        
        try:
            async with aiohttp.ClientSession() as session:
                try:
                    from modules.http_bypass import smart_request as _smart_request
                    _r, html = await _smart_request(session, 'GET', url, timeout=15)
                except Exception:
                    async with session.get(url, timeout=10) as response:
                        html = await response.text()
                    
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(html, 'html.parser')
                
                for form in soup.find_all('form'):
                    action = form.get('action', url)
                    if not action.startswith('http'):
                        from urllib.parse import urljoin
                        action = urljoin(url, action)
                    
                    method = form.get('method', 'GET').upper()
                    
                    # Extract form inputs
                    form_data = {}
                    for inp in form.find_all(['input', 'textarea', 'select']):
                        name = inp.get('name')
                        if name and inp.get('type') not in ['submit', 'button', 'image']:
                            form_data[name] = inp.get('value', 'test')
                    
                    if form_data:
                        forms.append({
                            'action': action,
                            'method': method,
                            'data': form_data
                        })
                        
        except Exception as e:
            logger.debug(f"Form discovery failed: {e}")
            
        return forms
