#!/usr/bin/env python3
"""
Nuclei-Based Vulnerability Scanner - XBOW-level vulnerability detection
"""

import asyncio
import subprocess
import json
import logging
import aiohttp
import tempfile
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

logger = logging.getLogger("NucleiScanner")

from asset_manager import VulnerabilityFinding

class NucleiVulnerabilityScanner:
    def __init__(self, asset_manager, config: Dict):
        self.asset_manager = asset_manager
        self.config = config
        self.nuclei_path = "/home/michael/go/bin/nuclei"
        self.templates_path = self._get_nuclei_templates_path()
        self.available = self.templates_path is not None
        
        # Priority security templates across vulnerability classes
        self.priority_templates = [
            "cves/",
            "vulnerabilities/",
            "exposures/",
            "misconfiguration/",
            "default-logins/",
            "fuzzing/",
            "file/",
            "network/",
            "dns/"
        ]
        
        logger.info("🚀 NucleiScanner initialized - XBOW-level vulnerability detection")
    
    def _get_nuclei_templates_path(self):
        """Get nuclei templates directory"""
        try:
            result = subprocess.run([self.nuclei_path, "-version"], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                # Try common template locations
                possible_paths = [
                    Path.home() / "nuclei-templates",
                    Path("/opt/nuclei-templates"),
                    Path("/usr/share/nuclei-templates"),
                ]
                
                for path in possible_paths:
                    if path.exists():
                        logger.info(f"📋 Found nuclei templates: {path}")
                        return str(path)
                        
                # If no templates found, update them
                logger.info("📥 Updating nuclei templates...")
                subprocess.run([self.nuclei_path, "-update-templates"], check=True)
                return str(Path.home() / "nuclei-templates")
        except Exception as e:
            logger.error(f"Nuclei setup error: {e}")
            return None
    
    async def scan_assets_for_vulnerabilities(self, assets: List[Dict], session=None) -> int:
        """Scan assets using Nuclei with AGGRESSIVE vulnerability detection"""
        if not assets:
            return 0
            
        logger.info(f"🎯 NUCLEI SCAN: Testing {len(assets)} assets for vulnerabilities")
        
        # Create target file for nuclei
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            target_file = f.name
            for asset in assets:
                f.write(f"{asset.get('url', '')}\n")
        
        vulnerabilities_found = 0
        
        try:
            # Run nuclei scan with aggressive settings
            vulnerabilities_found += await self._run_nuclei_scan(target_file, "AGGRESSIVE")
        finally:
            # Cleanup
            Path(target_file).unlink(missing_ok=True)
            
        logger.info(f"✅ NUCLEI SCAN COMPLETE: Found {vulnerabilities_found} vulnerabilities")
        return vulnerabilities_found
    
    async def _run_nuclei_scan(self, target_file: str, intensity: str = "NORMAL") -> int:
        """Run nuclei scan with specified intensity"""
        
        base_cmd = [
            self.nuclei_path,
            "-list", target_file,
            "-json",
            "-silent",
            "-no-color"
        ]
        
        if intensity == "AGGRESSIVE":
            base_cmd.extend([
                "-templates", f"{self.templates_path}/cves/",
                "-templates", f"{self.templates_path}/vulnerabilities/",
                "-templates", f"{self.templates_path}/exposures/",
                "-templates", f"{self.templates_path}/fuzzing/",
                "-rate-limit", "100",
                "-timeout", "10",
                "-retries", "2"
            ])
        elif intensity == "LONG":
            # Broad coverage across many template categories
            base_cmd.extend([
                "-templates", f"{self.templates_path}" if self.templates_path else ".",
                "-severity", "critical,high,medium,low,info",
                "-rate-limit", "150",
                "-timeout", "15",
                "-retries", "3"
            ])
        
        vulnerabilities_found = 0
        
        try:
            logger.info(f"🚀 Running nuclei: {' '.join(base_cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *base_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                # Parse nuclei JSON output
                for line in stdout.decode().strip().split('\n'):
                    if line.strip():
                        try:
                            vuln = json.loads(line)
                            if await self._process_nuclei_finding(vuln):
                                vulnerabilities_found += 1
                        except json.JSONDecodeError:
                            continue
            else:
                logger.error(f"Nuclei scan failed: {stderr.decode()}")
                
        except Exception as e:
            logger.error(f"Nuclei execution error: {e}")
            
        return vulnerabilities_found

    async def run_long_scan(self, urls: List[str]) -> int:
        """Run a long, broad Nuclei scan across provided URLs."""
        if not urls:
            return 0
        # Fallback to minimal scanner if nuclei/templates are unavailable
        if not self.available:
            logger.warning("Nuclei not available or templates missing; running minimal HTTP checks instead")
            return await self._fallback_minimal_scan(urls)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            target_file = f.name
            for u in urls:
                f.write(u + "\n")
        try:
            return await self._run_nuclei_scan(target_file, intensity="LONG")
        finally:
            Path(target_file).unlink(missing_ok=True)

    async def _fallback_minimal_scan(self, urls: List[str]) -> int:
        """Minimal universal checks when Nuclei is unavailable (no templates).
        Tests common exposures and weak security headers.
        """
        findings = 0
        timeout = aiohttp.ClientTimeout(total=10)
        headers = {"User-Agent": "ModScan-MinimalScanner/1.0"}
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            for base in urls[:200]:
                try:
                    # Quick HEAD/GET
                    async with session.get(base, allow_redirects=True) as resp:
                        hdrs = {k.lower(): v for k, v in resp.headers.items()}
                        # Insecure transport
                        if base.startswith('http://'):
                            await self._store_minimal_finding(base, 'insecure_transport', 'Medium', 'Endpoint over HTTP without TLS')
                            findings += 1
                        # Missing security headers
                        missing = []
                        for h in ['content-security-policy', 'x-frame-options', 'strict-transport-security']:
                            if h not in hdrs:
                                missing.append(h)
                        if missing:
                            await self._store_minimal_finding(base, 'missing_security_headers', 'Low', f"Missing: {', '.join(missing)}")
                            findings += 1
                    # Sensitive files (limited)
                    for p, vt, sev, evpat in [
                        ('/.env', 'sensitive_file', 'High', 'APP_KEY'),
                        ('/.git/HEAD', 'sensitive_file', 'High', 'refs/heads'),
                        ('/phpinfo.php', 'information_disclosure', 'Medium', 'phpinfo()')
                    ]:
                        url = base.rstrip('/') + p
                        try:
                            async with session.get(url, allow_redirects=True) as r2:
                                if r2.status == 200:
                                    text = await r2.text()
                                    if evpat.lower() in text.lower():
                                        await self._store_minimal_finding(url, vt, sev, f"Evidence: {evpat}")
                                        findings += 1
                        except Exception:
                            continue
                except Exception:
                    continue
        return findings

    async def _store_minimal_finding(self, url: str, vtype: str, severity: str, evidence: str):
        try:
            # Map url to asset_id
            asset_id = await self._get_asset_id_by_url(url)
            if not asset_id:
                return
            finding = VulnerabilityFinding(
                url=url,
                vuln_type=vtype.upper(),
                severity=severity.capitalize(),
                confidence=0.6,
                payload='',
                evidence=evidence,
                discovered_at=datetime.now()
            )
            self.asset_manager.add_vulnerability_finding(finding, asset_id)
        except Exception:
            pass
    
    async def _process_nuclei_finding(self, finding: Dict) -> bool:
        """Process and store nuclei vulnerability finding"""
        try:
            # Extract key information
            template_id = finding.get('template-id', 'unknown')
            template_name = finding.get('info', {}).get('name', 'Unknown Vulnerability')
            severity = finding.get('info', {}).get('severity', 'medium').upper()
            matched_at = finding.get('matched-at', '')
            
            # Get additional details
            description = finding.get('info', {}).get('description', template_name)
            reference = finding.get('info', {}).get('reference', [])
            tags = finding.get('info', {}).get('tags', [])
            
            # Create evidence
            evidence = {
                'template_id': template_id,
                'matched_at': matched_at,
                'curl_command': finding.get('curl-command', ''),
                'request': finding.get('request', ''),
                'response': finding.get('response', ''),
                'extracted_results': finding.get('extracted-results', [])
            }
            
            # Find corresponding asset
            asset_id = await self._get_asset_id_by_url(matched_at)
            if not asset_id:
                logger.warning(f"No asset found for URL: {matched_at}")
                return False
            
            # Store vulnerability
            try:
                with self.asset_manager._get_db() as db:
                    db.execute("""
                        INSERT INTO vulnerabilities 
                        (asset_id, type, description, severity, evidence, payload, detected_at, confidence)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        asset_id,
                        template_name,
                        description,
                        severity,
                        json.dumps(evidence),
                        template_id,
                        datetime.now().isoformat(),
                        0.9  # High confidence for nuclei findings
                    ))
                    db.commit()
                    
                logger.info(f"🚨 VULNERABILITY STORED: {template_name} on {matched_at}")
                return True
                
            except Exception as e:
                logger.error(f"Error storing vulnerability: {e}")
                return False
                
        except Exception as e:
            logger.error(f"Error processing nuclei finding: {e}")
            return False
    
    async def _get_asset_id_by_url(self, url: str) -> Optional[int]:
        """Get asset ID by URL"""
        try:
            with self.asset_manager._get_db() as db:
                result = db.execute("SELECT id FROM assets WHERE url = ?", (url,)).fetchone()
                return result[0] if result else None
        except Exception:
            return None
    
    

# Integration function for the main engine
async def scan_with_nuclei(asset_manager, assets: List[Dict], config: Dict) -> int:
    """Main function to scan assets with Nuclei"""
    scanner = NucleiVulnerabilityScanner(asset_manager, config)
    return await scanner.scan_assets_for_vulnerabilities(assets)
