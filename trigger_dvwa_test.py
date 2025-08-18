#!/usr/bin/env python3
"""
Trigger Multi-AI Pentester Team to test REAL DVWA vulnerabilities
"""

import asyncio
import sys
import os
from pathlib import Path
import json

# Add the parent directory to the path
sys.path.append(str(Path(__file__).parent))

from modules.multi_ai_pentester_team import MultiAIPentesterTeam
from asset_manager import AssetManager

async def test_real_dvwa_vulns():
    """Test the actual DVWA vulnerable pages"""
    
    # Load configuration
    try:
        with open('config.json') as f:
            config = json.load(f)
    except:
        config = {"gemini_api_key": "your-api-key-here"}
    
    # Initialize components
    asset_manager = AssetManager()
    ai_team = MultiAIPentesterTeam(asset_manager, config)
    
    # Initialize the team
    await ai_team.initialize()
    
    # REAL DVWA vulnerable endpoints (low security)
    dvwa_vulns = [
        "http://192.168.1.42/dvwa/vulnerabilities/xss_r/?name=test",  # Reflected XSS
        "http://192.168.1.42/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit",  # SQL Injection
        "http://192.168.1.42/dvwa/vulnerabilities/xss_s/",  # Stored XSS
        "http://192.168.1.42/dvwa/vulnerabilities/csrf/",  # CSRF
        "http://192.168.1.42/dvwa/vulnerabilities/fi/?page=include.php",  # File Inclusion
        "http://192.168.1.42/dvwa/vulnerabilities/upload/",  # File Upload
        "http://192.168.1.42/dvwa/vulnerabilities/brute/",  # Brute Force
    ]
    
    print(f"🎯 Testing Multi-AI Pentester Team on {len(dvwa_vulns)} REAL DVWA vulnerable endpoints...")
    print("🔥 Expected: CRITICAL/HIGH severity findings with actual exploitation")
    
    # Run parallel penetration testing
    findings = await ai_team.parallel_pentest(dvwa_vulns, max_concurrent=5)
    
    # Show results
    print(f"\n📊 REAL DVWA RESULTS:")
    print(f"Total findings: {len(findings)}")
    
    # Show findings by severity
    severity_counts = {}
    for finding in findings:
        severity = finding.get('severity', 'UNKNOWN')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    print(f"Severity breakdown: {severity_counts}")
    
    # Show specific findings
    for i, finding in enumerate(findings, 1):
        print(f"\n  Finding {i}:")
        print(f"    Type: {finding.get('type', 'Unknown')}")
        print(f"    Severity: {finding.get('severity', 'Unknown')}")
        print(f"    URL: {finding.get('url', 'Unknown')}")
        print(f"    Payload: {finding.get('payload', 'None')}")
        if finding.get('ai_analysis'):
            print(f"    AI Analysis: {finding.get('ai_analysis')[:100]}...")
    
    # Show exploit chains
    chains = [f for f in findings if f.get('type') == 'Exploit Chain']
    if chains:
        print(f"\n🔗 EXPLOIT CHAINS: {len(chains)}")
        for chain in chains:
            print(f"  Chain: {' → '.join(chain.get('chain_components', []))}")
    
    # Cleanup
    await ai_team.cleanup()
    
    print(f"\n✅ DVWA vulnerability testing complete!")

if __name__ == "__main__":
    asyncio.run(test_real_dvwa_vulns())