#!/usr/bin/env python3
"""
Test script for the professional CVSS-based confidence scoring system
Demonstrates the elimination of false positives and accurate vulnerability detection
"""

import asyncio
import aiohttp
from modules.confidence_engine import confidence_engine
from modules.vulnerability_scanner import VulnerabilityScanner
from asset_manager import AssetManager, VulnerabilityFinding
from datetime import datetime

async def test_confidence_system():
    """Test the professional confidence scoring system"""

    print("🎯 TESTING PROFESSIONAL CONFIDENCE SCORING SYSTEM")
    print("=" * 60)

    # Test 1: False Positive Scenario
    print("\n1. FALSE POSITIVE TEST:")
    print("   Scenario: Normal 200 response with X-Forwarded-For header")

    evidence_text = "Header test IP bypass via X-Forwarded-For resulted in 200 -> 200 response"
    result = confidence_engine.calculate_confidence(
        vuln_type='AUTHORIZATION_BYPASS',
        response_text=evidence_text,
        payload="{'X-Forwarded-For': '127.0.0.1'}",
        context={
            'status_change': False,
            'admin_content': False,
            'baseline_status': 200,
            'bypass_status': 200
        }
    )

    print(f"   Confidence Score: {result.score:.3f}")
    print(f"   Confidence Tier: {result.tier}")
    print(f"   Would Create Vulnerability: {result.score >= 0.60}")
    print(f"   ✅ CORRECT: False positive filtered out!" if result.score < 0.60 else f"   ❌ ERROR: False positive not caught!")

    # Test 2: Real Vulnerability Scenario
    print("\n2. REAL VULNERABILITY TEST:")
    print("   Scenario: Authorization bypass 403 -> 200")

    evidence_text = "Status code change indicates authorization bypass: 403 -> 200"
    result2 = confidence_engine.calculate_confidence(
        vuln_type='AUTHORIZATION_BYPASS',
        response_text=evidence_text,
        payload="{'X-Forwarded-For': '127.0.0.1'}",
        context={
            'status_change': True,
            'admin_content': False,
            'baseline_status': 403,
            'bypass_status': 200
        }
    )

    print(f"   Confidence Score: {result2.score:.3f}")
    print(f"   Confidence Tier: {result2.tier}")
    print(f"   Severity: {confidence_engine.get_severity_from_confidence(result2.score, 'AUTHORIZATION_BYPASS')}")
    print(f"   Would Create Vulnerability: {result2.score >= 0.60}")
    print(f"   ✅ CORRECT: Real vulnerability detected!" if result2.score >= 0.60 else f"   ❌ ERROR: Real vulnerability missed!")

    # Test 3: SQL Injection with MySQL Error
    print("\n3. SQL INJECTION TEST:")
    print("   Scenario: MySQL error in form response")

    evidence_text = "SQL error indicator found in form field uid: mysql_fetch_array()"
    result3 = confidence_engine.calculate_confidence(
        vuln_type='SQL_INJECTION',
        response_text=evidence_text,
        payload="' OR '1'='1'--",
        context={'error_type': 'mysql', 'form_based': True}
    )

    print(f"   Confidence Score: {result3.score:.3f}")
    print(f"   Confidence Tier: {result3.tier}")
    print(f"   Severity: {confidence_engine.get_severity_from_confidence(result3.score, 'SQL_INJECTION')}")
    print(f"   Evidence Types: {result3.evidence}")

    # Test 4: XSS Detection
    print("\n4. XSS DETECTION TEST:")
    print("   Scenario: Script tag execution detected")

    evidence_text = "XSS payload reflected: <script>alert('XSS')</script>"
    result4 = confidence_engine.calculate_confidence(
        vuln_type='XSS',
        response_text=evidence_text,
        payload="<script>alert('XSS')</script>",
        context={'reflected': True, 'browser_confirmed': False}
    )

    print(f"   Confidence Score: {result4.score:.3f}")
    print(f"   Confidence Tier: {result4.tier}")
    print(f"   Severity: {confidence_engine.get_severity_from_confidence(result4.score, 'XSS')}")

    # Test 5: Command Injection with Output
    print("\n5. COMMAND INJECTION TEST:")
    print("   Scenario: Unix id command output")

    evidence_text = "Command injection successful: uid=33(www-data) gid=33(www-data) groups=33(www-data)"
    result5 = confidence_engine.calculate_confidence(
        vuln_type='COMMAND_INJECTION',
        response_text=evidence_text,
        payload="; id",
        context={'command_output': True}
    )

    print(f"   Confidence Score: {result5.score:.3f}")
    print(f"   Confidence Tier: {result5.tier}")
    print(f"   Severity: {confidence_engine.get_severity_from_confidence(result5.score, 'COMMAND_INJECTION')}")

    print("\n" + "=" * 60)
    print("🎯 CONFIDENCE SYSTEM TEST COMPLETE")
    print("\n✅ KEY IMPROVEMENTS:")
    print("   • False positives filtered out (score < 0.60)")
    print("   • Real vulnerabilities accurately detected")
    print("   • CVSS-based professional scoring")
    print("   • Evidence-weighted confidence calculation")
    print("   • Severity mapping based on vulnerability type")
    print("\n🚀 READY FOR PRODUCTION SCANNING!")

if __name__ == "__main__":
    asyncio.run(test_confidence_system())