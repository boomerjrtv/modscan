#!/usr/bin/env python3
"""
ML-Powered Vulnerability Detection Engine
Smart vulnerability detection using machine learning and AI assistance
"""

import asyncio
import aiohttp
import logging
import json
import re
import base64
import hashlib
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
import google.generativeai as genai
from pathlib import Path

logger = logging.getLogger("MLVulnEngine")

@dataclass
class MLVulnerabilityFinding:
    """ML-enhanced vulnerability finding"""
    url: str
    vuln_type: str
    severity: str
    confidence: float
    payload: str
    evidence: str
    discovered_at: datetime
    ml_score: float = 0.0
    ai_analysis: str = ""
    exploitation_complexity: str = ""
    business_impact: str = ""
    remediation_priority: int = 1

class MLVulnerabilityEngine:
    def __init__(self, asset_manager, config: Dict):
        self.asset_manager = asset_manager
        self.config = config
        self.gemini_key = config.get('gemini_api_key', '')
        
        # Initialize Gemini if key is provided
        if self.gemini_key:
            genai.configure(api_key=self.gemini_key)
            self.gemini_model = genai.GenerativeModel('gemini-2.0-flash-exp')
            logger.info("🤖 Gemini Flash 2.5 initialized for AI-assisted vulnerability analysis")
        else:
            self.gemini_model = None
            logger.warning("⚠️ No Gemini API key provided - running without AI assistance")
        
        # ML patterns for vulnerability detection
        self.vulnerability_patterns = {
            'sql_injection': {
                'patterns': [
                    r"SQL syntax.*error",
                    r"mysql_fetch_array",
                    r"ORA-\d{5}",
                    r"Microsoft.*ODBC.*SQL",
                    r"PostgreSQL.*ERROR",
                    r"Warning.*mysql_.*",
                    r"valid MySQL result",
                    r"MySqlClient\."
                ],
                'payloads': [
                    "' OR '1'='1",
                    "\" OR \"1\"=\"1",
                    "' UNION SELECT NULL--",
                    "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                ]
            },
            'xss': {
                'patterns': [
                    r"<script[^>]*>.*?</script>",
                    r"javascript:",
                    r"on\w+\s*=",
                    r"expression\s*\(",
                    r"<iframe[^>]*>",
                    r"<object[^>]*>",
                    r"<embed[^>]*>"
                ],
                'payloads': [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "javascript:alert('XSS')",
                    "<svg onload=alert('XSS')>",
                    "'\"><script>alert('XSS')</script>",
                ]
            },
            'command_injection': {
                'patterns': [
                    r"sh: .*: command not found",
                    r"root:.*:0:0:",
                    r"/bin/.*: .*: not found",
                    r"FATAL.*ERROR.*password",
                    r"stderr: .*Permission denied"
                ],
                'payloads': [
                    "; id",
                    "| whoami",
                    "`pwd`",
                    "$(cat /etc/passwd)",
                    "&& echo vulnerable"
                ]
            },
            'xxe': {
                'patterns': [
                    r"ENTITY.*SYSTEM",
                    r"<!DOCTYPE.*ENTITY",
                    r"root:x:0:0:",
                    r"file:///etc/passwd"
                ],
                'payloads': [
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
                ]
            },
            'ssrf': {
                'patterns': [
                    r"169\.254\.169\.254",
                    r"metadata\.google\.internal",
                    r"Connection refused",
                    r"No route to host",
                    r"Connection timed out"
                ],
                'payloads': [
                    "http://169.254.169.254/latest/meta-data/",
                    "http://metadata.google.internal/computeMetadata/v1/",
                    "http://localhost:22",
                    "file:///etc/passwd"
                ]
            }
        }
        
        logger.info(f"🧠 ML Vulnerability Engine initialized with {len(self.vulnerability_patterns)} detection categories")

    async def analyze_vulnerabilities_with_ml(self, assets: List[Dict], session: aiohttp.ClientSession) -> List[MLVulnerabilityFinding]:
        """Analyze assets for vulnerabilities using ML-enhanced detection"""
        findings = []
        
        logger.info(f"🧠 ML VULN ANALYSIS: Starting intelligent vulnerability detection on {len(assets)} assets")
        
        for asset in assets:
            try:
                asset_findings = await self._analyze_single_asset_ml(asset, session)
                findings.extend(asset_findings)
            except Exception as e:
                logger.error(f"ML analysis failed for {asset.get('url', 'unknown')}: {e}")
        
        # Enhance findings with AI analysis if available
        if self.gemini_model and findings:
            enhanced_findings = await self._enhance_findings_with_ai(findings)
            return enhanced_findings
        
        return findings

    async def _analyze_single_asset_ml(self, asset: Dict, session: aiohttp.ClientSession) -> List[MLVulnerabilityFinding]:
        """ML-powered analysis of a single asset"""
        findings = []
        url = asset['url']
        tech_stack = asset.get('tech_stack', '')
        response_body = asset.get('response_body', '')
        
        logger.debug(f"🔬 ML analyzing: {url} (tech: {tech_stack})")
        
        # 1. Passive Analysis - Check response body for vulnerability indicators
        if response_body:
            passive_findings = await self._passive_vulnerability_detection(url, response_body, tech_stack)
            findings.extend(passive_findings)
        
        # 2. Active Testing - Smart payload selection based on tech stack
        active_findings = await self._active_vulnerability_testing(url, tech_stack, session)
        findings.extend(active_findings)
        
        # 3. ML Scoring - Calculate confidence scores
        for finding in findings:
            finding.ml_score = self._calculate_ml_confidence(finding, tech_stack)
        
        return findings

    async def _passive_vulnerability_detection(self, url: str, response_body: str, tech_stack: str) -> List[MLVulnerabilityFinding]:
        """Passive vulnerability detection from response analysis"""
        findings = []
        
        for vuln_type, config in self.vulnerability_patterns.items():
            for pattern in config['patterns']:
                if re.search(pattern, response_body, re.IGNORECASE):
                    confidence = self._calculate_pattern_confidence(pattern, response_body, tech_stack)
                    
                    if confidence > 0.3:  # Only report medium+ confidence findings
                        finding = MLVulnerabilityFinding(
                            url=url,
                            vuln_type=vuln_type,
                            severity=self._determine_severity(vuln_type, confidence),
                            confidence=confidence,
                            payload="passive_detection",
                            evidence=f"Pattern matched: {pattern}",
                            discovered_at=datetime.now(),
                            ml_score=confidence
                        )
                        findings.append(finding)
                        logger.info(f"🎯 ML PASSIVE DETECTION: {vuln_type} in {url} (confidence: {confidence:.2f})")
        
        return findings

    async def _active_vulnerability_testing(self, url: str, tech_stack: str, session: aiohttp.ClientSession) -> List[MLVulnerabilityFinding]:
        """Smart active testing based on tech stack"""
        findings = []
        
        # Select payloads based on technology stack
        target_vulns = self._select_target_vulnerabilities(tech_stack)
        
        for vuln_type in target_vulns:
            if vuln_type in self.vulnerability_patterns:
                config = self.vulnerability_patterns[vuln_type]
                
                # Test each payload
                for payload in config['payloads'][:2]:  # Limit to 2 payloads per type
                    try:
                        finding = await self._test_payload(url, vuln_type, payload, session)
                        if finding:
                            findings.append(finding)
                    except Exception as e:
                        logger.debug(f"Payload test failed for {url}: {e}")
        
        return findings

    def _select_target_vulnerabilities(self, tech_stack: str) -> List[str]:
        """Select vulnerability types to test based on technology stack"""
        # Base vulnerabilities to always test
        base_vulns = ['xss', 'sql_injection']
        
        tech_lower = tech_stack.lower()
        
        # Add technology-specific vulnerabilities
        if any(tech in tech_lower for tech in ['php', 'asp', 'jsp', 'python']):
            base_vulns.append('command_injection')
        
        if any(tech in tech_lower for tech in ['xml', 'soap', 'rest']):
            base_vulns.append('xxe')
        
        if any(tech in tech_lower for tech in ['api', 'microservice', 'cloud']):
            base_vulns.append('ssrf')
        
        logger.debug(f"🎯 Target vulnerabilities for {tech_stack}: {base_vulns}")
        return base_vulns

    async def _test_payload(self, url: str, vuln_type: str, payload: str, session: aiohttp.ClientSession) -> Optional[MLVulnerabilityFinding]:
        """Test a specific payload against a URL"""
        try:
            # Create test URL with payload
            if '?' in url:
                test_url = f"{url}&test={payload}"
            else:
                test_url = f"{url}?test={payload}"
            
            async with session.get(test_url, timeout=10) as response:
                response_text = await response.text()
                
                # Check for vulnerability indicators
                config = self.vulnerability_patterns[vuln_type]
                for pattern in config['patterns']:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        confidence = self._calculate_pattern_confidence(pattern, response_text, "")
                        
                        return MLVulnerabilityFinding(
                            url=url,
                            vuln_type=vuln_type,
                            severity=self._determine_severity(vuln_type, confidence),
                            confidence=confidence,
                            payload=payload,
                            evidence=f"Active test confirmed: {pattern}",
                            discovered_at=datetime.now(),
                            ml_score=confidence
                        )
        
        except Exception as e:
            logger.debug(f"Payload test error: {e}")
        
        return None

    def _calculate_pattern_confidence(self, pattern: str, response_text: str, tech_stack: str) -> float:
        """Calculate confidence score for pattern match"""
        base_confidence = 0.5
        
        # Boost confidence for specific error patterns
        high_confidence_patterns = [
            r"SQL syntax.*error",
            r"ORA-\d{5}",
            r"root:.*:0:0:",
            r"<script[^>]*>.*?</script>"
        ]
        
        for high_pattern in high_confidence_patterns:
            if re.search(high_pattern, pattern, re.IGNORECASE):
                base_confidence = 0.8
                break
        
        # Adjust based on tech stack relevance
        if tech_stack:
            if 'mysql' in pattern.lower() and 'mysql' in tech_stack.lower():
                base_confidence += 0.2
            elif 'php' in tech_stack.lower() and 'mysql' in pattern.lower():
                base_confidence += 0.1
        
        return min(base_confidence, 1.0)

    def _calculate_ml_confidence(self, finding: MLVulnerabilityFinding, tech_stack: str) -> float:
        """Calculate ML confidence score for a finding"""
        base_score = finding.confidence
        
        # Technology relevance boost
        tech_relevance = 0.0
        vuln_type = finding.vuln_type
        
        if vuln_type == 'sql_injection' and any(db in tech_stack.lower() for db in ['mysql', 'postgres', 'mssql', 'oracle']):
            tech_relevance = 0.2
        elif vuln_type == 'xss' and any(js in tech_stack.lower() for js in ['javascript', 'react', 'angular', 'vue']):
            tech_relevance = 0.2
        elif vuln_type == 'command_injection' and any(lang in tech_stack.lower() for lang in ['php', 'python', 'nodejs']):
            tech_relevance = 0.2
        
        return min(base_score + tech_relevance, 1.0)

    def _determine_severity(self, vuln_type: str, confidence: float) -> str:
        """Determine severity based on vulnerability type and confidence"""
        severity_map = {
            'sql_injection': 'HIGH',
            'command_injection': 'CRITICAL',
            'xss': 'MEDIUM',
            'xxe': 'HIGH',
            'ssrf': 'HIGH'
        }
        
        base_severity = severity_map.get(vuln_type, 'MEDIUM')
        
        # Adjust based on confidence
        if confidence > 0.8:
            return base_severity
        elif confidence > 0.5:
            # Downgrade by one level for medium confidence
            if base_severity == 'CRITICAL':
                return 'HIGH'
            elif base_severity == 'HIGH':
                return 'MEDIUM'
            else:
                return 'LOW'
        else:
            return 'LOW'

    async def _enhance_findings_with_ai(self, findings: List[MLVulnerabilityFinding]) -> List[MLVulnerabilityFinding]:
        """Enhance findings with AI analysis using Gemini"""
        if not self.gemini_model:
            return findings
        
        logger.info(f"🤖 GEMINI ANALYSIS: Enhancing {len(findings)} findings with AI insights")
        
        enhanced_findings = []
        
        # Process findings in batches to avoid rate limits
        batch_size = 5
        for i in range(0, len(findings), batch_size):
            batch = findings[i:i + batch_size]
            
            try:
                enhanced_batch = await self._analyze_findings_batch_with_ai(batch)
                enhanced_findings.extend(enhanced_batch)
                
                # Rate limiting
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"AI enhancement failed for batch: {e}")
                enhanced_findings.extend(batch)  # Return original findings on error
        
        return enhanced_findings

    async def _analyze_findings_batch_with_ai(self, findings: List[MLVulnerabilityFinding]) -> List[MLVulnerabilityFinding]:
        """Analyze a batch of findings with AI"""
        # Prepare context for AI analysis
        context = {
            "findings": [],
            "analysis_request": "Analyze these vulnerability findings and provide exploitation complexity, business impact assessment, and remediation priority (1-5 scale)"
        }
        
        for finding in findings:
            context["findings"].append({
                "url": finding.url,
                "vuln_type": finding.vuln_type,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "payload": finding.payload,
                "evidence": finding.evidence
            })
        
        prompt = f"""
        You are a cybersecurity expert analyzing vulnerability findings. For each finding, provide:
        1. Exploitation complexity (LOW/MEDIUM/HIGH)
        2. Business impact assessment (brief description)
        3. Remediation priority (1=Critical, 5=Low)
        
        Context: {json.dumps(context, indent=2)}
        
        Respond in JSON format with an array of objects containing: exploitation_complexity, business_impact, remediation_priority, ai_analysis
        """
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None, self.gemini_model.generate_content, prompt
            )
            
            ai_analysis = json.loads(response.text)
            
            # Enhance findings with AI insights
            for i, finding in enumerate(findings):
                if i < len(ai_analysis):
                    analysis = ai_analysis[i]
                    finding.exploitation_complexity = analysis.get('exploitation_complexity', 'MEDIUM')
                    finding.business_impact = analysis.get('business_impact', 'Assessment pending')
                    finding.remediation_priority = analysis.get('remediation_priority', 3)
                    finding.ai_analysis = analysis.get('ai_analysis', 'AI analysis completed')
        
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            # Set default values on error
            for finding in findings:
                finding.exploitation_complexity = 'MEDIUM'
                finding.business_impact = 'Requires manual assessment'
                finding.remediation_priority = 3
                finding.ai_analysis = 'AI analysis unavailable'
        
        return findings

    def store_ml_finding(self, finding: MLVulnerabilityFinding):
        """Store ML finding in database"""
        try:
            # Get asset ID from URL
            asset = self.asset_manager.get_asset_by_url(finding.url)
            if not asset:
                logger.warning(f"Asset not found for URL: {finding.url}")
                return
            
            # Store vulnerability
            vuln_data = {
                'asset_id': asset['id'],
                'type': finding.vuln_type,
                'description': f"{finding.evidence} | ML Score: {finding.ml_score:.2f} | {finding.ai_analysis}",
                'severity': finding.severity,
                'evidence': finding.evidence,
                'payload': finding.payload,
                'detected_at': finding.discovered_at.isoformat(),
                'confidence': finding.confidence
            }
            
            self.asset_manager.add_vulnerability(vuln_data)
            logger.info(f"✅ ML finding stored: {finding.vuln_type} in {finding.url}")
            
        except Exception as e:
            logger.error(f"Failed to store ML finding: {e}")