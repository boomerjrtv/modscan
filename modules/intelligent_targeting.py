#!/usr/bin/env python3
"""
🧠 INTELLIGENT VULNERABILITY TARGETING SYSTEM

Transforms ModScan from "spray and pray" to precision-guided vulnerability detection.
Uses AI analysis, technology fingerprinting, and risk assessment for smart targeting.
"""

import logging
import re
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

@dataclass
class VulnTarget:
    """Represents a prioritized vulnerability target with smart recommendations."""
    url: str
    risk_score: int  # 1-10, 10 = highest priority
    vulnerability_classes: Set[str]  # Predicted vuln types to test
    technology_stack: str
    target_type: str  # 'admin_panel', 'api_endpoint', 'form', 'file_upload', 'login'
    confidence: float  # AI confidence in vulnerability presence
    reasoning: str  # Why this target was prioritized

class IntelligentTargeting:
    """AI-driven vulnerability targeting that replaces brute force scanning."""

    def __init__(self, ai_client=None):
        self.ai_client = ai_client

        # Technology-specific vulnerability mappings
        self.tech_vuln_map = {
            'php': {'SQL_INJECTION', 'LFI', 'RFI', 'FILE_UPLOAD', 'SESSION_HIJACKING'},
            'asp.net': {'SQL_INJECTION', 'XXE', 'VIEWSTATE_DESERIALIZATION', 'PATH_TRAVERSAL'},
            'java': {'XXE', 'DESERIALIZATION', 'SQL_INJECTION', 'SSRF'},
            'nodejs': {'PROTOTYPE_POLLUTION', 'XSS', 'NOSQL_INJECTION', 'SSRF'},
            'python': {'SSTI', 'PICKLE_DESERIALIZATION', 'SQL_INJECTION', 'XSS'},
            'ruby': {'YAML_DESERIALIZATION', 'SQL_INJECTION', 'XSS', 'MASS_ASSIGNMENT'},
            'api': {'IDOR', 'BROKEN_ACCESS_CONTROL', 'RATE_LIMITING', 'INJECTION'}
        }

        # High-value target patterns (admin interfaces, sensitive endpoints)
        self.high_value_patterns = [
            r'/admin', r'/administrator', r'/manage', r'/dashboard', r'/control',
            r'/api/', r'/graphql', r'/upload', r'/file', r'/user', r'/profile',
            r'/login', r'/auth', r'/oauth', r'/sso', r'/password', r'/reset',
            r'/config', r'/settings', r'/debug', r'/test', r'/dev'
        ]

        # Low-value patterns (static content, unlikely vulnerable)
        self.low_value_patterns = [
            r'\.css$', r'\.js$', r'\.png$', r'\.jpg$', r'\.gif$', r'\.ico$',
            r'\.pdf$', r'\.doc$', r'\.zip$', r'/static/', r'/assets/', r'/images/'
        ]

    async def analyze_and_prioritize(self, assets: List[Dict]) -> List[VulnTarget]:
        """
        Transform assets into intelligently prioritized vulnerability targets.
        Returns sorted list with highest priority targets first.
        """
        targets = []

        for asset in assets:
            url = asset.get('url', '')
            tech_stack = asset.get('tech_stack', '').lower()
            status_code = asset.get('status_code', 0)

            # Skip obviously low-value targets
            if self._is_low_value_target(url):
                continue

            # Analyze target characteristics
            target_type = self._classify_target_type(url, asset)
            risk_score = self._calculate_risk_score(url, tech_stack, target_type, status_code)
            vuln_classes = self._predict_vulnerability_classes(url, tech_stack, target_type)

            # AI-enhanced analysis if available
            confidence, reasoning = await self._ai_analyze_target(asset, vuln_classes)

            target = VulnTarget(
                url=url,
                risk_score=risk_score,
                vulnerability_classes=vuln_classes,
                technology_stack=tech_stack,
                target_type=target_type,
                confidence=confidence,
                reasoning=reasoning
            )

            targets.append(target)

        # Sort by priority: risk_score * confidence
        targets.sort(key=lambda t: t.risk_score * t.confidence, reverse=True)

        logger.info(f"🎯 Intelligent targeting: {len(targets)} prioritized targets from {len(assets)} assets")
        if targets:
            top_target = targets[0]
            logger.info(f"🔥 Highest priority: {top_target.url} (risk:{top_target.risk_score}, "
                       f"vulns:{len(top_target.vulnerability_classes)}, confidence:{top_target.confidence:.2f})")

        return targets

    def _is_low_value_target(self, url: str) -> bool:
        """Check if URL is unlikely to contain vulnerabilities."""
        for pattern in self.low_value_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False

    def _classify_target_type(self, url: str, asset: Dict) -> str:
        """Classify what type of target this is for vulnerability testing."""
        url_lower = url.lower()

        # Admin interfaces - highest priority
        if any(re.search(pattern, url_lower) for pattern in [r'/admin', r'/manage', r'/dashboard']):
            return 'admin_panel'

        # API endpoints
        if any(pattern in url_lower for pattern in ['/api/', '/graphql', '.json', '/rest/']):
            return 'api_endpoint'

        # Authentication related
        if any(pattern in url_lower for pattern in ['/login', '/auth', '/oauth', '/sso']):
            return 'login'

        # File operations
        if any(pattern in url_lower for pattern in ['/upload', '/file', '/download']):
            return 'file_upload'

        # Check for forms in content (would need HTML analysis)
        # For now, assume form if it has parameters
        if '?' in url or 'form' in url_lower:
            return 'form'

        return 'page'

    def _calculate_risk_score(self, url: str, tech_stack: str, target_type: str, status_code: int) -> int:
        """Calculate risk score 1-10 based on target characteristics."""
        score = 1

        # Base score by target type
        type_scores = {
            'admin_panel': 9,
            'api_endpoint': 8,
            'login': 7,
            'file_upload': 8,
            'form': 6,
            'page': 3
        }
        score = type_scores.get(target_type, 3)

        # Boost for high-value URL patterns
        for pattern in self.high_value_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                score += 2
                break

        # Boost for vulnerable technologies
        if any(tech in tech_stack for tech in ['php', 'asp', 'java']):
            score += 1

        # Reduce for static-looking URLs
        if any(ext in url.lower() for ext in ['.css', '.js', '.png', '.jpg']):
            score = max(1, score - 3)

        # Boost for successful responses that might have functionality
        if status_code == 200:
            score += 1
        elif status_code in [401, 403]:  # Auth required = interesting
            score += 2

        return min(10, max(1, score))

    def _predict_vulnerability_classes(self, url: str, tech_stack: str, target_type: str) -> Set[str]:
        """Predict which vulnerability classes to test based on target analysis."""
        vulns = set()

        # Technology-specific vulnerabilities
        for tech, tech_vulns in self.tech_vuln_map.items():
            if tech in tech_stack.lower():
                vulns.update(tech_vulns)

        # Target-type specific vulnerabilities
        if target_type == 'admin_panel':
            vulns.update({'IDOR', 'BROKEN_ACCESS_CONTROL', 'XSS', 'CSRF'})
        elif target_type == 'api_endpoint':
            vulns.update({'IDOR', 'BROKEN_ACCESS_CONTROL', 'INJECTION', 'RATE_LIMITING'})
        elif target_type == 'login':
            vulns.update({'BRUTE_FORCE', 'SQL_INJECTION', 'XSS', 'CSRF'})
        elif target_type == 'file_upload':
            vulns.update({'FILE_UPLOAD', 'PATH_TRAVERSAL', 'XSS'})
        elif target_type == 'form':
            vulns.update({'XSS', 'SQL_INJECTION', 'CSRF'})

        # URL pattern-based predictions
        url_lower = url.lower()
        if 'id=' in url_lower or '/user/' in url_lower:
            vulns.add('IDOR')
        if 'search' in url_lower or 'query' in url_lower:
            vulns.update({'XSS', 'SQL_INJECTION'})
        if 'file' in url_lower or 'download' in url_lower:
            vulns.add('PATH_TRAVERSAL')

        # Add CSRF prediction
        if 'csrf' in url_lower or 'token' in url_lower:
            vulns.add('CSRF')

        # Add SSRF prediction
        if 'metadata' in url_lower or 'internal' in url_lower:
            vulns.add('SSRF')

        # Universal fallback: never return an empty set
        # Ensure at least a baseline that works on any target (universal principle)
        if not vulns:
            # Prefer form-centric baseline if hints present, else general web baseline
            baseline = {'XSS', 'SQL_INJECTION'}
            if '?' in url_lower or any(k in url_lower for k in ['form', 'search', 'query']):
                baseline.update({'CSRF'})
            vulns.update(baseline)

        return vulns

    async def _ai_analyze_target(self, asset: Dict, predicted_vulns: Set[str]) -> Tuple[float, str]:
        """Use AI to analyze target and provide confidence + reasoning."""
        if not self.ai_client:
            return 0.7, "No AI analysis available"

        try:
            url = asset.get('url', '')
            tech_stack = asset.get('tech_stack', '')

            prompt = f"""
            Analyze this web target for vulnerability testing priority:

            URL: {url}
            Technology: {tech_stack}
            Predicted vulnerabilities: {', '.join(predicted_vulns)}

            Rate the likelihood of finding vulnerabilities (0.0-1.0) and explain why this target
            should or shouldn't be prioritized. Consider:
            - URL structure and functionality indicators
            - Technology stack vulnerability patterns
            - Business logic complexity
            - Exposure risk

            Respond with: CONFIDENCE:X.X REASONING:explanation
            """

            # This would call your AI client
            response = await self.ai_client.analyze(prompt)

            # Parse AI response
            if "CONFIDENCE:" in response and "REASONING:" in response:
                conf_part = response.split("CONFIDENCE:")[1].split("REASONING:")[0].strip()
                reasoning_part = response.split("REASONING:")[1].strip()

                try:
                    confidence = float(conf_part)
                    return confidence, reasoning_part[:200]  # Limit reasoning length
                except ValueError:
                    pass

        except Exception as e:
            logger.debug(f"AI analysis failed for {asset.get('url', '')}: {e}")

        return 0.7, "Standard heuristic analysis"

    def get_smart_scan_plan(self, targets: List[VulnTarget], time_budget_minutes: int = 30) -> Dict:
        """
        Create an optimized scanning plan based on time budget and target priorities.
        Returns scan plan with specific targets and vulnerability types to test.
        """
        plan = {
            'high_priority': [],
            'medium_priority': [],
            'low_priority': [],
            'estimated_minutes': 0,
            'target_count': len(targets)
        }

        # Estimate time per vulnerability test (rough estimates)
        vuln_time_estimates = {
            'SQL_INJECTION': 3,
            'XSS': 2,
            'IDOR': 1,
            'LFI': 2,
            'FILE_UPLOAD': 4,
            'SSTI': 3,
            'BROKEN_ACCESS_CONTROL': 2
        }

        total_time = 0

        for target in targets:
            # Calculate estimated time for this target
            target_time = sum(vuln_time_estimates.get(vuln, 2) for vuln in target.vulnerability_classes)

            if total_time + target_time > time_budget_minutes * 60:
                # Time budget exceeded, put in low priority
                plan['low_priority'].append(target)
                continue

            total_time += target_time

            # Categorize by risk score
            if target.risk_score >= 8:
                plan['high_priority'].append(target)
            elif target.risk_score >= 5:
                plan['medium_priority'].append(target)
            else:
                plan['low_priority'].append(target)

        plan['estimated_minutes'] = total_time / 60

        logger.info(f"📋 Smart scan plan: {len(plan['high_priority'])} high, "
                   f"{len(plan['medium_priority'])} medium, {len(plan['low_priority'])} low priority targets")
        logger.info(f"⏱️ Estimated time: {plan['estimated_minutes']:.1f} minutes")

        return plan
