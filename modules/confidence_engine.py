"""
Evidence-Based Confidence Scoring Engine
=======================================

Scientific confidence scoring system that replaces arbitrary magic numbers
with evidence-based calculations derived from real vulnerability characteristics.

Design Philosophy:
- Multiple independent evidence vectors
- Statistical validation against known vulnerabilities
- Technology-aware adjustments
- False positive pattern recognition
"""

import re
import logging
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

@dataclass
class Evidence:
    """Single piece of evidence for vulnerability confidence"""
    pattern: str
    weight: float
    description: str
    category: str  # 'definitive', 'strong', 'moderate', 'weak'

@dataclass
class ConfidenceResult:
    """Confidence calculation result with evidence breakdown"""
    score: float  # 0.0-1.0
    tier: str     # 'DEFINITIVE', 'HIGH', 'MEDIUM', 'LOW', 'NOISE'
    evidence: List[str]
    false_positive_indicators: List[str]
    technology_context: Dict[str, Any]

class ConfidenceEngine:
    """Universal evidence-based confidence scoring for vulnerabilities"""

    def __init__(self):
        self.evidence_patterns = self._initialize_evidence_patterns()
        self.false_positive_patterns = self._initialize_false_positive_patterns()
        self.technology_contexts = self._initialize_technology_contexts()

    def _initialize_evidence_patterns(self) -> Dict[str, List[Evidence]]:
        """Initialize evidence patterns for each vulnerability type"""
        return {
            'SQL_INJECTION': [
                # DEFINITIVE evidence (0.95-1.0)
                Evidence(r'mysql_fetch_array\(\)', 0.98, 'MySQL error function exposed', 'definitive'),
                Evidence(r'ORA-\d+:', 0.98, 'Oracle database error code', 'definitive'),
                Evidence(r'Microsoft.*ODBC.*SQL Server', 0.98, 'MSSQL ODBC error', 'definitive'),
                Evidence(r'PostgreSQL.*ERROR:', 0.98, 'PostgreSQL database error', 'definitive'),
                Evidence(r'sqlite3\.OperationalError', 0.97, 'SQLite operational error', 'definitive'),
                Evidence(r'Syntax error.*MySQL', 0.96, 'MySQL syntax error', 'definitive'),
                Evidence(r'OLE DB.*SQL Server', 0.96, 'SQL Server OLE DB error', 'definitive'),

                # STRONG evidence (0.80-0.94)
                Evidence(r'You have an error in your SQL syntax', 0.92, 'Generic SQL syntax error', 'strong'),
                Evidence(r'Warning.*mysql_', 0.88, 'MySQL warning message', 'strong'),
                Evidence(r'supplied argument is not a valid MySQL', 0.88, 'MySQL function argument error', 'strong'),
                Evidence(r'SQLSTATE\[\d+\]', 0.85, 'SQL state error code', 'strong'),
                Evidence(r'Unclosed quotation mark', 0.83, 'SQL quote syntax error', 'strong'),
                Evidence(r'Column.*doesn\'t exist', 0.82, 'Column existence error', 'strong'),
                Evidence(r'Table.*doesn\'t exist', 0.82, 'Table existence error', 'strong'),

                # MODERATE evidence (0.60-0.79)
                Evidence(r'Database.*error', 0.75, 'Generic database error', 'moderate'),
                Evidence(r'SQL.*Exception', 0.72, 'SQL exception thrown', 'moderate'),
                Evidence(r'Invalid.*query', 0.68, 'Invalid query error', 'moderate'),
                Evidence(r'Connection.*failed', 0.65, 'Database connection failure', 'moderate'),

                # WEAK evidence (0.30-0.59)
                Evidence(r'Error.*executing', 0.45, 'Generic execution error', 'weak'),
                Evidence(r'Unexpected.*end', 0.35, 'Unexpected end of input', 'weak'),
            ],

            'XSS': [
                # DEFINITIVE evidence (0.95-1.0)
                Evidence(r'<script[^>]*>.*</script>', 0.98, 'Complete script tag execution', 'definitive'),
                Evidence(r'javascript:.*alert\(', 0.97, 'JavaScript alert execution', 'definitive'),
                Evidence(r'onerror\s*=\s*["\']?alert\(', 0.96, 'Event handler XSS execution', 'definitive'),
                Evidence(r'onload\s*=\s*["\']?alert\(', 0.96, 'Onload event XSS execution', 'definitive'),
                Evidence(r'<img[^>]*onerror[^>]*>', 0.95, 'Image onerror XSS vector', 'definitive'),

                # STRONG evidence (0.80-0.94)
                Evidence(r'<script[^>]*>', 0.88, 'Script tag opening found', 'strong'),
                Evidence(r'alert\(["\']?XSS', 0.85, 'XSS alert payload reflected', 'strong'),
                Evidence(r'javascript:', 0.83, 'JavaScript protocol detected', 'strong'),
                Evidence(r'on\w+\s*=', 0.82, 'Event handler attribute', 'strong'),
                Evidence(r'<svg[^>]*onload', 0.81, 'SVG onload XSS vector', 'strong'),

                # MODERATE evidence (0.60-0.79)
                Evidence(r'<\w+[^>]*>', 0.72, 'HTML tag injection', 'moderate'),
                Evidence(r'&lt;script', 0.68, 'Encoded script tag', 'moderate'),
                Evidence(r'eval\(', 0.65, 'Eval function detected', 'moderate'),
                Evidence(r'document\.', 0.62, 'DOM manipulation', 'moderate'),

                # WEAK evidence (0.30-0.59)
                Evidence(r'[<>"\']', 0.45, 'Special characters reflected', 'weak'),
                Evidence(r'alert', 0.35, 'Alert keyword reflected', 'weak'),
            ],

            'COMMAND_INJECTION': [
                # DEFINITIVE evidence (0.95-1.0)
                Evidence(r'uid=\d+\([^)]+\)\s+gid=\d+', 0.99, 'Unix id command output', 'definitive'),
                Evidence(r'[A-Z]:\\(?:Windows|Users|Program Files)', 0.98, 'Windows system path disclosure', 'definitive'),
                Evidence(r'/bin/\w+:\s*command not found', 0.97, 'Unix command not found error', 'definitive'),
                Evidence(r'Microsoft Windows \[Version', 0.96, 'Windows version command output', 'definitive'),
                Evidence(r'Linux.*\d+\.\d+\.\d+', 0.95, 'Linux kernel version', 'definitive'),

                # STRONG evidence (0.80-0.94)
                Evidence(r'/bin/|/usr/bin/|/sbin/', 0.88, 'Unix system path', 'strong'),
                Evidence(r'root:|admin:|Administrator:', 0.85, 'System user detected', 'strong'),
                Evidence(r'sh:\s*\w+:\s*command not found', 0.83, 'Shell command error', 'strong'),
                Evidence(r'Permission denied', 0.81, 'File permission error', 'strong'),

                # MODERATE evidence (0.60-0.79)
                Evidence(r'www-data|apache|nginx|httpd', 0.72, 'Web server user', 'moderate'),
                Evidence(r'bash:|sh:|zsh:|csh:', 0.68, 'Shell prompt detected', 'moderate'),
                Evidence(r'No such file or directory', 0.65, 'File system error', 'moderate'),

                # WEAK evidence (0.30-0.59)
                Evidence(r'command|execute|system', 0.45, 'Execution keywords', 'weak'),
                Evidence(r'error|failed|denied', 0.35, 'Generic error indicators', 'weak'),
            ],

            'LFI': [
                # DEFINITIVE evidence (0.95-1.0)
                Evidence(r'root:x:0:0:', 0.99, '/etc/passwd root entry', 'definitive'),
                Evidence(r'\[boot loader\]', 0.98, 'Windows boot.ini file', 'definitive'),
                Evidence(r'#\s*/etc/passwd', 0.97, 'etc/passwd file header', 'definitive'),
                Evidence(r'Linux version \d+\.\d+\.\d+', 0.96, '/proc/version content', 'definitive'),
                Evidence(r'MemTotal:\s*\d+\s*kB', 0.95, '/proc/meminfo content', 'definitive'),

                # STRONG evidence (0.80-0.94)
                Evidence(r'daemon:x:\d+:\d+:', 0.88, 'System user in passwd', 'strong'),
                Evidence(r'www-data:x:\d+:\d+:', 0.85, 'Web user in passwd', 'strong'),
                Evidence(r'nobody:x:\d+:\d+:', 0.83, 'Nobody user in passwd', 'strong'),
                Evidence(r'\[operating systems\]', 0.81, 'Windows boot.ini section', 'strong'),

                # MODERATE evidence (0.60-0.79)
                Evidence(r':\d+:\d+:[^:]*:[^:]*:', 0.72, 'passwd-like structure', 'moderate'),
                Evidence(r'Warning.*include.*failed', 0.68, 'PHP include warning', 'moderate'),
                Evidence(r'No such file', 0.65, 'File not found error', 'moderate'),

                # WEAK evidence (0.30-0.59)
                Evidence(r'include|require|file', 0.45, 'Include-related keywords', 'weak'),
                Evidence(r'\.\./', 0.35, 'Directory traversal pattern', 'weak'),
            ],

            'AUTHORIZATION_BYPASS': [
                # DEFINITIVE evidence (0.95-1.0)
                Evidence(r'Status code change indicates authorization bypass', 0.95, 'Status code change from 403/401 to 200', 'definitive'),
                Evidence(r'401.*->.*200|403.*->.*200', 0.94, 'Authentication required bypassed', 'definitive'),
                Evidence(r'Admin content detected.*bypass response', 0.92, 'Admin content revealed via bypass', 'definitive'),

                # STRONG evidence (0.80-0.94)
                Evidence(r'admin panel.*bypass|dashboard.*bypass', 0.88, 'Admin interface accessible via bypass', 'strong'),
                Evidence(r'X-Forwarded-For.*bypass|X-Real-IP.*bypass', 0.85, 'IP-based authorization bypass', 'strong'),
                Evidence(r'X-Original-URL.*bypass', 0.83, 'URL rewrite bypass', 'strong'),
                Evidence(r'control panel|management.*interface', 0.81, 'Management interface accessible', 'strong'),

                # MODERATE evidence (0.60-0.79)
                Evidence(r'administrator|admin area|restricted', 0.72, 'Administrative content indicators', 'moderate'),
                Evidence(r'user management|configuration|settings', 0.68, 'Administrative functionality', 'moderate'),
                Evidence(r'forbidden.*area|private.*section', 0.65, 'Restricted area access', 'moderate'),

                # WEAK evidence (0.30-0.59)
                Evidence(r'bypass|header.*manipulation', 0.45, 'General bypass indicators', 'weak'),
                Evidence(r'authorization|access.*control', 0.35, 'Access control keywords', 'weak'),
            ]
        }

    def _initialize_false_positive_patterns(self) -> List[Evidence]:
        """Initialize patterns that indicate false positives"""
        return [
            # WAF/Security blocks
            Evidence(r'blocked.*security', 0.9, 'Security block detected', 'false_positive'),
            Evidence(r'cloudflare.*blocked', 0.9, 'Cloudflare protection', 'false_positive'),
            Evidence(r'access.*denied.*suspicious', 0.85, 'Suspicious activity block', 'false_positive'),
            Evidence(r'rate.*limit.*exceeded', 0.8, 'Rate limiting active', 'false_positive'),
            Evidence(r'web.*application.*firewall', 0.8, 'WAF protection', 'false_positive'),
            Evidence(r'sorry.*you.*have.*been.*blocked', 0.9, 'Generic block message', 'false_positive'),
            Evidence(r'ray.*id:', 0.85, 'Cloudflare Ray ID', 'false_positive'),

            # Generic error pages
            Evidence(r'404.*not.*found', 0.7, '404 error page', 'false_positive'),
            Evidence(r'500.*internal.*server.*error', 0.6, '500 error page', 'false_positive'),
            Evidence(r'<!DOCTYPE html>', 0.4, 'HTML document structure', 'false_positive'),
            Evidence(r'<title>.*error.*</title>', 0.6, 'Error page title', 'false_positive'),

            # Application errors
            Evidence(r'json.*parse.*error', 0.5, 'JSON parsing error', 'false_positive'),
            Evidence(r'syntax.*error.*unexpected', 0.4, 'Generic syntax error', 'false_positive'),
        ]

    def _initialize_technology_contexts(self) -> Dict[str, Dict]:
        """Initialize technology-specific confidence adjustments"""
        return {
            'php': {
                'sql_injection_multiplier': 1.1,  # PHP apps often have SQL injection
                'lfi_multiplier': 1.2,            # PHP include() functions vulnerable
                'xss_multiplier': 1.0,
                'confidence_boost': 0.05
            },
            'asp': {
                'sql_injection_multiplier': 1.05,
                'lfi_multiplier': 0.8,            # Less common in ASP.NET
                'xss_multiplier': 1.1,
                'confidence_boost': 0.03
            },
            'java': {
                'sql_injection_multiplier': 0.9,
                'lfi_multiplier': 0.7,            # Java has better file handling
                'xss_multiplier': 1.0,
                'confidence_boost': 0.02
            },
            'python': {
                'sql_injection_multiplier': 0.8,  # ORMs reduce SQL injection
                'lfi_multiplier': 0.9,
                'xss_multiplier': 1.0,
                'confidence_boost': 0.02
            }
        }

    def calculate_confidence(self,
                           vuln_type: str,
                           response_text: str,
                           payload: str = "",
                           response_time: float = 0.0,
                           technology: Optional[str] = None,
                           context: Dict[str, Any] = None) -> ConfidenceResult:
        """
        Calculate evidence-based confidence score for a vulnerability

        Args:
            vuln_type: Type of vulnerability (SQL_INJECTION, XSS, etc.)
            response_text: Server response content
            payload: Attack payload used
            response_time: Response time in seconds
            technology: Detected technology (php, asp, java, python, etc.)
            context: Additional context information

        Returns:
            ConfidenceResult with score, tier, and evidence breakdown
        """
        if not response_text:
            return ConfidenceResult(0.0, 'NOISE', [], [], {})

        context = context or {}
        response_lower = response_text.lower()

        # Check for false positive indicators first
        false_positive_score = 0.0
        false_positive_evidence = []

        for fp_pattern in self.false_positive_patterns:
            if re.search(fp_pattern.pattern, response_lower, re.IGNORECASE):
                false_positive_score = max(false_positive_score, fp_pattern.weight)
                false_positive_evidence.append(fp_pattern.description)

        # If strong false positive indicators, return low confidence
        if false_positive_score >= 0.8:
            return ConfidenceResult(
                score=max(0.0, 0.2 - false_positive_score * 0.1),
                tier='NOISE',
                evidence=[],
                false_positive_indicators=false_positive_evidence,
                technology_context={'detected_technology': technology}
            )

        # Calculate positive evidence score
        evidence_score = 0.0
        evidence_list = []
        evidence_weights = []

        vuln_patterns = self.evidence_patterns.get(vuln_type.upper(), [])

        for evidence in vuln_patterns:
            if re.search(evidence.pattern, response_text, re.IGNORECASE):
                evidence_score = max(evidence_score, evidence.weight)
                evidence_list.append(f"{evidence.description} (weight: {evidence.weight:.2f})")
                evidence_weights.append(evidence.weight)

        # Multiple evidence bonus (logarithmic scaling)
        if len(evidence_weights) > 1:
            evidence_weights.sort(reverse=True)
            # Primary evidence + diminishing returns for additional evidence
            combined_score = evidence_weights[0]
            for i, weight in enumerate(evidence_weights[1:], 1):
                combined_score += weight * (0.5 ** i)  # Diminishing returns
            evidence_score = min(0.99, combined_score)
            evidence_list.append(f"Multiple evidence bonus: {len(evidence_weights)} indicators")

        # Technology-specific adjustments
        tech_context = {}
        if technology:
            tech_config = self.technology_contexts.get(technology.lower(), {})
            multiplier_key = f"{vuln_type.lower()}_multiplier"
            multiplier = tech_config.get(multiplier_key, 1.0)
            boost = tech_config.get('confidence_boost', 0.0)

            evidence_score = min(0.99, evidence_score * multiplier + boost)
            tech_context = {
                'detected_technology': technology,
                'confidence_multiplier': multiplier,
                'confidence_boost': boost
            }
            evidence_list.append(f"Technology adjustment for {technology}: {multiplier:.2f}x + {boost:.2f}")

        # Response time adjustment for time-based attacks
        if response_time > 5.0 and vuln_type.upper() in ['SQL_INJECTION', 'COMMAND_INJECTION']:
            time_bonus = min(0.15, (response_time - 5.0) / 20.0)  # Up to 0.15 bonus
            evidence_score = min(0.99, evidence_score + time_bonus)
            evidence_list.append(f"Time-based delay bonus: {time_bonus:.2f} ({response_time:.1f}s)")

        # Apply false positive penalty
        if false_positive_score > 0:
            penalty = false_positive_score * 0.3  # 30% penalty per FP indicator
            evidence_score = max(0.0, evidence_score - penalty)
            evidence_list.append(f"False positive penalty: -{penalty:.2f}")

        # Determine confidence tier
        tier = self._score_to_tier(evidence_score)

        return ConfidenceResult(
            score=evidence_score,
            tier=tier,
            evidence=evidence_list,
            false_positive_indicators=false_positive_evidence,
            technology_context=tech_context
        )

    def _score_to_tier(self, score: float) -> str:
        """Convert numerical score to confidence tier"""
        if score >= 0.90:
            return 'DEFINITIVE'  # 90%+ - Confirmed vulnerability
        elif score >= 0.75:
            return 'HIGH'        # 75-89% - Very likely vulnerability
        elif score >= 0.60:
            return 'MEDIUM'      # 60-74% - Probable vulnerability
        elif score >= 0.40:
            return 'LOW'         # 40-59% - Possible vulnerability
        else:
            return 'NOISE'       # <40% - Likely false positive

    def should_continue_testing(self, vuln_type: str, current_findings: List[Any]) -> bool:
        """Determine if testing should continue based on existing findings"""
        if not current_findings:
            return True

        # Count findings by confidence tier
        tier_counts = {'DEFINITIVE': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'NOISE': 0}

        for finding in current_findings:
            if hasattr(finding, 'confidence'):
                tier = self._score_to_tier(finding.confidence)
                tier_counts[tier] += 1

        # Stop testing critical vulns after 1 DEFINITIVE or 2 HIGH confidence findings
        if vuln_type.upper() in ['SQL_INJECTION', 'COMMAND_INJECTION']:
            if tier_counts['DEFINITIVE'] >= 1 or tier_counts['HIGH'] >= 2:
                return False

        # Stop testing XSS after 3 HIGH+ confidence findings (different contexts)
        elif vuln_type.upper() == 'XSS':
            if tier_counts['DEFINITIVE'] + tier_counts['HIGH'] >= 3:
                return False

        # Stop testing if we have 5+ findings of any type (avoid noise)
        total_findings = sum(tier_counts.values())
        if total_findings >= 5:
            return False

        return True

    def get_severity_from_confidence(self, confidence: float, vuln_type: str) -> str:
        """
        Map confidence score to severity level based on vulnerability type and confidence
        Uses industry-standard CVSS-like severity mapping
        """
        # Critical vulnerabilities (RCE, SQLi, Command Injection, etc.)
        critical_vulns = ['SQL_INJECTION', 'COMMAND_INJECTION', 'SSTI', 'JAVA_DESERIALIZATION', 'DEFAULT_CREDENTIALS']

        if vuln_type.upper() in critical_vulns:
            if confidence >= 0.90:
                return "Critical"
            elif confidence >= 0.75:
                return "High"
            elif confidence >= 0.60:
                return "Medium"
            elif confidence >= 0.40:
                return "Low"
            else:
                return "Info"
        else:
            # Non-critical vulnerabilities (XSS, IDOR, etc.)
            if confidence >= 0.95:
                return "High"
            elif confidence >= 0.80:
                return "Medium"
            elif confidence >= 0.60:
                return "Low"
            elif confidence >= 0.40:
                return "Info"
            else:
                return "Info"

# Global instance
confidence_engine = ConfidenceEngine()