#!/usr/bin/env python3
"""
🔍 SECRET SCANNER - TruffleHog Style
Comprehensive secret detection for bug bounty hunting
"""

import re
import logging
import base64
import json
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

@dataclass
class SecretFinding:
    """Represents a discovered secret."""
    secret_type: str
    secret_value: str
    confidence: float  # 0.0-1.0
    context: str  # Surrounding text
    source_url: str
    line_number: Optional[int] = None
    file_path: Optional[str] = None

class SecretScanner:
    """TruffleHog-style secret detection for bug bounty hunting."""

    def __init__(self):
        self.secret_patterns = self._load_secret_patterns()

    def _load_secret_patterns(self) -> Dict[str, Dict]:
        """Load comprehensive secret detection patterns."""
        return {
            # AWS Secrets
            'aws_access_key': {
                'pattern': r'AKIA[0-9A-Z]{16}',
                'confidence': 0.95,
                'description': 'AWS Access Key ID'
            },
            'aws_secret_key': {
                'pattern': r'aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
                'confidence': 0.9,
                'description': 'AWS Secret Access Key'
            },
            'aws_session_token': {
                'pattern': r'aws_session_token\s*[=:]\s*["\']?([A-Za-z0-9/+=]{100,})["\']?',
                'confidence': 0.85,
                'description': 'AWS Session Token'
            },

            # Google Cloud
            'gcp_service_account': {
                'pattern': r'"type":\s*"service_account".*?"private_key":\s*"-----BEGIN PRIVATE KEY-----',
                'confidence': 0.95,
                'description': 'Google Cloud Service Account Key'
            },
            'gcp_api_key': {
                'pattern': r'AIza[0-9A-Za-z_-]{35}',
                'confidence': 0.9,
                'description': 'Google API Key'
            },

            # GitHub
            'github_token': {
                'pattern': r'gh[pousr]_[A-Za-z0-9_]{36,255}',
                'confidence': 0.95,
                'description': 'GitHub Token'
            },
            'github_app_token': {
                'pattern': r'ghs_[A-Za-z0-9_]{36}',
                'confidence': 0.95,
                'description': 'GitHub App Token'
            },
            'github_oauth': {
                'pattern': r'gho_[A-Za-z0-9_]{36}',
                'confidence': 0.95,
                'description': 'GitHub OAuth Token'
            },

            # API Keys (Generic)
            'generic_api_key': {
                'pattern': r'(?i)(?:api[_-]?key|apikey|access[_-]?key)\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,})["\']?',
                'confidence': 0.7,
                'description': 'Generic API Key'
            },
            'bearer_token': {
                'pattern': r'Bearer\s+([A-Za-z0-9_-]{20,})',
                'confidence': 0.8,
                'description': 'Bearer Token'
            },

            # Database Credentials
            'mysql_connection': {
                'pattern': r'mysql://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?/(\w+)',
                'confidence': 0.9,
                'description': 'MySQL Connection String'
            },
            'postgres_connection': {
                'pattern': r'postgres(?:ql)?://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?/(\w+)',
                'confidence': 0.9,
                'description': 'PostgreSQL Connection String'
            },
            'mongodb_connection': {
                'pattern': r'mongodb://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?/(\w+)',
                'confidence': 0.9,
                'description': 'MongoDB Connection String'
            },

            # JWT Tokens
            'jwt_token': {
                'pattern': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
                'confidence': 0.85,
                'description': 'JWT Token'
            },

            # Private Keys
            'rsa_private_key': {
                'pattern': r'-----BEGIN (?:RSA )?PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END (?:RSA )?PRIVATE KEY-----',
                'confidence': 0.95,
                'description': 'RSA Private Key'
            },
            'ssh_private_key': {
                'pattern': r'-----BEGIN OPENSSH PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END OPENSSH PRIVATE KEY-----',
                'confidence': 0.95,
                'description': 'SSH Private Key'
            },

            # Slack
            'slack_token': {
                'pattern': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
                'confidence': 0.9,
                'description': 'Slack Token'
            },
            'slack_webhook': {
                'pattern': r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+',
                'confidence': 0.95,
                'description': 'Slack Webhook URL'
            },

            # Azure
            'azure_storage_key': {
                'pattern': r'DefaultEndpointsProtocol=https;AccountName=([^;]+);AccountKey=([A-Za-z0-9+/=]{88});',
                'confidence': 0.9,
                'description': 'Azure Storage Account Key'
            },

            # Discord
            'discord_token': {
                'pattern': r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}',
                'confidence': 0.85,
                'description': 'Discord Bot Token'
            },
            'discord_webhook': {
                'pattern': r'https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+',
                'confidence': 0.95,
                'description': 'Discord Webhook'
            },

            # Telegram
            'telegram_bot_token': {
                'pattern': r'\d{8,10}:[A-Za-z0-9_-]{35}',
                'confidence': 0.8,
                'description': 'Telegram Bot Token'
            },

            # PayPal
            'paypal_client_id': {
                'pattern': r'A[A-Za-z0-9_-]{80}',
                'confidence': 0.6,
                'description': 'PayPal Client ID'
            },

            # Stripe
            'stripe_secret_key': {
                'pattern': r'sk_live_[A-Za-z0-9]{24}',
                'confidence': 0.95,
                'description': 'Stripe Live Secret Key'
            },
            'stripe_test_key': {
                'pattern': r'sk_test_[A-Za-z0-9]{24}',
                'confidence': 0.9,
                'description': 'Stripe Test Secret Key'
            },

            # Twilio
            'twilio_account_sid': {
                'pattern': r'AC[a-f0-9]{32}',
                'confidence': 0.8,
                'description': 'Twilio Account SID'
            },
            'twilio_auth_token': {
                'pattern': r'twilio.*["\']([a-f0-9]{32})["\']',
                'confidence': 0.85,
                'description': 'Twilio Auth Token'
            },

            # SendGrid
            'sendgrid_api_key': {
                'pattern': r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
                'confidence': 0.95,
                'description': 'SendGrid API Key'
            },

            # Mailgun
            'mailgun_api_key': {
                'pattern': r'key-[a-f0-9]{32}',
                'confidence': 0.8,
                'description': 'Mailgun API Key'
            },

            # Firebase
            'firebase_url': {
                'pattern': r'https://[a-z0-9-]+\.firebaseio\.com',
                'confidence': 0.7,
                'description': 'Firebase Database URL'
            },

            # Generic Passwords
            'password_in_url': {
                'pattern': r'[?&](?:password|pass|pwd)=([^&\s]+)',
                'confidence': 0.6,
                'description': 'Password in URL Parameter'
            },
            'basic_auth': {
                'pattern': r'://([^:]+):([^@]+)@',
                'confidence': 0.8,
                'description': 'Basic Auth in URL'
            },

            # Configuration Files
            'db_password': {
                'pattern': r'(?i)(?:database_password|db_password|db_pass)\s*[=:]\s*["\']?([^"\'\\s]+)["\']?',
                'confidence': 0.8,
                'description': 'Database Password'
            },
            'smtp_password': {
                'pattern': r'(?i)smtp_password\s*[=:]\s*["\']?([^"\'\\s]+)["\']?',
                'confidence': 0.8,
                'description': 'SMTP Password'
            },

            # Session/Cookie Secrets
            'session_secret': {
                'pattern': r'(?i)(?:session_secret|secret_key|session_key)\s*[=:]\s*["\']?([A-Za-z0-9_-]{16,})["\']?',
                'confidence': 0.7,
                'description': 'Session Secret Key'
            },

            # Cloud Function URLs
            'azure_function_url': {
                'pattern': r'https://[a-z0-9-]+\.azurewebsites\.net/api/[^\\s"\']+code=[A-Za-z0-9_-]+',
                'confidence': 0.9,
                'description': 'Azure Function URL with Code'
            },
            'aws_lambda_url': {
                'pattern': r'https://[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com/[^\\s"\']*',
                'confidence': 0.8,
                'description': 'AWS Lambda Function URL'
            },

            # API Endpoints that often leak secrets
            'internal_api': {
                'pattern': r'(?:localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.).*(?:api|admin)',
                'confidence': 0.6,
                'description': 'Internal API Endpoint'
            }
        }

    def scan_text(self, text: str, source_url: str = "", file_path: str = "") -> List[SecretFinding]:
        """Scan text content for secrets."""
        findings = []

        # Split into lines for line number tracking
        lines = text.split('\n')

        for line_num, line in enumerate(lines, 1):
            for secret_type, pattern_info in self.secret_patterns.items():
                pattern = pattern_info['pattern']
                confidence = pattern_info['confidence']

                matches = re.finditer(pattern, line, re.IGNORECASE | re.MULTILINE)

                for match in matches:
                    # Extract the secret value
                    if match.groups():
                        secret_value = match.group(1)  # First capture group
                    else:
                        secret_value = match.group(0)  # Entire match

                    # Get context (surrounding text)
                    context_start = max(0, match.start() - 50)
                    context_end = min(len(line), match.end() + 50)
                    context = line[context_start:context_end]

                    # Skip if it looks like a placeholder
                    if self._is_placeholder(secret_value):
                        continue

                    finding = SecretFinding(
                        secret_type=secret_type,
                        secret_value=secret_value,
                        confidence=confidence,
                        context=context,
                        source_url=source_url,
                        line_number=line_num,
                        file_path=file_path
                    )

                    findings.append(finding)

        return findings

    def scan_response(self, response_text: str, response_headers: Dict, url: str) -> List[SecretFinding]:
        """Scan HTTP response for secrets."""
        findings = []

        # Scan response body
        body_findings = self.scan_text(response_text, source_url=url)
        findings.extend(body_findings)

        # Scan response headers
        header_text = '\n'.join([f"{k}: {v}" for k, v in response_headers.items()])
        header_findings = self.scan_text(header_text, source_url=f"{url} (headers)")
        findings.extend(header_findings)

        # Look for specific response patterns
        findings.extend(self._scan_response_patterns(response_text, url))

        return findings

    def _scan_response_patterns(self, response_text: str, url: str) -> List[SecretFinding]:
        """Scan for response-specific secret patterns."""
        findings = []

        # Debug/error pages that leak info
        debug_patterns = [
            (r'Database.*password.*[=:]\s*([^\s<>&]+)', 'debug_db_password', 0.8),
            (r'SECRET_KEY.*[=:]\s*["\']([^"\']+)["\']', 'debug_secret_key', 0.9),
            (r'API_KEY.*[=:]\s*["\']([^"\']+)["\']', 'debug_api_key', 0.9),
            (r'(?i)exception.*(?:password|secret|key).*[=:]\s*([^\s<>&]+)', 'exception_secret', 0.7),
        ]

        for pattern, secret_type, confidence in debug_patterns:
            matches = re.finditer(pattern, response_text, re.IGNORECASE)
            for match in matches:
                secret_value = match.group(1)
                if not self._is_placeholder(secret_value):
                    finding = SecretFinding(
                        secret_type=secret_type,
                        secret_value=secret_value,
                        confidence=confidence,
                        context=match.group(0),
                        source_url=url
                    )
                    findings.append(finding)

        # JSON responses with secrets
        try:
            json_data = json.loads(response_text)
            json_findings = self._scan_json_secrets(json_data, url)
            findings.extend(json_findings)
        except (json.JSONDecodeError, ValueError):
            pass

        return findings

    def _scan_json_secrets(self, json_data: any, url: str, path: str = "") -> List[SecretFinding]:
        """Recursively scan JSON for secret patterns."""
        findings = []

        if isinstance(json_data, dict):
            for key, value in json_data.items():
                current_path = f"{path}.{key}" if path else key

                # Check key names for secret indicators
                if self._is_secret_key_name(key) and isinstance(value, str):
                    if not self._is_placeholder(value) and len(value) > 8:
                        finding = SecretFinding(
                            secret_type=f"json_{key}",
                            secret_value=value,
                            confidence=0.8,
                            context=f'"{key}": "{value}"',
                            source_url=f"{url} (JSON path: {current_path})"
                        )
                        findings.append(finding)

                # Recurse into nested objects
                if isinstance(value, (dict, list)):
                    findings.extend(self._scan_json_secrets(value, url, current_path))

        elif isinstance(json_data, list):
            for i, item in enumerate(json_data):
                current_path = f"{path}[{i}]" if path else f"[{i}]"
                findings.extend(self._scan_json_secrets(item, url, current_path))

        return findings

    def _is_secret_key_name(self, key: str) -> bool:
        """Check if a JSON key name indicates it might contain a secret."""
        secret_keywords = [
            'password', 'pass', 'pwd', 'secret', 'key', 'token', 'auth',
            'api_key', 'apikey', 'access_key', 'private_key', 'session',
            'credential', 'authorization', 'bearer', 'jwt', 'oauth'
        ]
        key_lower = key.lower()
        return any(keyword in key_lower for keyword in secret_keywords)

    def _is_placeholder(self, value: str) -> bool:
        """Check if a value is likely a placeholder rather than real secret."""
        if not value or len(value) < 4:
            return True

        placeholder_patterns = [
            'your_', 'example', 'test', 'demo', 'placeholder', 'replace',
            'xxx', '***', '...', 'dummy', 'fake', 'sample', 'default',
            '123', 'abc', 'lorem', 'ipsum', 'null', 'none', 'undefined'
        ]

        value_lower = value.lower()
        return any(pattern in value_lower for pattern in placeholder_patterns)

    def validate_secret(self, finding: SecretFinding) -> float:
        """Validate if a secret is likely real (returns confidence 0.0-1.0)."""
        value = finding.secret_value
        secret_type = finding.secret_type

        # Length-based validation
        if len(value) < 8:
            return 0.2

        # Type-specific validation
        if secret_type in ['aws_access_key'] and len(value) != 20:
            return 0.3

        if secret_type in ['jwt_token']:
            try:
                # Try to decode JWT header
                parts = value.split('.')
                if len(parts) == 3:
                    header = json.loads(base64.b64decode(parts[0] + '=='))
                    if 'alg' in header and 'typ' in header:
                        return 0.95
            except:
                pass

        # Entropy check (high entropy suggests real secret)
        entropy = self._calculate_entropy(value)
        if entropy > 4.0:  # High entropy
            return min(1.0, finding.confidence + 0.2)
        elif entropy < 2.0:  # Low entropy
            return max(0.1, finding.confidence - 0.3)

        return finding.confidence

    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0

        # Count character frequencies
        counts = {}
        for char in s:
            counts[char] = counts.get(char, 0) + 1

        # Calculate entropy
        length = len(s)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            if p > 0:
                entropy -= p * (p.log2() if hasattr(p, 'log2') else 0)

        return entropy

    def get_high_confidence_secrets(self, findings: List[SecretFinding]) -> List[SecretFinding]:
        """Filter to only high-confidence secret findings."""
        validated_findings = []

        for finding in findings:
            validated_confidence = self.validate_secret(finding)
            if validated_confidence >= 0.7:  # High confidence threshold
                finding.confidence = validated_confidence
                validated_findings.append(finding)

        return validated_findings

    def format_findings_report(self, findings: List[SecretFinding]) -> str:
        """Format findings into a detailed report."""
        if not findings:
            return "No secrets found."

        report = f"🔍 SECRET SCANNER REPORT\n"
        report += f"Total secrets found: {len(findings)}\n\n"

        # Group by secret type
        by_type = {}
        for finding in findings:
            if finding.secret_type not in by_type:
                by_type[finding.secret_type] = []
            by_type[finding.secret_type].append(finding)

        for secret_type, type_findings in by_type.items():
            report += f"🔑 {secret_type.upper()} ({len(type_findings)} found)\n"

            for finding in type_findings:
                report += f"  URL: {finding.source_url}\n"
                report += f"  Value: {finding.secret_value[:20]}{'...' if len(finding.secret_value) > 20 else ''}\n"
                report += f"  Confidence: {finding.confidence:.2f}\n"
                report += f"  Context: {finding.context[:100]}{'...' if len(finding.context) > 100 else ''}\n"
                report += f"  ---\n"

        return report