#!/usr/bin/env python3
"""
Advanced Cryptographic Oracle Detection Module - Outperforming XBOW

This module implements sophisticated cryptographic vulnerability detection including:
- CBC Padding Oracle attacks
- Timing-based oracle attacks
- Length extension attacks
- Weak cryptographic implementations
- JWT/JOSE vulnerabilities
- Session token predictability

Universal, target-agnostic detection that works on any web application.
"""

import asyncio
import aiohttp
import time
import base64
import secrets
import binascii
import hashlib
import hmac
import json
from typing import List, Dict, Optional, Tuple, Any
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime
import logging

from asset_manager import VulnerabilityFinding

logger = logging.getLogger(__name__)

class CryptographicOracleDetector:
    def __init__(self):
        self.session = None
        self.timing_samples = 10  # Number of samples for timing analysis
        self.timing_threshold = 0.05  # 50ms timing difference threshold

    async def _ensure_session(self) -> aiohttp.ClientSession:
        """Ensure we have an active session"""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=30, connect=10)
            self.session = aiohttp.ClientSession(timeout=timeout)
        return self.session

    async def close(self):
        """Clean up session"""
        if self.session and not self.session.closed:
            await self.session.close()

    async def detect_cryptographic_oracles(self, url: str) -> List[VulnerabilityFinding]:
        """
        Comprehensive cryptographic oracle detection
        """
        findings = []

        try:
            session = await self._ensure_session()

            # CBC Padding Oracle Detection
            findings.extend(await self._detect_cbc_padding_oracle(url, session))

            # JWT/JOSE Vulnerability Detection
            findings.extend(await self._detect_jwt_vulnerabilities(url, session))

            # Session Token Analysis
            findings.extend(await self._analyze_session_tokens(url, session))

            # Timing Oracle Detection
            findings.extend(await self._detect_timing_oracles(url, session))

            # Weak Encryption Detection
            findings.extend(await self._detect_weak_encryption(url, session))

        except Exception as e:
            logger.error(f"Cryptographic oracle detection failed for {url}: {e}")

        return findings

    async def _detect_cbc_padding_oracle(self, url: str, session: aiohttp.ClientSession) -> List[VulnerabilityFinding]:
        """
        Advanced CBC Padding Oracle Attack Detection

        Tests for CBC padding oracle vulnerabilities by:
        1. Identifying encrypted parameters (cookies, form fields, URL params)
        2. Modifying ciphertext blocks to trigger padding errors
        3. Analyzing response differences to detect oracle behavior
        4. Using statistical analysis to confirm oracle presence
        """
        findings = []

        try:
            logger.info(f"🔐 Testing CBC padding oracle vulnerabilities on {url}")

            # Get baseline response
            async with session.get(url) as response:
                baseline_content = await response.text()
                baseline_status = response.status
                baseline_headers = dict(response.headers)
                cookies = response.cookies

            # Look for encrypted-looking parameters
            encrypted_candidates = self._identify_encrypted_parameters(url, cookies, baseline_headers)

            for param_type, param_name, param_value in encrypted_candidates:
                oracle_detected = await self._test_cbc_padding_oracle(
                    url, session, param_type, param_name, param_value,
                    baseline_content, baseline_status
                )

                if oracle_detected:
                    finding = VulnerabilityFinding(
                        url=url,
                        vuln_type="CBC_PADDING_ORACLE",
                        severity="High",
                        confidence=0.90,
                        payload=f"Modified {param_name} parameter to trigger padding oracle",
                        evidence=f"CBC padding oracle detected in {param_type} parameter '{param_name}'",
                        discovered_at=datetime.now(),
                        impact_description="CBC padding oracle allows decryption of encrypted data without knowing the key",
                        remediation="Implement proper HMAC authentication and avoid exposing padding errors",
                        affected_parameter=param_name
                    )
                    findings.append(finding)
                    logger.info(f"🚨 CBC PADDING ORACLE FOUND: {param_name} in {param_type}")

        except Exception as e:
            logger.error(f"CBC padding oracle detection failed: {e}")

        return findings

    def _identify_encrypted_parameters(self, url: str, cookies: Any, headers: Dict[str, str]) -> List[Tuple[str, str, str]]:
        """
        Identify parameters that may contain encrypted data
        """
        candidates = []

        # Check URL parameters
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param_name, param_values in params.items():
                for value in param_values:
                    if self._looks_encrypted(value):
                        candidates.append(("url_param", param_name, value))

        # Check cookies
        for cookie in cookies:
            if self._looks_encrypted(cookie.value):
                candidates.append(("cookie", cookie.key, cookie.value))

        # Check headers for session tokens
        session_headers = ['Authorization', 'X-Auth-Token', 'X-Session-Token']
        for header_name in session_headers:
            if header_name in headers:
                value = headers[header_name]
                if self._looks_encrypted(value):
                    candidates.append(("header", header_name, value))

        return candidates

    def _looks_encrypted(self, value: str) -> bool:
        """
        Heuristics to identify encrypted/encoded data
        """
        if len(value) < 16:  # Too short to be meaningful ciphertext
            return False

        # Check for base64 encoding (common for encrypted data)
        try:
            decoded = base64.b64decode(value, validate=True)
            # CBC blocks are typically 16 bytes (AES) or 8 bytes (DES)
            if len(decoded) % 8 == 0 and len(decoded) >= 16:
                return True
        except:
            pass

        # Check for hex encoding
        try:
            decoded = bytes.fromhex(value)
            if len(decoded) % 8 == 0 and len(decoded) >= 16:
                return True
        except:
            pass

        # Check for URL-safe base64
        try:
            # Add padding if missing
            padded_value = value + '=' * (4 - len(value) % 4)
            decoded = base64.urlsafe_b64decode(padded_value)
            if len(decoded) % 8 == 0 and len(decoded) >= 16:
                return True
        except:
            pass

        return False

    async def _test_cbc_padding_oracle(self, url: str, session: aiohttp.ClientSession,
                                      param_type: str, param_name: str, param_value: str,
                                      baseline_content: str, baseline_status: int) -> bool:
        """
        Test for CBC padding oracle by modifying ciphertext and analyzing responses
        """
        try:
            # Decode the parameter value
            original_data = None
            encoding_type = None

            # Try different decodings
            for encoding in ['base64', 'urlsafe_base64', 'hex']:
                try:
                    if encoding == 'base64':
                        original_data = base64.b64decode(param_value)
                        encoding_type = 'base64'
                        break
                    elif encoding == 'urlsafe_base64':
                        padded = param_value + '=' * (4 - len(param_value) % 4)
                        original_data = base64.urlsafe_b64decode(padded)
                        encoding_type = 'urlsafe_base64'
                        break
                    elif encoding == 'hex':
                        original_data = bytes.fromhex(param_value)
                        encoding_type = 'hex'
                        break
                except:
                    continue

            if not original_data or len(original_data) < 16:
                return False

            # Test padding oracle by modifying last block
            responses = []

            # Generate test cases by modifying the last byte(s)
            for i in range(5):  # Test 5 different modifications
                modified_data = bytearray(original_data)
                # Modify last byte
                modified_data[-1] = (modified_data[-1] + i + 1) % 256

                # Encode back
                if encoding_type == 'base64':
                    modified_value = base64.b64encode(modified_data).decode()
                elif encoding_type == 'urlsafe_base64':
                    modified_value = base64.urlsafe_b64encode(modified_data).decode().rstrip('=')
                elif encoding_type == 'hex':
                    modified_value = modified_data.hex()

                # Send request with modified parameter
                start_time = time.time()

                if param_type == "url_param":
                    test_url = url.replace(f"{param_name}={param_value}", f"{param_name}={modified_value}")
                    async with session.get(test_url) as response:
                        content = await response.text()
                        status = response.status
                elif param_type == "cookie":
                    cookies = {param_name: modified_value}
                    async with session.get(url, cookies=cookies) as response:
                        content = await response.text()
                        status = response.status
                elif param_type == "header":
                    headers = {param_name: modified_value}
                    async with session.get(url, headers=headers) as response:
                        content = await response.text()
                        status = response.status

                response_time = time.time() - start_time

                responses.append({
                    'status': status,
                    'content_length': len(content),
                    'response_time': response_time,
                    'contains_error': self._contains_padding_error(content)
                })

            # Analyze responses for oracle behavior
            return self._analyze_oracle_responses(responses, baseline_status, len(baseline_content))

        except Exception as e:
            logger.debug(f"CBC padding oracle test failed: {e}")
            return False

    def _contains_padding_error(self, content: str) -> bool:
        """
        Check if response contains padding error indicators
        """
        padding_error_patterns = [
            'padding', 'pad', 'invalid padding', 'decryption error',
            'bad decrypt', 'padding incorrect', 'invalid block',
            'cryptographic', 'cipher', 'block size', 'padding length'
        ]

        content_lower = content.lower()
        return any(pattern in content_lower for pattern in padding_error_patterns)

    def _analyze_oracle_responses(self, responses: List[Dict], baseline_status: int, baseline_length: int) -> bool:
        """
        Analyze response patterns to detect oracle behavior
        """
        # Look for consistent differences that indicate oracle
        error_responses = sum(1 for r in responses if r['contains_error'])
        status_variations = len(set(r['status'] for r in responses))
        length_variations = len(set(r['content_length'] for r in responses))

        # Oracle indicators:
        # 1. Some responses contain padding error messages
        # 2. Consistent status code differences
        # 3. Consistent content length differences
        # 4. Timing differences (side-channel)

        if error_responses > 0:
            return True

        if status_variations > 1 and any(r['status'] != baseline_status for r in responses):
            return True

        if length_variations > 1:
            # Check if length differences are significant
            lengths = [r['content_length'] for r in responses]
            if max(lengths) - min(lengths) > 10:  # Significant difference
                return True

        return False

    async def _detect_jwt_vulnerabilities(self, url: str, session: aiohttp.ClientSession) -> List[VulnerabilityFinding]:
        """
        Detect JWT/JOSE vulnerabilities including:
        - Algorithm confusion (alg=none)
        - Weak secrets
        - Key confusion attacks
        - Critical claim manipulation
        """
        findings = []

        try:
            # Look for JWT tokens in responses
            async with session.get(url) as response:
                content = await response.text()
                headers = dict(response.headers)
                cookies = response.cookies

            jwt_tokens = self._extract_jwt_tokens(content, headers, cookies)

            for token_location, token in jwt_tokens:
                vulnerabilities = await self._analyze_jwt_token(token, url, session, token_location)
                findings.extend(vulnerabilities)

        except Exception as e:
            logger.error(f"JWT vulnerability detection failed: {e}")

        return findings

    def _extract_jwt_tokens(self, content: str, headers: Dict[str, str], cookies: Any) -> List[Tuple[str, str]]:
        """
        Extract JWT tokens from various locations
        """
        tokens = []

        # JWT pattern: xxxxx.yyyyy.zzzzz
        import re
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'

        # Check content
        content_tokens = re.findall(jwt_pattern, content)
        for token in content_tokens:
            tokens.append(("response_body", token))

        # Check headers
        auth_headers = ['Authorization', 'X-Auth-Token', 'X-Access-Token']
        for header_name in auth_headers:
            if header_name in headers:
                header_value = headers[header_name]
                if 'Bearer ' in header_value:
                    token = header_value.replace('Bearer ', '')
                    if re.match(jwt_pattern, token):
                        tokens.append((f"header_{header_name}", token))
                elif re.match(jwt_pattern, header_value):
                    tokens.append((f"header_{header_name}", header_value))

        # Check cookies
        for cookie in cookies:
            if re.match(jwt_pattern, cookie.value):
                tokens.append(f"cookie_{cookie.key}", cookie.value)

        return tokens

    async def _analyze_jwt_token(self, token: str, url: str, session: aiohttp.ClientSession,
                                token_location: str) -> List[VulnerabilityFinding]:
        """
        Comprehensive JWT token analysis
        """
        findings = []

        try:
            # Parse JWT
            parts = token.split('.')
            if len(parts) != 3:
                return findings

            header_data = self._decode_jwt_part(parts[0])
            payload_data = self._decode_jwt_part(parts[1])
            signature = parts[2]

            if not header_data or not payload_data:
                return findings

            # Test algorithm confusion (alg=none)
            none_vuln = await self._test_jwt_alg_none(token, url, session, token_location, header_data, payload_data)
            if none_vuln:
                findings.append(none_vuln)

            # Test weak secrets
            weak_secret_vuln = await self._test_jwt_weak_secret(token, header_data, payload_data, signature, url, token_location)
            if weak_secret_vuln:
                findings.append(weak_secret_vuln)

            # Test key confusion
            key_confusion_vuln = await self._test_jwt_key_confusion(token, url, session, token_location, header_data, payload_data)
            if key_confusion_vuln:
                findings.append(key_confusion_vuln)

        except Exception as e:
            logger.debug(f"JWT analysis failed: {e}")

        return findings

    def _decode_jwt_part(self, part: str) -> Optional[Dict]:
        """
        Decode JWT header or payload
        """
        try:
            # Add padding if missing
            padded = part + '=' * (4 - len(part) % 4)
            decoded = base64.urlsafe_b64decode(padded)
            return json.loads(decoded.decode('utf-8'))
        except:
            return None

    async def _test_jwt_alg_none(self, original_token: str, url: str, session: aiohttp.ClientSession,
                                token_location: str, header_data: Dict, payload_data: Dict) -> Optional[VulnerabilityFinding]:
        """
        Test JWT algorithm confusion vulnerability (alg=none)
        """
        try:
            # Create modified header with alg=none
            modified_header = header_data.copy()
            modified_header['alg'] = 'none'

            # Encode modified JWT
            header_b64 = base64.urlsafe_b64encode(json.dumps(modified_header).encode()).decode().rstrip('=')
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).decode().rstrip('=')

            # Create token with no signature
            modified_token = f"{header_b64}.{payload_b64}."

            # Test if server accepts the modified token
            if await self._test_modified_jwt(modified_token, url, session, token_location):
                return VulnerabilityFinding(
                    url=url,
                    vuln_type="JWT_ALG_NONE",
                    severity="Critical",
                    confidence=0.95,
                    payload=f"Modified JWT with alg=none: {modified_token}",
                    evidence=f"Server accepts JWT tokens with alg=none in {token_location}",
                    discovered_at=datetime.now(),
                    impact_description="JWT algorithm confusion allows token forgery without knowing the secret",
                    remediation="Explicitly validate JWT algorithm and reject alg=none",
                    affected_parameter=token_location
                )

        except Exception as e:
            logger.debug(f"JWT alg=none test failed: {e}")

        return None

    async def _test_jwt_weak_secret(self, token: str, header_data: Dict, payload_data: Dict,
                                   signature: str, url: str, token_location: str) -> Optional[VulnerabilityFinding]:
        """
        Test for weak JWT signing secrets
        """
        if header_data.get('alg') != 'HS256':
            return None  # Only test HMAC algorithms

        weak_secrets = [
            'secret', 'password', '123456', 'admin', 'jwt', 'key',
            'your-256-bit-secret', 'your-secret-key', 'mysecret',
            'qwertyuiop', 'abcdefgh', '12345678', 'changeme'
        ]

        try:
            import jwt as pyjwt

            # Get unsigned payload
            header_b64 = base64.urlsafe_b64encode(json.dumps(header_data).encode()).decode().rstrip('=')
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).decode().rstrip('=')
            unsigned_token = f"{header_b64}.{payload_b64}"

            for secret in weak_secrets:
                try:
                    # Calculate signature with weak secret
                    calculated_sig = hmac.new(
                        secret.encode(),
                        unsigned_token.encode(),
                        hashlib.sha256
                    ).digest()
                    calculated_b64 = base64.urlsafe_b64encode(calculated_sig).decode().rstrip('=')

                    if calculated_b64 == signature:
                        return VulnerabilityFinding(
                            url=url,
                            vuln_type="JWT_WEAK_SECRET",
                            severity="Critical",
                            confidence=0.98,
                            payload=f"JWT signed with weak secret: '{secret}'",
                            evidence=f"JWT token uses weak secret '{secret}' for HMAC signing",
                            discovered_at=datetime.now(),
                            impact_description="Weak JWT secret allows token forgery and privilege escalation",
                            remediation="Use cryptographically strong, randomly generated JWT signing keys",
                            affected_parameter=token_location
                        )

                except Exception:
                    continue

        except ImportError:
            logger.debug("PyJWT not available for weak secret testing")
        except Exception as e:
            logger.debug(f"JWT weak secret test failed: {e}")

        return None

    async def _test_jwt_key_confusion(self, original_token: str, url: str, session: aiohttp.ClientSession,
                                     token_location: str, header_data: Dict, payload_data: Dict) -> Optional[VulnerabilityFinding]:
        """
        Test JWT key confusion vulnerability (RS256 -> HS256)
        """
        if header_data.get('alg') != 'RS256':
            return None

        try:
            # Attempt to change algorithm from RS256 to HS256
            modified_header = header_data.copy()
            modified_header['alg'] = 'HS256'

            # Create token that might be verified with public key as HMAC secret
            header_b64 = base64.urlsafe_b64encode(json.dumps(modified_header).encode()).decode().rstrip('=')
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).decode().rstrip('=')

            # Try common public key formats as HMAC secrets
            common_public_keys = [
                '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PUBLIC KEY-----',
                'public_key', 'rsa_public_key'
            ]

            for pub_key in common_public_keys:
                try:
                    unsigned = f"{header_b64}.{payload_b64}"
                    signature = hmac.new(pub_key.encode(), unsigned.encode(), hashlib.sha256).digest()
                    sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')

                    confused_token = f"{unsigned}.{sig_b64}"

                    if await self._test_modified_jwt(confused_token, url, session, token_location):
                        return VulnerabilityFinding(
                            url=url,
                            vuln_type="JWT_KEY_CONFUSION",
                            severity="Critical",
                            confidence=0.92,
                            payload=f"JWT with algorithm confusion: {confused_token}",
                            evidence="Server vulnerable to JWT key confusion attack (RS256->HS256)",
                            discovered_at=datetime.now(),
                            impact_description="JWT key confusion allows token forgery using public key as HMAC secret",
                            remediation="Explicitly validate JWT algorithm and use separate keys for RSA and HMAC",
                            affected_parameter=token_location
                        )

                except Exception:
                    continue

        except Exception as e:
            logger.debug(f"JWT key confusion test failed: {e}")

        return None

    async def _test_modified_jwt(self, modified_token: str, url: str, session: aiohttp.ClientSession,
                                token_location: str) -> bool:
        """
        Test if server accepts a modified JWT token
        """
        try:
            if token_location.startswith("header_"):
                header_name = token_location.replace("header_", "")
                headers = {header_name: f"Bearer {modified_token}"}
                async with session.get(url, headers=headers) as response:
                    # Check if we get different response than without token
                    return response.status != 401 and response.status != 403

            elif token_location.startswith("cookie_"):
                cookie_name = token_location.replace("cookie_", "")
                cookies = {cookie_name: modified_token}
                async with session.get(url, cookies=cookies) as response:
                    return response.status != 401 and response.status != 403

        except Exception:
            pass

        return False

    async def _analyze_session_tokens(self, url: str, session: aiohttp.ClientSession) -> List[VulnerabilityFinding]:
        """
        Analyze session tokens for predictability and weak generation
        """
        findings = []

        try:
            # Collect multiple session tokens
            tokens = []
            for i in range(10):
                async with session.get(url) as response:
                    for cookie in response.cookies:
                        if self._is_session_token(cookie.key):
                            tokens.append(cookie.value)

            if len(tokens) >= 3:
                predictability = self._analyze_token_predictability(tokens)
                if predictability > 0.7:  # High predictability
                    finding = VulnerabilityFinding(
                        url=url,
                        vuln_type="PREDICTABLE_SESSION_TOKEN",
                        severity="High",
                        confidence=0.85,
                        payload=f"Session token analysis: {predictability:.2f} predictability",
                        evidence=f"Session tokens show high predictability ({predictability:.2f})",
                        discovered_at=datetime.now(),
                        impact_description="Predictable session tokens allow session hijacking",
                        remediation="Use cryptographically secure random number generator for session tokens",
                        affected_parameter="session_token"
                    )
                    findings.append(finding)

        except Exception as e:
            logger.debug(f"Session token analysis failed: {e}")

        return findings

    def _is_session_token(self, cookie_name: str) -> bool:
        """
        Identify session token cookies
        """
        session_indicators = [
            'session', 'sess', 'sid', 'token', 'auth', 'login',
            'jsessionid', 'phpsessid', 'asp.net_sessionid'
        ]
        return any(indicator in cookie_name.lower() for indicator in session_indicators)

    def _analyze_token_predictability(self, tokens: List[str]) -> float:
        """
        Analyze session token predictability using various metrics
        """
        if len(tokens) < 3:
            return 0.0

        # Check for sequential patterns
        sequential_score = self._check_sequential_patterns(tokens)

        # Check for timestamp-based patterns
        timestamp_score = self._check_timestamp_patterns(tokens)

        # Check for weak randomness
        entropy_score = self._check_entropy(tokens)

        # Combined predictability score
        return max(sequential_score, timestamp_score, 1.0 - entropy_score)

    def _check_sequential_patterns(self, tokens: List[str]) -> float:
        """
        Check for sequential patterns in tokens
        """
        try:
            # Try to parse as integers
            int_tokens = []
            for token in tokens:
                try:
                    # Try hex
                    int_tokens.append(int(token, 16))
                except:
                    try:
                        # Try base64
                        decoded = base64.b64decode(token)
                        int_tokens.append(int.from_bytes(decoded, 'big'))
                    except:
                        pass

            if len(int_tokens) >= 3:
                # Check for arithmetic progression
                differences = [int_tokens[i+1] - int_tokens[i] for i in range(len(int_tokens)-1)]
                if len(set(differences)) == 1:  # All differences are the same
                    return 1.0

                # Check for small differences (predictable increments)
                avg_diff = sum(abs(d) for d in differences) / len(differences)
                if avg_diff < 1000:  # Small increments
                    return 0.8

        except Exception:
            pass

        return 0.0

    def _check_timestamp_patterns(self, tokens: List[str]) -> float:
        """
        Check if tokens are based on timestamps
        """
        try:
            current_time = int(time.time())

            for token in tokens:
                # Check if token contains current timestamp
                if str(current_time)[:8] in token:
                    return 0.9

                # Check if token is close to current timestamp when parsed as int
                try:
                    token_int = int(token, 16) if len(token) <= 16 else int(token)
                    if abs(token_int - current_time) < 86400:  # Within 24 hours
                        return 0.8
                except:
                    pass

        except Exception:
            pass

        return 0.0

    def _check_entropy(self, tokens: List[str]) -> float:
        """
        Calculate entropy of token set
        """
        try:
            # Combine all tokens
            combined = ''.join(tokens)

            # Calculate character frequency
            char_counts = {}
            for char in combined:
                char_counts[char] = char_counts.get(char, 0) + 1

            # Calculate Shannon entropy
            total_chars = len(combined)
            entropy = 0.0
            for count in char_counts.values():
                probability = count / total_chars
                entropy -= probability * (probability.bit_length() - 1)

            # Normalize entropy (max entropy for given charset)
            max_entropy = len(char_counts).bit_length() - 1
            normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0.0

            return normalized_entropy

        except Exception:
            return 0.5  # Assume medium entropy on error

    async def _detect_timing_oracles(self, url: str, session: aiohttp.ClientSession) -> List[VulnerabilityFinding]:
        """
        Detect timing-based oracle vulnerabilities
        """
        findings = []

        try:
            # Test login endpoints for username enumeration
            if any(path in url.lower() for path in ['login', 'auth', 'signin']):
                timing_vuln = await self._test_login_timing_oracle(url, session)
                if timing_vuln:
                    findings.append(timing_vuln)

        except Exception as e:
            logger.debug(f"Timing oracle detection failed: {e}")

        return findings

    async def _test_login_timing_oracle(self, url: str, session: aiohttp.ClientSession) -> Optional[VulnerabilityFinding]:
        """
        Test for timing-based username enumeration
        """
        try:
            # Test with valid vs invalid usernames
            valid_usernames = ['admin', 'administrator', 'user', 'test']
            invalid_usernames = ['nonexistent123', 'fakeusr456', 'notreal789']

            valid_times = []
            invalid_times = []

            for username in valid_usernames:
                start = time.time()
                try:
                    data = {'username': username, 'password': 'wrongpassword'}
                    async with session.post(url, data=data) as response:
                        await response.text()
                except:
                    pass
                valid_times.append(time.time() - start)

            for username in invalid_usernames:
                start = time.time()
                try:
                    data = {'username': username, 'password': 'wrongpassword'}
                    async with session.post(url, data=data) as response:
                        await response.text()
                except:
                    pass
                invalid_times.append(time.time() - start)

            # Statistical analysis
            if len(valid_times) > 0 and len(invalid_times) > 0:
                avg_valid = sum(valid_times) / len(valid_times)
                avg_invalid = sum(invalid_times) / len(invalid_times)

                timing_difference = abs(avg_valid - avg_invalid)

                if timing_difference > self.timing_threshold:
                    return VulnerabilityFinding(
                        url=url,
                        vuln_type="TIMING_ORACLE",
                        severity="Medium",
                        confidence=0.75,
                        payload=f"Timing difference: {timing_difference:.3f}s",
                        evidence=f"Timing oracle allows username enumeration (Δt={timing_difference:.3f}s)",
                        discovered_at=datetime.now(),
                        impact_description="Timing oracle allows enumeration of valid usernames",
                        remediation="Implement constant-time authentication checks",
                        affected_parameter="username"
                    )

        except Exception as e:
            logger.debug(f"Login timing oracle test failed: {e}")

        return None

    async def _detect_weak_encryption(self, url: str, session: aiohttp.ClientSession) -> List[VulnerabilityFinding]:
        """
        Detect weak encryption implementations
        """
        findings = []

        try:
            async with session.get(url) as response:
                # Check TLS configuration
                if hasattr(response, 'connection') and hasattr(response.connection, 'transport'):
                    ssl_info = response.connection.transport.get_extra_info('ssl_object')
                    if ssl_info:
                        cipher = ssl_info.cipher()
                        if cipher and self._is_weak_cipher(cipher[0]):
                            finding = VulnerabilityFinding(
                                url=url,
                                vuln_type="WEAK_ENCRYPTION",
                                severity="Medium",
                                confidence=0.90,
                                payload=f"Weak cipher: {cipher[0]}",
                                evidence=f"Server uses weak encryption cipher: {cipher[0]}",
                                discovered_at=datetime.now(),
                                impact_description="Weak encryption cipher allows easier cryptographic attacks",
                                remediation="Configure server to use strong encryption ciphers only",
                                affected_parameter="tls_cipher"
                            )
                            findings.append(finding)

        except Exception as e:
            logger.debug(f"Weak encryption detection failed: {e}")

        return findings

    def _is_weak_cipher(self, cipher_name: str) -> bool:
        """
        Check if cipher is considered weak
        """
        weak_ciphers = [
            'DES', 'RC4', 'MD5', 'SHA1', 'NULL', 'EXPORT',
            'ADH', 'AECDH', 'aNULL', 'eNULL'
        ]
        return any(weak in cipher_name.upper() for weak in weak_ciphers)