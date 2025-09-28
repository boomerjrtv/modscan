"""
Universal Tool Orchestration Framework
=====================================

Unified interface for running security tools with proper output parsing,
validation, and VulnerabilityFinding conversion.

Design Philosophy:
- Tool-first approach: Leverage proven tools instead of reinventing detection
- Standardized interface: All tools return VulnerabilityFinding objects
- Rate limiting: Respectful scanning for bug bounty programs
- Error handling: Graceful degradation when tools fail
"""

import asyncio
import json
import logging
import tempfile
import os
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass

from asset_manager import VulnerabilityFinding
# Import adaptive rate controller for intelligent rate limiting
from .adaptive_rate_controller import adaptive_rate_controller

logger = logging.getLogger(__name__)

@dataclass
class ToolConfig:
    """Configuration for a security tool - now with adaptive intelligence"""
    name: str
    executable_path: str
    timeout: int = 300
    output_format: str = "json"
    safe_for_bug_bounty: bool = True

    # Note: rate_limit and max_concurrent are now dynamically determined
    # by the adaptive rate controller based on real-time performance

class UniversalToolRunner:
    """Universal orchestrator for security tools"""

    def __init__(self):
        self.tools = self._initialize_tools()
        self.running_processes = {}

    def _initialize_tools(self) -> Dict[str, ToolConfig]:
        """Initialize tool configurations - rates/concurrency now adaptive"""
        return {
            # LFI Detection
            'nuclei-lfi': ToolConfig(
                name='nuclei-lfi',
                executable_path='/home/michael/go/bin/nuclei',
                timeout=120,
                safe_for_bug_bounty=True
            ),

            # XSS Detection
            'dalfox': ToolConfig(
                name='dalfox',
                executable_path='/home/michael/go/bin/dalfox',
                timeout=180,
                safe_for_bug_bounty=True
            ),

            # SQL Injection
            'sqlmap': ToolConfig(
                name='sqlmap',
                executable_path='/home/michael/.local/bin/sqlmap',
                timeout=600,
                safe_for_bug_bounty=True
            ),

            # Directory Discovery
            'ffuf': ToolConfig(
                name='ffuf',
                executable_path='/home/michael/go/bin/ffuf',
                timeout=300,
                safe_for_bug_bounty=True
            ),

            # Nuclei General Templates
            'nuclei-general': ToolConfig(
                name='nuclei-general',
                executable_path='/home/michael/go/bin/nuclei',
                timeout=180,
                safe_for_bug_bounty=True
            ),

            # Command Injection
            'commix': ToolConfig(
                name='commix',
                executable_path='/usr/bin/commix',
                timeout=300,
                safe_for_bug_bounty=True
            )
        }

    async def run_tool(self, tool_name: str, url: str, **kwargs) -> List[VulnerabilityFinding]:
        """Universal tool runner interface"""

        if tool_name not in self.tools:
            logger.warning(f"Unknown tool: {tool_name}")
            return []

        tool_config = self.tools[tool_name]

        # Check if tool executable exists
        if not os.path.exists(tool_config.executable_path):
            logger.warning(f"Tool not found: {tool_config.executable_path}")
            return []

        try:
            # Route to specific tool runner
            if tool_name == 'nuclei-lfi':
                return await self._run_nuclei_lfi(url, tool_config, **kwargs)
            elif tool_name == 'nuclei-general':
                return await self._run_nuclei_general(url, tool_config, **kwargs)
            elif tool_name == 'dalfox':
                return await self._run_dalfox(url, tool_config, **kwargs)
            elif tool_name == 'sqlmap':
                return await self._run_sqlmap(url, tool_config, **kwargs)
            elif tool_name == 'ffuf':
                return await self._run_ffuf(url, tool_config, **kwargs)
            elif tool_name == 'commix':
                return await self._run_commix(url, tool_config, **kwargs)
            else:
                logger.warning(f"No runner implemented for tool: {tool_name}")
                return []

        except Exception as e:
            logger.error(f"Tool {tool_name} failed on {url}: {e}")
            return []

    async def _run_nuclei_lfi(self, url: str, config: ToolConfig, **kwargs) -> List[VulnerabilityFinding]:
        """Run Nuclei LFI-specific templates with enhanced options"""
        cmd = [
            config.executable_path,
            "-u", url,
            "-id", "linux-lfi-fuzzing",  # Specific LFI template
            "-json",                     # JSON output for parsing
            "-silent",                   # Suppress banner/info
            "-no-color",                # No ANSI colors in output
            "-rate-limit", str(config.rate_limit),  # Respectful rate limiting
            "-timeout", "10s",           # Per-request timeout
            "-retries", "1",             # Single retry for failed requests
            "-severity", "medium,high,critical"  # Skip low-severity findings
        ]

        result = await self._execute_tool(cmd, config.timeout)
        return self._parse_nuclei_output(result, "LFI", url)

    async def _run_nuclei_general(self, url: str, config: ToolConfig, templates: List[str] = None, **kwargs) -> List[VulnerabilityFinding]:
        """Run Nuclei with general vulnerability templates"""
        cmd = [
            config.executable_path,
            "-u", url,
            "-json",
            "-silent",
            "-rate-limit", str(config.rate_limit)
        ]

        # Add specific templates if provided
        if templates:
            for template in templates:
                cmd.extend(["-t", template])
        else:
            # Default safe templates for bug bounty
            cmd.extend(["-t", "vulnerabilities/", "-t", "exposures/"])

        result = await self._execute_tool(cmd, config.timeout)
        return self._parse_nuclei_output(result, "NUCLEI_GENERAL", url)

    async def _run_dalfox(self, url: str, config: ToolConfig, **kwargs) -> List[VulnerabilityFinding]:
        """Run Dalfox XSS scanner with comprehensive options"""
        cmd = [
            config.executable_path,
            "url", url,
            "--format", "json",          # JSON output for parsing
            "--silence",                 # Suppress progress output
            "--delay", str(max(100, 1000 // config.rate_limit)),  # Rate limiting (min 100ms)
            "--timeout", "10",           # Per-request timeout
            "--worker", "5",             # Limited concurrent workers for bug bounty
            "--skip-bav",               # Skip Basic Another Vulnerability scan
            "--waf-evasion",            # Enable WAF evasion techniques
            "--follow-redirects",       # Follow redirects
            "--mining-dict",            # Enable parameter dictionary mining
            "--mining-dom"              # Enable DOM-based parameter mining
        ]

        # Add custom headers for better coverage
        cmd.extend(["--header", "X-Forwarded-For: 127.0.0.1"])
        cmd.extend(["--header", "X-Real-IP: 127.0.0.1"])

        result = await self._execute_tool(cmd, config.timeout)
        return self._parse_dalfox_output(result, url)

    async def _run_sqlmap(self, url: str, config: ToolConfig, **kwargs) -> List[VulnerabilityFinding]:
        """Run SQLMap with bug bounty safe options"""
        cmd = [
            config.executable_path,
            "-u", url,
            "--batch",                  # Never ask for user input
            "--level", "2",             # Moderate testing level (1-5)
            "--risk", "1",              # Low risk for bug bounty safety (1-3)
            "--timeout", "10",          # Connection timeout
            "--retries", "1",           # Single retry for failed requests
            "--delay", str(max(1, int(1.0 / config.rate_limit))),  # Rate limiting
            "--technique", "B",         # Boolean-based blind only (safer)
            "--no-cast",               # Avoid casting payloads
            "--skip-static",           # Skip testing static parameters
            "--flush-session",         # Clean session for fresh test
            "--disable-coloring",      # No ANSI colors
            "--answers", "quit=N,crack=N,dict=N,continue=Y"  # Auto-answer prompts
        ]

        result = await self._execute_tool(cmd, config.timeout)
        return self._parse_sqlmap_output(result, url)

    async def _run_ffuf(self, url: str, config: ToolConfig, wordlist: str = None, **kwargs) -> List[VulnerabilityFinding]:
        """Run ffuf directory discovery"""
        if not wordlist:
            # Use a small, safe wordlist for bug bounty
            wordlist = "/usr/share/wordlists/dirb/common.txt"

        cmd = [
            config.executable_path,
            "-u", f"{url}/FUZZ",
            "-w", wordlist,
            "-mc", "200,301,302,403",  # Common interesting status codes
            "-rate", str(config.rate_limit),
            "-json"
        ]

        result = await self._execute_tool(cmd, config.timeout)
        return self._parse_ffuf_output(result, url)

    async def _run_commix(self, url: str, config: ToolConfig, **kwargs) -> List[VulnerabilityFinding]:
        """Run Commix command injection scanner"""
        cmd = [
            config.executable_path,
            "--url", url,
            "--batch",
            "--level", "2",
            "--delay", str(1.0 / config.rate_limit)
        ]

        result = await self._execute_tool(cmd, config.timeout)
        return self._parse_commix_output(result, url)

    async def _execute_tool(self, cmd: List[str], timeout: int) -> Dict[str, Any]:
        """Execute a tool command with timeout and error handling"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )

            return {
                'stdout': stdout.decode('utf-8', errors='ignore'),
                'stderr': stderr.decode('utf-8', errors='ignore'),
                'returncode': process.returncode
            }

        except asyncio.TimeoutError:
            logger.warning(f"Tool command timed out: {' '.join(cmd[:3])}")
            return {'stdout': '', 'stderr': 'Timeout', 'returncode': -1}
        except Exception as e:
            logger.error(f"Tool execution failed: {e}")
            return {'stdout': '', 'stderr': str(e), 'returncode': -1}

    def _parse_nuclei_output(self, result: Dict[str, Any], vuln_type: str, url: str) -> List[VulnerabilityFinding]:
        """Parse Nuclei JSON output to VulnerabilityFinding objects"""
        findings = []

        if not result.get('stdout'):
            return findings

        for line in result['stdout'].strip().split('\n'):
            if not line.strip():
                continue

            try:
                nuclei_result = json.loads(line)

                # Extract vulnerability information
                info = nuclei_result.get('info', {})
                severity = info.get('severity', 'Medium').title()

                finding = VulnerabilityFinding(
                    url=nuclei_result.get('matched-at', url),
                    vuln_type=vuln_type,
                    severity=severity,
                    confidence=0.95,  # High confidence for Nuclei templates
                    payload=nuclei_result.get('matcher-name', 'Nuclei detection'),
                    evidence=f"Nuclei template: {info.get('name', 'Unknown')}",
                    discovered_at=datetime.now(),
                    impact_description=info.get('description', f"{vuln_type} vulnerability detected"),
                    remediation=info.get('remediation', 'Review and fix identified vulnerability'),
                    affected_parameter="nuclei_detected"
                )
                findings.append(finding)

            except json.JSONDecodeError:
                continue

        return findings

    def _parse_dalfox_output(self, result: Dict[str, Any], url: str) -> List[VulnerabilityFinding]:
        """Parse Dalfox JSON output"""
        findings = []

        if not result.get('stdout'):
            return findings

        try:
            dalfox_result = json.loads(result['stdout'])

            for vuln in dalfox_result.get('vulnerabilities', []):
                finding = VulnerabilityFinding(
                    url=vuln.get('url', url),
                    vuln_type="XSS",
                    severity="High",
                    confidence=0.90,
                    payload=vuln.get('payload', ''),
                    evidence=f"Dalfox XSS: {vuln.get('evidence', '')}",
                    discovered_at=datetime.now(),
                    impact_description="Cross-site scripting vulnerability allows code execution",
                    remediation="Implement proper input validation and output encoding",
                    affected_parameter=vuln.get('parameter', 'unknown')
                )
                findings.append(finding)

        except json.JSONDecodeError:
            pass

        return findings

    def _parse_sqlmap_output(self, result: Dict[str, Any], url: str) -> List[VulnerabilityFinding]:
        """Parse SQLMap output for SQL injection findings"""
        findings = []
        stdout = result.get('stdout', '').lower()

        # Look for SQL injection indicators in SQLMap output
        sqli_indicators = [
            'is vulnerable',
            'injection point',
            'parameter appears to be',
            'payload used:',
            'type: boolean-based blind',
            'type: time-based blind',
            'type: error-based',
            'type: union query'
        ]

        if any(indicator in stdout for indicator in sqli_indicators):
            # Extract more details from output if possible
            severity = "Critical"
            if "time-based" in stdout:
                technique = "Time-based blind"
            elif "boolean-based" in stdout:
                technique = "Boolean-based blind"
            elif "error-based" in stdout:
                technique = "Error-based"
            elif "union" in stdout:
                technique = "UNION query"
            else:
                technique = "SQL injection"

            finding = VulnerabilityFinding(
                url=url,
                vuln_type="SQL_INJECTION",
                severity=severity,
                confidence=0.95,  # High confidence for SQLMap
                payload=f"SQLMap {technique}",
                evidence=f"SQLMap confirmed {technique} SQL injection",
                discovered_at=datetime.now(),
                impact_description="SQL injection allows unauthorized database access",
                remediation="Use parameterized queries and input validation",
                affected_parameter="sqlmap_detected"
            )
            findings.append(finding)

        return findings

    def _parse_ffuf_output(self, result: Dict[str, Any], url: str) -> List[VulnerabilityFinding]:
        """Parse ffuf output for directory discovery"""
        findings = []

        # ffuf findings are informational, not vulnerabilities
        # We'd store these as assets instead of vulnerabilities

        return findings

    def _parse_commix_output(self, result: Dict[str, Any], url: str) -> List[VulnerabilityFinding]:
        """Parse Commix command injection output"""
        findings = []

        if 'command injection' in result.get('stdout', '').lower():
            finding = VulnerabilityFinding(
                url=url,
                vuln_type="COMMAND_INJECTION",
                severity="Critical",
                confidence=0.90,
                payload="Commix detected",
                evidence="Commix confirmed command injection",
                discovered_at=datetime.now(),
                impact_description="Command injection allows arbitrary command execution",
                remediation="Implement proper input validation and avoid system calls",
                affected_parameter="commix_detected"
            )
            findings.append(finding)

        return findings

# Global instance for easy access
tool_runner = UniversalToolRunner()