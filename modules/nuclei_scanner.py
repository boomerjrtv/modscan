#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nuclei Scanner (restored)
- Provides NucleiVulnerabilityScanner with async scanning entrypoints
- Handles cases where nuclei binary or templates are missing by falling back
  to minimal HTTP checks
- Stores findings in the "vulnerabilities" table via asset_manager
"""
from __future__ import annotations

import asyncio
import aiohttp
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import logging
from asset_manager import VulnerabilityFinding

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def _safe_json_dumps(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False)
    except Exception:
        return str(obj)

class NucleiVulnerabilityScanner:
    def __init__(self, asset_manager, config: Dict[str, Any]):
        self.asset_manager = asset_manager
        self.config = config or {}
        self.root = Path(self.config.get("ROOT_DIR") or Path(__file__).resolve().parents[1])
        self.nuclei_path = self._detect_nuclei_binary()
        self.templates_path = self._get_nuclei_templates_path()
        self.available = bool(self.nuclei_path and self.templates_path and Path(self.templates_path).exists())

        templates_exist = Path(self.templates_path).exists() if self.templates_path else False
        binary_path = self.nuclei_path if self.nuclei_path else None
        logger.info("[Nuclei] binary=%s, templates=%s exists=%s", binary_path, self.templates_path, templates_exist)

    # ---------------- Detection ----------------

    def _detect_nuclei_binary(self) -> Optional[Path]:
        # Allow override via config or env
        if self.config.get("NUCLEI_BIN"):
            p = Path(self.config["NUCLEI_BIN"])
            if p.exists():
                return p
        if os.getenv("NUCLEI_BIN"):
            p = Path(os.getenv("NUCLEI_BIN"))
            if p.exists():
                return p
        # Look on PATH
        exe = shutil.which("nuclei")
        return Path(exe) if exe else None

    def _get_nuclei_templates_path(self) -> Optional[str]:
        """
        Determine templates directory. Precedence:
        1) config["NUCLEI_TEMPLATES"]
        2) env NUCLEI_TEMPLATES
        3) ~/.local/nuclei-templates
        4) ./nuclei-templates under repo root
        """
        # 1
        direct = self.config.get("NUCLEI_TEMPLATES")
        if direct and Path(direct).exists():
            logger.info(f"[Nuclei] Using templates (config): {direct}")
            return direct

        # 2
        envp = os.getenv("NUCLEI_TEMPLATES")
        if envp and Path(envp).exists():
            logger.info(f"[Nuclei] Using templates (env): {envp}")
            return envp

        # 3
        home_default = Path.home() / ".local" / "nuclei-templates"
        if home_default.exists():
            logger.info(f"[Nuclei] Using templates (~/.local): {home_default}")
            return str(home_default)

        # 4
        repo_default = self.root / "nuclei-templates"
        if repo_default.exists():
            logger.info(f"[Nuclei] Using templates (repo): {repo_default}")
            return str(repo_default)

        logger.warning("[Nuclei] No templates directory found")
        return None

    # ---------------- Public API ----------------

    async def scan_assets_for_vulnerabilities(self, assets: List[Dict[str, Any]]) -> int:
        """
        Entry point used by engine. Returns the number of findings stored.
        """
        urls = [a.get("url") for a in assets if a.get("url")]
        return await self.scan_urls(urls)

    async def scan_urls(self, urls: List[str]) -> int:
        if not urls:
            return 0
        if not self.available:
            logger.warning("Nuclei not available or templates missing; running minimal HTTP checks instead")
            return await self._fallback_minimal_scan(urls)

        # write URLs to a temp file for nuclei -l
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            target_file = f.name
            for u in urls:
                f.write(u.strip() + "\n")

        try:
            return await self._run_nuclei_scan(target_file, intensity=self.config.get("NUCLEI_INTENSITY", "MEDIUM"))
        finally:
            try:
                Path(target_file).unlink(missing_ok=True)
            except Exception:
                pass

    # ---------------- Minimal Fallback ----------------

    async def _fallback_minimal_scan(self, urls: List[str]) -> int:
        findings = 0
        timeout = aiohttp.ClientTimeout(total=10)
        headers = {"User-Agent": "ModScan-MinimalScanner/1.0"}
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            for base in urls[:200]:
                try:
                    async with session.get(base, allow_redirects=True) as resp:
                        hdrs = {k.lower(): v for k, v in resp.headers.items()}
                        # Insecure transport
                        if str(base).startswith("http://"):
                            await self._store_minimal_finding(base, "INSECURE_TRANSPORT", "Medium",
                                                              "Endpoint over HTTP without TLS")
                            findings += 1
                        # Missing security headers
                        missing = []
                        for h in ["content-security-policy", "x-frame-options", "strict-transport-security"]:
                            if h not in hdrs:
                                missing.append(h)
                        if missing:
                            await self._store_minimal_finding(base, "MISSING_SECURITY_HEADERS", "Low",
                                                              f"Missing: {', '.join(missing)}")
                            findings += 1

                    # quick sensitive files
                    for p, vt, sev, evpat in [
                        ("/.env", "SENSITIVE_FILE", "High", "APP_KEY"),
                        ("/.git/HEAD", "SENSITIVE_FILE", "High", "refs/heads"),
                        ("/phpinfo.php", "INFO_DISCLOSURE", "Medium", "phpinfo()"),
                    ]:
                        url = base.rstrip("/") + p
                        try:
                            async with session.get(url, allow_redirects=True) as r2:
                                if r2.status == 200:
                                    text = await r2.text()
                                    if evpat.lower() in text.lower():
                                        await self._store_minimal_finding(url, vt, sev, f"Evidence: {evpat}")
                                        findings += 1
                        except Exception:
                            continue
                except Exception:
                    continue
        return findings

    async def _store_minimal_finding(self, url: str, vtype: str, severity: str, evidence: str):
        try:
            asset_id = await self._get_asset_id_by_url(url)
            if not asset_id:
                return
            finding = VulnerabilityFinding(
                url=url,
                vuln_type=vtype,
                severity=severity.capitalize(),
                confidence=0.6,
                payload="",
                evidence=evidence,
                discovered_at=datetime.now()
            )
            # Asset manager unified API (if available)
            if hasattr(self.asset_manager, "add_vulnerability_finding"):
                self.asset_manager.add_vulnerability_finding(finding, asset_id)
            else:
                # Fallback to direct insert
                await self._insert_vuln_row(asset_id, vtype, evidence, severity.capitalize(), payload="")
        except Exception:
            pass

    # ---------------- Nuclei Execution ----------------

    async def _run_nuclei_scan(self, targets_file: str, intensity: str = "MEDIUM") -> int:
        """
        Run nuclei and parse JSONL results.
        """
        cmd = [
            str(self.nuclei_path),
            "-l", targets_file,
            "-t", str(self.templates_path),
            "-jsonl",
            "-silent",
        ]
        # Respect HTTP proxy env if set; nothing extra needed here

        logger.info(f"[Nuclei] Running: {' '.join(cmd)}")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        findings = 0
        # Consume stdout lines as JSONL
        assert proc.stdout is not None
        async for raw in proc.stdout:
            try:
                line = raw.decode("utf-8", "replace").strip()
                if not line:
                    continue
                finding = json.loads(line)
                ok = await self._process_nuclei_finding(finding)
                if ok:
                    findings += 1
            except Exception as e:
                logger.error(f"[Nuclei] JSON parse error: {e}")
                continue

        # Drain stderr for logs
        if proc.stderr:
            err = (await proc.stderr.read()).decode("utf-8", "replace")
            if err.strip():
                logger.warning(f"[Nuclei] stderr: {err}")

        rc = await proc.wait()
        logger.info(f"[Nuclei] Exit code: {rc}, stored findings: {findings}")
        return findings

    async def scan_urls_by_cves(self, urls: List[str], cves: List[str]) -> int:
        """Run a CVE-focused Nuclei scan limited to provided CVE tags (best-effort).
        Falls back to generic '-tags cve' if specific tags unsupported.
        """
        if not urls or not cves:
            return 0
        if not self.available:
            logger.warning("[Nuclei] Not available; skipping CVE-focused run")
            return 0
        # Write URLs to temp
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            target_file = f.name
            for u in urls:
                f.write(u.strip() + "\n")
        try:
            cmd = [
                str(self.nuclei_path),
                "-l", target_file,
                "-t", str(self.templates_path),
                "-jsonl",
                "-silent",
            ]
            # Limit by CVE tags when possible
            try:
                tag_arg = ",".join(sorted(set(cves)))
                if tag_arg:
                    cmd += ["-tags", tag_arg]
                else:
                    cmd += ["-tags", "cve"]
            except Exception:
                cmd += ["-tags", "cve"]
            logger.info(f"[Nuclei] CVE-focused: {' '.join(cmd)}")
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            findings = 0
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                try:
                    data = json.loads(line.decode('utf-8', errors='ignore'))
                    await self._store_nuclei_result(data)
                    findings += 1
                except Exception:
                    continue
            await proc.wait()
            return findings
        finally:
            try:
                Path(target_file).unlink(missing_ok=True)
            except Exception:
                pass

    async def _process_nuclei_finding(self, finding: Dict[str, Any]) -> bool:
        try:
            template_id = finding.get("template-id", "unknown")
            template_name = finding.get("info", {}).get("name", "Unknown Vulnerability")
            severity = str(finding.get("info", {}).get("severity", "medium")).upper()
            matched_at = finding.get("matched-at", "")

            description = finding.get("info", {}).get("description", template_name)
            evidence = {
                "template_id": template_id,
                "matched_at": matched_at,
                "curl_command": finding.get("curl-command", ""),
                "request": finding.get("request", ""),
                "response": finding.get("response", ""),
                "extracted_results": finding.get("extracted-results", []),
            }

            asset_id = await self._get_asset_id_by_url(matched_at)
            if not asset_id:
                logger.warning(f"[Nuclei] No asset found for URL: {matched_at}")
                return False

            # Preferred unified insert via asset_manager
            if hasattr(self.asset_manager, "add_vulnerability_finding"):
                vf = VulnerabilityFinding(
                    url=matched_at,
                    vuln_type=template_name.upper(),
                    severity=severity.capitalize(),
                    confidence=0.9,
                    payload=template_id,
                    evidence=_safe_json_dumps(evidence),
                    discovered_at=datetime.now()
                )
                self.asset_manager.add_vulnerability_finding(vf, asset_id)
            else:
                # Direct DB insert fallback
                await self._insert_vuln_row(asset_id, template_name, description, severity.capitalize(),
                                            payload=template_id, evidence=json.dumps(evidence))

            logger.info(f"🚨 VULNERABILITY STORED: {template_name} on {matched_at}")
            return True
        except Exception as e:
            logger.error(f"[Nuclei] Error processing finding: {e}")
            return False

    async def _insert_vuln_row(self, asset_id: int, vtype: str, description: str,
                               severity: str, payload: str = "", evidence: str = ""):
        try:
            # asset_manager must expose _get_db() when unified API not present
            if not hasattr(self.asset_manager, "_get_db"):
                return
            with self.asset_manager._get_db() as db:
                db.execute(
                    """
                    INSERT INTO vulnerabilities
                    (asset_id, type, description, severity, evidence, payload, detected_at, confidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        asset_id,
                        vtype,
                        description,
                        severity,
                        evidence or "",
                        payload or "",
                        datetime.now().isoformat(),
                        0.9,
                    ),
                )
                db.commit()
        except Exception as e:
            logger.error(f"[Nuclei] Insert vuln row failed: {e}")

    async def _get_asset_id_by_url(self, url: str) -> Optional[int]:
        try:
            if hasattr(self.asset_manager, "_get_db"):
                with self.asset_manager._get_db() as db:
                    row = db.execute("SELECT id FROM assets WHERE url = ?", (url,)).fetchone()
                    return row[0] if row else None
            return None
        except Exception:
            return None

# Integration function for the main engine
async def scan_with_nuclei(asset_manager, assets: List[Dict[str, Any]], config: Dict[str, Any]) -> int:
    scanner = NucleiVulnerabilityScanner(asset_manager, config)
    return await scanner.scan_assets_for_vulnerabilities(assets)
