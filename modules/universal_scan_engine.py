"""Top-level adaptive scan engine that orchestrates planning + execution."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import logging

from asset_manager import VulnerabilityFinding

from .adaptive_probe_planner import AdaptiveProbePlanner
from .universal_playbook_registry import PlaybookRegistry
from .universal_knowledge_index import UniversalKnowledgeIndex
from .universal_probe_executor import FindingCandidate, UniversalProbeExecutor

logger = logging.getLogger(__name__)


class UniversalScanEngine:
    """High-level coordinator for the adaptive scanning workflow."""

    def __init__(self, asset_manager, config: Optional[Dict[str, Any]] = None) -> None:
        self.asset_manager = asset_manager
        self.config = config or {}

        playbook_dir = self._resolve_path(self.config.get("playbooks", {}).get("directory"))
        knowledge_db = self._resolve_path(self.config.get("knowledge_index", {}).get("db_path"))
        seed_dir = self._resolve_path(self.config.get("knowledge_index", {}).get("seed_dir"))
        timeout = float(self.config.get("adaptive_scanner", {}).get("probe_timeout", 12.0))

        self.playbook_registry = PlaybookRegistry(playbook_dir)
        self.knowledge_index = UniversalKnowledgeIndex(knowledge_db)
        self.knowledge_index.hydrate_default_corpus(base_dir=seed_dir)
        self.planner = AdaptiveProbePlanner(self.playbook_registry, self.knowledge_index)
        self.executor = UniversalProbeExecutor(timeout=timeout)

    async def run_adaptive_scan(self, asset: Dict[str, Any]) -> List[VulnerabilityFinding]:
        plans = await self.planner.plan(asset)
        if not plans:
            logger.debug("Adaptive planner skipped %s", asset.get("url"))
            return []

        candidates = await self.executor.execute(plans)
        findings: List[VulnerabilityFinding] = []
        for candidate in candidates:
            finding = self._candidate_to_finding(candidate)
            if finding:
                findings.append(finding)
        return findings

    # ------------------------------------------------------------------
    def _candidate_to_finding(self, candidate: FindingCandidate) -> Optional[VulnerabilityFinding]:
        payload = self._infer_payload(candidate)
        affected_parameter = str(candidate.variant_metadata.get("parameter", ""))
        evidence_lines = [
            f"Signals: {candidate.signals}",
            f"Knowledge: {candidate.knowledge_snippets[:2]}",
            f"Plan: {candidate.plan_id} variant {candidate.variant_label}",
        ]
        evidence = "\n".join(evidence_lines)

        severity = self._default_severity(candidate.vulnerability)
        remediation = self._default_remediation(candidate.vulnerability)

        try:
            finding = VulnerabilityFinding(
                url=candidate.url,
                vuln_type=candidate.vulnerability,
                severity=severity,
                confidence=float(candidate.score),
                payload=payload,
                evidence=evidence,
                discovered_at=datetime.utcnow(),
                impact_description="Adaptive probe detected high-risk signals",
                remediation=remediation,
                affected_parameter=affected_parameter,
                raw_request="",  # Capturing raw requests requires HTTP instrumentation
                raw_response=candidate.evidence.get("mutation_preview", ""),
            )
        except Exception as exc:
            logger.error("Failed to convert candidate to finding: %s", exc)
            return None
        return finding

    @staticmethod
    def _infer_payload(candidate: FindingCandidate) -> str:
        metadata = candidate.variant_metadata or {}
        if metadata.get("template") == "ssrf_payloads":
            return str(metadata.get("payload"))
        if metadata.get("template") == "reflection_payloads":
            return str(metadata.get("payload"))
        if metadata.get("template") == "numeric_offset":
            offset = metadata.get("offset")
            mutated_value = metadata.get("mutated_value")
            return f"offset={offset}, value={mutated_value}"
        # Fallback to first signal entry
        signals = candidate.signals
        if signals:
            first_key = next(iter(signals.keys()))
            return str(signals[first_key])
        return ""

    @staticmethod
    def _default_severity(vulnerability: str) -> str:
        mapping = {
            "SSRF": "Critical",
            "IDOR": "High",
            "XSS": "High",
        }
        return mapping.get(vulnerability.upper(), "Medium")

    @staticmethod
    def _default_remediation(vulnerability: str) -> str:
        remediation_map = {
            "SSRF": "Validate outbound destinations and restrict metadata service access.",
            "IDOR": "Enforce object level authorization for every request.",
            "XSS": "Apply contextual output encoding and strong CSP.",
        }
        return remediation_map.get(vulnerability.upper(), "Review application controls and follow OWASP ASVS guidance.")

    def _resolve_path(self, value: Optional[str]) -> Optional[Path]:
        if not value:
            return None
        path = Path(value)
        if not path.is_absolute():
            return Path.cwd() / path
        return path


__all__ = ["UniversalScanEngine"]
