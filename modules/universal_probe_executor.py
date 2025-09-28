"""Execute adaptive probe plans and score resulting signals."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import aiohttp

from .adaptive_probe_planner import ProbePlan, ProbeVariant

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ResponseSnapshot:
    label: str
    status: int
    body: str
    headers: Dict[str, str]
    latency_ms: float


@dataclass(slots=True)
class FindingCandidate:
    vulnerability: str
    plan_id: str
    score: float
    variant_label: str
    url: str
    signals: Dict[str, Any]
    evidence: Dict[str, Any]
    knowledge_snippets: List[str]
    variant_metadata: Dict[str, Any]


class UniversalProbeExecutor:
    """Runs probe variants and evaluates signal strength."""

    SIGNAL_WEIGHTS = {
        "status_code_change": 0.35,
        "content_difference": 0.25,
        "reflection_indicator": 0.25,
        "html_execution": 0.35,
        "error_anomaly": 0.2,
        "outbound_indicator": 0.3,
    }

    def __init__(self, timeout: float = 12.0) -> None:
        self.timeout = timeout

    async def execute(self, plans: Iterable[ProbePlan], session: Optional[aiohttp.ClientSession] = None) -> List[FindingCandidate]:
        own_session = False
        if session is None:
            timeout_cfg = aiohttp.ClientTimeout(total=self.timeout)
            session = aiohttp.ClientSession(timeout=timeout_cfg)
            own_session = True

        findings: List[FindingCandidate] = []
        try:
            for plan in plans:
                plan_findings = await self._run_plan(plan, session)
                findings.extend(plan_findings)
        finally:
            if own_session:
                await session.close()

        return findings

    async def _run_plan(self, plan: ProbePlan, session: aiohttp.ClientSession) -> List[FindingCandidate]:
        responses: Dict[str, ResponseSnapshot] = {}
        for variant in plan.variants:
            snapshot = await self._execute_variant(variant, session)
            responses[variant.label] = snapshot

        candidates: List[FindingCandidate] = []
        control = next((plan.variants[idx] for idx, variant in enumerate(plan.variants) if variant.metadata.get("role") == "control"), None)
        control_snapshot = responses.get(control.label) if control else None

        for variant in plan.variants:
            if variant.metadata.get("role") != "mutation":
                continue
            mutation_snapshot = responses.get(variant.label)
            if not mutation_snapshot or not control_snapshot:
                continue
            signals = self._evaluate_signals(plan, control, control_snapshot, variant, mutation_snapshot)
            score = self._score_signals(signals, plan.signals)
            evidence = self._build_evidence(plan, control_snapshot, mutation_snapshot, variant, signals)
            if score >= 0.5:
                candidate = FindingCandidate(
                    vulnerability=plan.vulnerability,
                    plan_id=plan.playbook_id,
                    score=score,
                    variant_label=variant.label,
                    url=variant.url,
                    signals=signals,
                    evidence=evidence,
                    knowledge_snippets=plan.knowledge_snippets,
                    variant_metadata=dict(variant.metadata),
                )
                candidates.append(candidate)
        return candidates

    async def _execute_variant(self, variant: ProbeVariant, session: aiohttp.ClientSession) -> ResponseSnapshot:
        start = time.perf_counter()
        try:
            async with session.request(variant.method, variant.url, json=variant.body if isinstance(variant.body, (dict, list)) else None, data=variant.body if isinstance(variant.body, (bytes, str)) else None, headers=variant.headers) as resp:
                text = await resp.text(errors="ignore")
                latency_ms = (time.perf_counter() - start) * 1000
                snapshot = ResponseSnapshot(
                    label=variant.label,
                    status=resp.status,
                    body=text[:4000],
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    latency_ms=latency_ms,
                )
                logger.debug("Probe %s %s -> %s (%sms)", variant.method, variant.url, resp.status, int(latency_ms))
                return snapshot
        except asyncio.TimeoutError:
            latency_ms = (time.perf_counter() - start) * 1000
            logger.debug("Probe timeout for %s", variant.url)
            return ResponseSnapshot(
                label=variant.label,
                status=599,
                body="",
                headers={},
                latency_ms=latency_ms,
            )
        except Exception as exc:
            latency_ms = (time.perf_counter() - start) * 1000
            logger.debug("Probe exception for %s: %s", variant.url, exc)
            return ResponseSnapshot(
                label=variant.label,
                status=598,
                body=str(exc),
                headers={},
                latency_ms=latency_ms,
            )

    # ------------------------------------------------------------------
    def _evaluate_signals(
        self,
        plan: ProbePlan,
        control_variant: ProbeVariant,
        control_response: ResponseSnapshot,
        mutation_variant: ProbeVariant,
        mutation_response: ResponseSnapshot,
    ) -> Dict[str, Any]:
        signals: Dict[str, Any] = {}
        # Status
        if mutation_response.status != control_response.status:
            signals["status_code_change"] = {
                "before": control_response.status,
                "after": mutation_response.status,
            }

        # Content difference using simple ratio
        control_len = max(len(control_response.body), 1)
        delta = abs(len(mutation_response.body) - len(control_response.body)) / control_len
        if delta >= 0.15:
            signals["content_difference"] = round(delta, 3)

        # Reflection indicator based on payload or mutation metadata
        if payload := mutation_variant.metadata.get("payload"):
            if payload[:120] in mutation_response.body and payload[:120] not in control_response.body:
                signals["reflection_indicator"] = payload[:120]
        elif mutation_variant.metadata.get("template") == "numeric_offset":
            mutated_value = str(mutation_variant.metadata.get("mutated_value"))
            if mutated_value and mutated_value in mutation_response.body and mutated_value not in control_response.body:
                signals["reflection_indicator"] = mutated_value

        # HTML execution heuristics
        if "<script" in mutation_response.body.lower() or "onerror=" in mutation_response.body.lower():
            signals["html_execution"] = True

        # Error anomaly detection
        if mutation_response.status >= 500 or "exception" in mutation_response.body.lower():
            signals["error_anomaly"] = mutation_response.status

        # Outbound indicator (SSRF hints)
        if any(token in mutation_response.body.lower() for token in ["metadata", "169.254.169.254", "connection refused", "localhost"]):
            signals["outbound_indicator"] = True

        return signals

    def _score_signals(self, signals: Dict[str, Any], desired_signals: List[str]) -> float:
        if not signals:
            return 0.0
        weights = []
        for signal, payload in signals.items():
            weight = self.SIGNAL_WEIGHTS.get(signal, 0.1)
            if desired_signals and signal not in desired_signals:
                weight *= 0.5
            weights.append(weight)
        total = sum(weights)
        max_possible = sum(self.SIGNAL_WEIGHTS.get(sig, 0.1) for sig in (desired_signals or signals.keys())) or 1.0
        return round(min(total / max_possible, 1.0), 3)

    def _build_evidence(
        self,
        plan: ProbePlan,
        control: ResponseSnapshot,
        mutation: ResponseSnapshot,
        mutation_variant: ProbeVariant,
        signals: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "plan": plan.playbook_id,
            "variant": mutation_variant.label,
            "signals": signals,
            "control_status": control.status,
            "mutation_status": mutation.status,
            "control_preview": control.body[:400],
            "mutation_preview": mutation.body[:400],
        }


__all__ = [
    "UniversalProbeExecutor",
    "FindingCandidate",
    "ResponseSnapshot",
]
