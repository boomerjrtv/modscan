"""Adaptive probing planner that ties together playbooks, knowledge, and target context.

The planner consumes endpoint metadata and produces structured probe plans that
can be executed by the universal scan engine. It uses lightweight heuristics to
fingerprint technology, looks up relevant playbooks, enriches them with
knowledge base snippets, and materializes deterministic probe variants that can
run against any target.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
import json
import logging

from .universal_playbook_registry import Playbook, PlaybookRegistry
from .universal_knowledge_index import UniversalKnowledgeIndex

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class NumericIdentifier:
    location: str  # "path" or "query"
    value: int
    raw: str
    key: Optional[str] = None
    segment_index: Optional[int] = None


@dataclass(slots=True)
class ProbeVariant:
    label: str
    method: str
    url: str
    body: Optional[Any]
    headers: Dict[str, str]
    metadata: Dict[str, Any]


@dataclass(slots=True)
class ProbePlan:
    playbook_id: str
    title: str
    vulnerability: str
    description: str
    signals: List[str]
    knowledge_snippets: List[str]
    variants: List[ProbeVariant]
    context: Dict[str, Any]


class AdaptiveProbePlanner:
    """Generate structured probe plans using playbooks + knowledge retrieval."""

    def __init__(
        self,
        playbook_registry: PlaybookRegistry,
        knowledge_index: UniversalKnowledgeIndex,
    ) -> None:
        self.registry = playbook_registry
        self.knowledge_index = knowledge_index

    # ------------------------------------------------------------------
    async def plan(self, asset: Dict[str, Any]) -> List[ProbePlan]:
        """Generate ordered probe plans for the supplied asset context."""
        context = self._build_context(asset)
        matches = self.registry.get_applicable_playbooks(context)
        if not matches:
            logger.debug("No playbooks matched context for %s", asset.get("url"))
            return []

        plans: List[ProbePlan] = []
        for playbook, enriched_context in matches:
            variants = self._materialize_variants(playbook, asset, enriched_context)
            if not variants:
                continue
            knowledge = self._retrieve_knowledge(playbook, enriched_context)
            plan = ProbePlan(
                playbook_id=playbook.id,
                title=playbook.title,
                vulnerability=playbook.vulnerability,
                description=playbook.description,
                signals=playbook.signals,
                knowledge_snippets=knowledge,
                variants=variants,
                context=enriched_context,
            )
            plans.append(plan)

        return plans

    # ------------------------------------------------------------------
    def _retrieve_knowledge(self, playbook: Playbook, context: Dict[str, Any]) -> List[str]:
        query_terms = [playbook.vulnerability]
        query_terms.extend(context.get("tags", []))
        tech_stack = context.get("tech_stack") or []
        query_terms.extend(tech_stack if isinstance(tech_stack, list) else [tech_stack])
        query = " ".join(str(t) for t in query_terms if t)
        docs = self.knowledge_index.query(query, limit=3, category=playbook.vulnerability.lower())
        snippets: List[str] = []
        for doc in docs:
            summary = doc.get("title") or doc.get("doc_id")
            content = doc.get("content", "")
            if content:
                content = content.strip().splitlines()[0][:280]
            snippets.append(f"{summary}: {content}")
        return snippets

    # ------------------------------------------------------------------
    def _materialize_variants(
        self,
        playbook: Playbook,
        asset: Dict[str, Any],
        context: Dict[str, Any],
    ) -> List[ProbeVariant]:
        url = asset.get("url") or ""
        method = str(asset.get("method") or "GET").upper()
        headers = {k: v for k, v in (asset.get("headers") or {}).items()}

        variants: List[ProbeVariant] = []
        for template in playbook.action_templates:
            template_name = str(template.get("template"))
            if template_name == "numeric_offset":
                variants.extend(
                    self._variants_numeric_offset(template, url, method, headers, context)
                )
            elif template_name == "reflection_payloads":
                variants.extend(
                    self._variants_reflection(template, url, method, headers, context)
                )
            elif template_name == "ssrf_payloads":
                variants.extend(
                    self._variants_ssrf(template, url, method, headers, context)
                )
            else:
                logger.debug("Unknown action template %s in playbook %s", template_name, playbook.id)

        # Deduplicate by (method, url, body)
        unique: Dict[Tuple[str, str, str], ProbeVariant] = {}
        for variant in variants:
            key = (variant.method, variant.url, json.dumps(variant.body, sort_keys=True) if isinstance(variant.body, (dict, list)) else str(variant.body))
            unique[key] = variant

        ordered = list(unique.values())
        if not ordered:
            return []

        # Ensure the control action comes first
        ordered.sort(key=lambda v: (0 if v.metadata.get("role") == "control" else 1, v.label))
        return ordered

    # ------------------------------------------------------------------
    def _variants_numeric_offset(
        self,
        template: Dict[str, Any],
        url: str,
        method: str,
        headers: Dict[str, str],
        context: Dict[str, Any],
    ) -> List[ProbeVariant]:
        identifiers: List[NumericIdentifier] = context.get("numeric_identifiers") or []
        if not identifiers:
            return []

        offsets = template.get("offsets", [-1, 1])
        if not isinstance(offsets, list):
            offsets = [-1, 1]
        limit = int(template.get("sample_size") or len(offsets))

        variants: List[ProbeVariant] = []
        for identifier in identifiers[:2]:  # limit to first two identifiers for safety
            control_variant = ProbeVariant(
                label=f"control_{identifier.raw}",
                method=method,
                url=url,
                body=None,
                headers=headers,
                metadata={
                    "role": "control",
                    "template": "numeric_offset",
                    "identifier": self._identifier_metadata(identifier),
                },
            )
            variants.append(control_variant)

            for offset in offsets[:limit]:
                new_value = identifier.value + int(offset)
                if new_value < 0:
                    continue
                mutated_url = self._replace_numeric(url, identifier, new_value)
                label = f"offset_{offset:+d}".replace("+", "plus_")
                variants.append(
                    ProbeVariant(
                        label=label,
                        method=method,
                        url=mutated_url,
                        body=None,
                        headers=headers,
                        metadata={
                            "role": "mutation",
                            "template": "numeric_offset",
                            "offset": offset,
                            "identifier": self._identifier_metadata(identifier),
                            "mutated_value": new_value,
                        },
                    )
                )

        return variants

    def _variants_reflection(
        self,
        template: Dict[str, Any],
        url: str,
        method: str,
        headers: Dict[str, str],
        context: Dict[str, Any],
    ) -> List[ProbeVariant]:
        payload_family = template.get("payload_family")
        if not payload_family:
            return []
        payloads = self.registry.get_payload_family(str(payload_family))
        if not payloads:
            return []
        max_payloads = int(template.get("max_payloads") or 5)
        payloads = payloads[:max_payloads]

        param_name = template.get("param_name") or self._select_input_parameter(context, fallback="q")
        param_scope = str(template.get("param_scope") or "query")

        variants: List[ProbeVariant] = []
        baseline_value = "modscan-baseline"
        baseline_url = self._inject_query_param(url, param_name, baseline_value)
        variants.append(
            ProbeVariant(
                label="control",
                method=method,
                url=baseline_url,
                body=None,
                headers=headers,
                metadata={
                    "role": "control",
                    "template": "reflection_payloads",
                    "parameter": param_name,
                },
            )
        )

        for idx, payload in enumerate(payloads):
            mutated_url = self._inject_query_param(url, param_name, payload)
            variants.append(
                ProbeVariant(
                    label=f"payload_{idx}",
                    method=method,
                    url=mutated_url,
                    body=None,
                    headers=headers,
                    metadata={
                        "role": "mutation",
                        "template": "reflection_payloads",
                        "payload": payload,
                        "parameter": param_name,
                    },
                )
            )

        return variants

    def _variants_ssrf(
        self,
        template: Dict[str, Any],
        url: str,
        method: str,
        headers: Dict[str, str],
        context: Dict[str, Any],
    ) -> List[ProbeVariant]:
        payload_family = template.get("payload_family")
        if not payload_family:
            return []
        payloads = self.registry.get_payload_family(str(payload_family))
        if not payloads:
            return []
        max_payloads = int(template.get("max_payloads") or 3)
        payloads = payloads[:max_payloads]

        param_name = template.get("param_name") or self._select_url_parameter(context)
        if not param_name:
            return []

        variants: List[ProbeVariant] = []
        control_url = self._inject_query_param(url, param_name, "https://example.com/")
        variants.append(
            ProbeVariant(
                label="control",
                method=method,
                url=control_url,
                body=None,
                headers=headers,
                metadata={
                    "role": "control",
                    "template": "ssrf_payloads",
                    "parameter": param_name,
                },
            )
        )

        for idx, payload in enumerate(payloads):
            mutated_url = self._inject_query_param(url, param_name, payload)
            variants.append(
                ProbeVariant(
                    label=f"payload_{idx}",
                    method=method,
                    url=mutated_url,
                    body=None,
                    headers=headers,
                    metadata={
                        "role": "mutation",
                        "template": "ssrf_payloads",
                        "payload": payload,
                        "parameter": param_name,
                    },
                )
            )

        return variants

    # ------------------------------------------------------------------
    def _build_context(self, asset: Dict[str, Any]) -> Dict[str, Any]:
        url = asset.get("url", "")
        parsed = urlparse(url)
        path = parsed.path or "/"
        method = str(asset.get("method") or "GET").upper()
        headers = asset.get("headers") or {}
        tech_stack = self._normalize_collection(asset.get("tech_stack"))

        tags: set[str] = set()
        if "/api" in path:
            tags.update({"api", "resource"})
        if any(seg in path.lower() for seg in ["login", "auth", "signin", "oauth"]):
            tags.update({"auth", "form", "input"})
        if any(seg in path.lower() for seg in ["search", "query", "filter", "find"]):
            tags.update({"search", "input"})
        if any(seg in path.lower() for seg in ["upload", "file", "image"]):
            tags.update({"file_upload", "fetcher"})
        if method in {"POST", "PUT", "PATCH"}:
            tags.add("input")

        query_params_raw = parse_qsl(parsed.query, keep_blank_values=True)
        query_param_names = [k for k, _ in query_params_raw]

        numeric_identifiers = self._extract_numeric_identifiers(path, query_params_raw)
        if numeric_identifiers:
            tags.add("numeric_identifier")

        has_url_parameter = any(self._looks_like_url(v) or "url" in k.lower() for k, v in query_params_raw)
        if has_url_parameter:
            tags.add("url_handler")

        context = {
            "url": url,
            "host": parsed.hostname or "",
            "path": path,
            "method": method,
            "headers": headers,
            "tech_stack": tech_stack,
            "tags": tags,
            "numeric_identifiers": numeric_identifiers,
            "has_url_parameter": has_url_parameter,
            "query_param_names": query_param_names,
            "supports_payload_injection": bool(query_params_raw or method in {"POST", "PUT", "PATCH"}),
        }
        return context

    # ------------------------------------------------------------------
    @staticmethod
    def _extract_numeric_identifiers(
        path: str,
        query_params: Sequence[Tuple[str, str]],
    ) -> List[NumericIdentifier]:
        identifiers: List[NumericIdentifier] = []
        segments = path.split('/')
        for idx, segment in enumerate(segments):
            if segment and segment.isdigit():
                identifiers.append(
                    NumericIdentifier(
                        location="path",
                        value=int(segment),
                        raw=segment,
                        key=None,
                        segment_index=idx,
                    )
                )

        for key, value in query_params:
            if value and value.isdigit():
                identifiers.append(
                    NumericIdentifier(
                        location="query",
                        value=int(value),
                        raw=value,
                        key=key,
                        segment_index=None,
                    )
                )
        return identifiers

    @staticmethod
    def _select_input_parameter(context: Dict[str, Any], fallback: str = "input") -> str:
        candidates = context.get("query_param_names") or []
        priority = [
            "q",
            "query",
            "search",
            "term",
            "username",
            "message",
            "name",
            "comment",
        ]
        for desired in priority:
            for candidate in candidates:
                if desired == candidate.lower():
                    return candidate
        return candidates[0] if candidates else fallback

    @staticmethod
    def _select_url_parameter(context: Dict[str, Any]) -> Optional[str]:
        candidates = context.get("query_param_names") or []
        priority = ["url", "redirect", "target", "dest", "uri", "link"]
        for desired in priority:
            for candidate in candidates:
                if desired == candidate.lower():
                    return candidate
        return candidates[0] if candidates else None

    @staticmethod
    def _identifier_metadata(identifier: NumericIdentifier) -> Dict[str, Any]:
        return {
            "location": identifier.location,
            "raw": identifier.raw,
            "key": identifier.key,
            "segment_index": identifier.segment_index,
        }

    @staticmethod
    def _replace_numeric(url: str, identifier: NumericIdentifier, new_value: int) -> str:
        parsed = urlparse(url)
        if identifier.location == "path" and identifier.segment_index is not None:
            segments = parsed.path.split('/')
            if 0 <= identifier.segment_index < len(segments):
                segments[identifier.segment_index] = str(new_value)
                new_path = '/'.join(segments)
                parsed = parsed._replace(path=new_path)
        elif identifier.location == "query" and identifier.key:
            params = parse_qsl(parsed.query, keep_blank_values=True)
            updated: List[Tuple[str, str]] = []
            replaced = False
            for key, value in params:
                if not replaced and key == identifier.key and value == identifier.raw:
                    updated.append((key, str(new_value)))
                    replaced = True
                else:
                    updated.append((key, value))
            if not replaced:
                updated.append((identifier.key, str(new_value)))
            parsed = parsed._replace(query=urlencode(updated))
        return urlunparse(parsed)

    @staticmethod
    def _inject_query_param(url: str, name: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        updated: List[Tuple[str, str]] = []
        replaced = False
        for key, existing_value in params:
            if key == name:
                updated.append((key, value))
                replaced = True
            else:
                updated.append((key, existing_value))
        if not replaced:
            updated.append((name, value))
        return urlunparse(parsed._replace(query=urlencode(updated)))

    @staticmethod
    def _looks_like_url(value: str) -> bool:
        if not value:
            return False
        return value.startswith("http://") or value.startswith("https://") or "://" in value

    @staticmethod
    def _normalize_collection(value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, (list, tuple, set)):
            return [str(v) for v in value]
        return [str(value)]


__all__ = [
    "AdaptiveProbePlanner",
    "ProbePlan",
    "ProbeVariant",
    "NumericIdentifier",
]
