"""Universal playbook registry for ModScan.

Loads technology-agnostic probing playbooks and exposes matching utilities
for adaptive vulnerability planning. The registry supports YAML or JSON
playbook bundles and evaluates lightweight fingerprint rules to decide
which playbooks are relevant for a given target context.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
import json
import logging

logger = logging.getLogger(__name__)

try:  # Optional dependency; we fail gracefully if PyYAML is absent
    import yaml  # type: ignore
except Exception:  # pragma: no cover - fallback path when PyYAML missing
    yaml = None


@dataclass(slots=True)
class Playbook:
    """Normalized representation of a vulnerability playbook."""

    id: str
    title: str
    vulnerability: str
    description: str
    triggers: Dict[str, Any]
    action_templates: List[Dict[str, Any]]
    signals: List[str]
    remediation_hints: List[str] = field(default_factory=list)
    source_path: Optional[Path] = None


class PlaybookRegistry:
    """Registry that loads and matches universal vulnerability playbooks."""

    def __init__(self, directory: Optional[Path | str] = None) -> None:
        self.directory = Path(directory or Path.cwd() / "playbooks")
        self.fingerprints: Dict[str, Dict[str, Any]] = {}
        self.playbooks: List[Playbook] = []
        self.payload_families: Dict[str, List[str]] = {}
        self._loaded_files: List[Path] = []

        if not self.directory.exists():
            logger.warning("Playbook directory %s does not exist", self.directory)
            return

        self._load_directory(self.directory)

    # ------------------------------------------------------------------
    # Loading utilities
    # ------------------------------------------------------------------
    def _load_directory(self, directory: Path) -> None:
        files: List[Path] = []
        files.extend(directory.glob("*.yml"))
        files.extend(directory.glob("*.yaml"))
        files.extend(directory.glob("*.json"))

        if not files:
            logger.warning("No playbook bundles found in %s", directory)
            return

        for path in sorted(files):
            try:
                bundle = self._parse_bundle(path)
                if not bundle:
                    continue
                self._loaded_files.append(path)
                self._register_bundle(bundle, path)
                logger.debug("Loaded playbook bundle %s", path.name)
            except Exception as exc:  # pragma: no cover - defensive logging
                logger.error("Failed to load playbook bundle %s: %s", path, exc)

    def _parse_bundle(self, path: Path) -> Optional[Dict[str, Any]]:
        text = path.read_text(encoding="utf-8")
        suffix = path.suffix.lower()

        if suffix in {".json"}:
            return json.loads(text)

        if suffix in {".yml", ".yaml"}:
            if yaml is None:
                raise RuntimeError(
                    "PyYAML not installed; please install pyyaml to load YAML playbooks"
                )
            data = yaml.safe_load(text)
            if isinstance(data, dict):
                return data
            raise ValueError(f"Unexpected YAML structure in {path}")

        raise ValueError(f"Unsupported playbook format: {path}")

    def _register_bundle(self, bundle: Dict[str, Any], source_path: Path) -> None:
        fingerprints = bundle.get("fingerprints") or {}
        for fp_id, definition in fingerprints.items():
            self.fingerprints[fp_id] = definition

        payload_families = bundle.get("payload_families") or {}
        for name, payloads in payload_families.items():
            if isinstance(payloads, list):
                self.payload_families[name] = [str(p) for p in payloads[:100]]

        for raw in bundle.get("playbooks", []) or []:
            playbook = Playbook(
                id=str(raw.get("id")),
                title=str(raw.get("title", raw.get("id", "untitled"))),
                vulnerability=str(raw.get("vulnerability", "UNKNOWN")),
                description=str(raw.get("description", "")),
                triggers=dict(raw.get("triggers", {})),
                action_templates=list(raw.get("action_templates", [])),
                signals=list(raw.get("signals", [])),
                remediation_hints=list(raw.get("remediation_hints", [])),
                source_path=source_path,
            )
            self.playbooks.append(playbook)

    # ------------------------------------------------------------------
    # Matching utilities
    # ------------------------------------------------------------------
    def list_playbooks(self) -> List[str]:
        return [pb.id for pb in self.playbooks]

    def get_payload_family(self, name: str) -> List[str]:
        return self.payload_families.get(name, [])

    def get_applicable_playbooks(self, context: Dict[str, Any]) -> List[Tuple[Playbook, Dict[str, Any]]]:
        """Return playbooks applicable to the supplied context.

        Each returned tuple contains the playbook and a match report with
        contributing fingerprint identifiers & computed tags.
        """
        tags: Set[str] = set(context.get("tags", []))
        matched_fingerprints: List[str] = []

        for fp_id, definition in self.fingerprints.items():
            if self._fingerprint_matches(definition, context, tags):
                matched_fingerprints.append(fp_id)
                tags.update(definition.get("tags", []))

        enriched_context = dict(context)
        enriched_context["tags"] = tags
        enriched_context["matched_fingerprints"] = matched_fingerprints

        results: List[Tuple[Playbook, Dict[str, Any]]] = []
        for playbook in self.playbooks:
            if self._playbook_matches(playbook, enriched_context):
                results.append((playbook, enriched_context))

        return results

    # ------------------------------------------------------------------
    # Matching helpers
    # ------------------------------------------------------------------
    def _fingerprint_matches(
        self,
        definition: Dict[str, Any],
        context: Dict[str, Any],
        current_tags: Set[str],
    ) -> bool:
        match = definition.get("match") or {}
        if not isinstance(match, dict):
            return False

        path = (context.get("path") or context.get("url") or "").lower()
        method = str(context.get("method", "GET")).upper()
        headers = {k.lower(): str(v).lower() for k, v in (context.get("headers") or {}).items()}
        tech_stack = {t.lower() for t in self._as_sequence(context.get("tech_stack"))}

        for key, value in match.items():
            if key == "path_contains":
                if not self._any_substring(path, value):
                    return False
            elif key == "methods_any":
                methods = {str(v).upper() for v in self._as_sequence(value)}
                if method not in methods:
                    return False
            elif key == "tags_any":
                required = set(self._as_sequence(value))
                if not current_tags.intersection(required):
                    return False
            elif key == "tech_stack_any":
                required = {str(v).lower() for v in self._as_sequence(value)}
                if not tech_stack.intersection(required):
                    return False
            elif key == "header_contains":
                if not headers:
                    return False
                required = [str(v).lower() for v in self._as_sequence(value)]
                if not any(any(req in f"{hk}: {hv}" for req in required) for hk, hv in headers.items()):
                    return False
            elif key == "host_contains":
                host = str(context.get("host", "")).lower()
                if not self._any_substring(host, value):
                    return False
            else:
                logger.debug("Unhandled fingerprint rule %s", key)
                return False

        return True

    def _playbook_matches(self, playbook: Playbook, context: Dict[str, Any]) -> bool:
        triggers = playbook.triggers or {}
        tags: Set[str] = set(context.get("tags", []))

        if tags:
            tags.update(self._as_sequence(triggers.get("additional_tags", [])))

        if finger_ids := set(self._as_sequence(triggers.get("fingerprints_any", []))):
            matched = set(context.get("matched_fingerprints", []))
            if matched.isdisjoint(finger_ids):
                return False

        if required_tags := set(self._as_sequence(triggers.get("tags_any", []))):
            if tags.isdisjoint(required_tags):
                return False

        if requires_all := set(self._as_sequence(triggers.get("tags_all", []))):
            if not requires_all.issubset(tags):
                return False

        if triggers.get("requires_numeric_identifier"):
            numeric_identifiers = context.get("numeric_identifiers") or []
            if not numeric_identifiers:
                return False

        if triggers.get("requires_url_parameter"):
            if not context.get("has_url_parameter"):
                return False

        if triggers.get("requires_payload_capability"):
            if not context.get("supports_payload_injection"):
                return False

        return True

    # ------------------------------------------------------------------
    @staticmethod
    def _as_sequence(value: Any) -> Sequence[Any]:
        if value is None:
            return []
        if isinstance(value, (list, tuple, set)):
            return value
        return [value]

    @staticmethod
    def _any_substring(haystack: str, needles: Iterable[Any]) -> bool:
        for needle in needles or []:
            s = str(needle).lower()
            if s and s in haystack:
                return True
        return False


__all__ = ["Playbook", "PlaybookRegistry"]
