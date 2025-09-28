#!/usr/bin/env python3
"""Universal observation cache for AI-guided planning.

Stores structured observations about each endpoint (headers, forms, metadata)
so the planner can make informed decisions without brute forcing everything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import collections

@dataclass
class Observation:
    url: str
    method: str
    status_code: int
    headers: Dict[str, str]
    cookies: Dict[str, str]
    forms: List[Dict[str, Any]]
    body_preview: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    observed_at: datetime = field(default_factory=datetime.utcnow)

    @property
    def host(self) -> str:
        parsed = urlparse(self.url)
        return (parsed.hostname or '').lower()


class ObservationStore:
    """Lightweight cache keyed by host for planner decisions."""

    def __init__(self) -> None:
        self._by_host: Dict[str, List[Observation]] = collections.defaultdict(list)
        self._host_metadata: Dict[str, Dict[str, Any]] = collections.defaultdict(dict)

    def record(self, observation: Observation) -> None:
        host = observation.host
        if not host:
            return
        self._by_host[host].append(observation)

        host_meta = self._host_metadata[host]

        # Track Laravel app keys or other sensitive tokens once per host
        app_keys: List[str] = observation.metadata.get('laravel_app_keys') or []
        if app_keys:
            host_meta.setdefault('laravel_app_keys', set()).update(app_keys)

        xsrf_tokens = observation.metadata.get('xsrf_tokens')
        if xsrf_tokens:
            host_meta['xsrf_tokens_exposed'] = True

        if observation.metadata.get('laravel_detected'):
            host_meta.setdefault('flags', set()).add('laravel_detected')

        technologies = observation.metadata.get('technologies') or []
        if technologies:
            host_meta.setdefault('technologies', set()).update(technologies)

        host_meta['last_observed_at'] = observation.observed_at

    def get_observations(self, host: str) -> List[Observation]:
        return list(self._by_host.get(host.lower(), []))
    
    def has_observed(self, url: str) -> bool:
        host = (urlparse(url).hostname or '').lower()
        if not host:
            return False
        return any(obs.url == url for obs in self._by_host.get(host, []))

    def get_host_metadata(self, host: str) -> Dict[str, Any]:
        host_meta = self._host_metadata.get(host.lower())
        if not host_meta:
            return {}
        # Provide immutable snapshots while keeping internal sets mutable
        snapshot = {}
        for key, value in host_meta.items():
            if isinstance(value, set):
                snapshot[key] = list(sorted(value))
            else:
                snapshot[key] = value
        return snapshot

    def note_exploit_attempt(self, host: str, exploit_id: str) -> None:
        host = host.lower()
        meta = self._host_metadata[host]
        meta.setdefault('exploits_attempted', set()).add(exploit_id)

    def exploit_attempted(self, host: str, exploit_id: str) -> bool:
        host = host.lower()
        attempts = self._host_metadata.get(host, {}).get('exploits_attempted')
        return bool(attempts and exploit_id in attempts)

    def set_host_flag(self, host: str, flag: str) -> None:
        host = host.lower()
        meta = self._host_metadata[host]
        meta.setdefault('flags', set()).add(flag)

    def host_flag(self, host: str, flag: str) -> bool:
        host = host.lower()
        flags = self._host_metadata.get(host, {}).get('flags')
        return bool(flags and flag in flags)
