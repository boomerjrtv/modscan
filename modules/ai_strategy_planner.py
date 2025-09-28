#!/usr/bin/env python3
"""AI-guided strategy planner that pivots off observations instead of brute forcing.

The planner inspects the ObservationStore and proposes targeted exploit routines
(e.g., Laravel insecure deserialization) only when host metadata justifies it.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict, List, Optional
from urllib.parse import urlparse, urljoin
from pathlib import Path
import asyncio
import aiohttp
import re
import os
import logging

from .observation_store import Observation, ObservationStore
from .universal_form_parser import parse_forms

logger = logging.getLogger(__name__)


class PlannedAction:
    """Light wrapper for an async vulnerability routine proposed by the planner."""

    def __init__(self, name: str, executor: Callable[[], Awaitable[List]]):
        self.name = name
        self.executor = executor

    async def run(self) -> List:
        logger.debug(f"🧠 Planner executing action: {self.name}")
        return await self.executor()


class AIStrategyPlanner:
    """Rule-based planner scaffold; swaps out brute force for observation-driven pivots."""

    def __init__(self, observation_store: ObservationStore, scanner: "VulnerabilityScanner") -> None:
        self.observations = observation_store
        self.scanner = scanner

    async def evaluate(
        self,
        asset: Dict,
        latest_observation: Observation,
        session
    ) -> List:
        """Return targeted findings by running only exploits justified by observations."""
        host = latest_observation.host
        host_meta = self.observations.get_host_metadata(host)
        planned_actions: List[PlannedAction] = []

        # Proactively probe Laravel helper endpoints once per host when framework detected
        flags = host_meta.get('flags', []) or []
        laravel_seen = ('laravel_detected' in flags or self.scanner._looks_like_laravel(
            latest_observation.headers, latest_observation.body_preview, latest_observation.url
        ))
        if laravel_seen:
            if not self.observations.host_flag(host, 'laravel_probed'):
                await self._probe_laravel_endpoints(latest_observation, session)
                self.observations.set_host_flag(host, 'laravel_probed')
            if not self.observations.host_flag(host, 'laravel_wordlist'):
                await self._targeted_laravel_wordlist(latest_observation, session)
                self.observations.set_host_flag(host, 'laravel_wordlist')

        # Laravel insecure deserialization chain
        laravel_keys = host_meta.get('laravel_app_keys') or []
        xsrf_exposed = host_meta.get('xsrf_tokens_exposed', False)

        if laravel_keys and xsrf_exposed:
            exploit_id = 'laravel_rce'
            if not self.observations.exploit_attempted(host, exploit_id):
                self.observations.note_exploit_attempt(host, exploit_id)

                async def _run_laravel():
                    return await self.scanner._attempt_laravel_deserialization_exploit(
                        asset,
                        session,
                        latest_observation.body_preview,
                        latest_observation.headers
                    )

                planned_actions.append(PlannedAction('laravel_insecure_deserialization', _run_laravel))

        # Execute planned actions sequentially to keep runtime predictable
        findings: List = []
        for action in planned_actions:
            try:
                result = await action.run()
                if result:
                    findings.extend(result)
            except Exception as exc:
                logger.debug(f"Planner action {action.name} failed: {exc}")

        return findings

    async def _probe_laravel_endpoints(self, observation: Observation, session) -> None:
        """Probe known Laravel helper endpoints to populate observations."""
        try:
            parsed = urlparse(observation.url)
            host = observation.host
            scheme = parsed.scheme or 'http'
            base = f"{scheme}://{parsed.netloc}"

            body = observation.body_preview or ''
            candidate_urls: List[str] = []

            # Collect already parsed forms
            try:
                forms = parse_forms(body, base_url=observation.url)
            except Exception:
                forms = []
            for form in forms or []:
                action = form.get('action') or ''
                if action:
                    candidate_urls.append(urljoin(base, action))

            # Collect same-host links
            for attr in re.findall(r'(?:href|src)\s*=\s*["\']([^"\']+)', body, re.IGNORECASE):
                candidate_urls.append(urljoin(base, attr))

            # Deduplicate and limit to avoid runaway crawling
            seen = set()
            limited_targets: List[str] = []
            for target_url in candidate_urls:
                target_host = (urlparse(target_url).hostname or '').lower()
                if target_host != host or target_url in seen:
                    continue
                if any(obs.url == target_url for obs in self.observations.get_observations(host)):
                    continue
                seen.add(target_url)
                limited_targets.append(target_url)
                if len(limited_targets) >= 20:
                    break

            for target_url in limited_targets:
                try:
                    headers = await self.scanner._get_auth_headers(target_url)
                    async with session.get(target_url, headers=headers, timeout=10) as resp:
                        text = await resp.text()
                        metadata: Dict[str, Any] = {}
                        if self.scanner._looks_like_laravel(dict(resp.headers), text, target_url):
                            metadata['laravel_detected'] = True
                        app_keys = []
                        for match in re.findall(r'APP_KEY[^A-Za-z0-9+/=]*([A-Za-z0-9+/=:\-]{16,})', text, re.IGNORECASE):
                            candidate = match.strip().strip('\"\'')
                            if candidate.lower().startswith('base64:'):
                                candidate = candidate.split(':', 1)[-1]
                            if len(candidate) >= 30:
                                app_keys.append(candidate)
                        if app_keys:
                            metadata['laravel_app_keys'] = app_keys
                        if 'x-xsrf-token' in text.lower() or any('xsrf-token' in k.lower() for k in resp.headers.keys()):
                            metadata['xsrf_tokens'] = True

                        try:
                            forms_found = parse_forms(text, base_url=target_url)
                        except Exception:
                            forms_found = []

                        observation_record = Observation(
                            url=target_url,
                            method='GET',
                            status_code=resp.status,
                            headers=dict(resp.headers),
                            cookies={},
                            forms=forms_found[:5],
                            body_preview=text[:4000],
                            metadata=metadata
                        )
                        self.observations.record(observation_record)
                except Exception as err:
                    logger.debug(f"Laravel crawl failed for {target_url}: {err}")
        except Exception as outer_err:
            logger.debug(f"Laravel probing routine failed: {outer_err}")

    async def _targeted_laravel_wordlist(self, observation: Observation, session) -> None:
        """Use Laravel-specific SecLists entries to discover helper endpoints."""
        try:
            seclists_dir = self._resolve_seclists_dir()
            if not seclists_dir:
                return

            laravel_paths = self._load_laravel_paths(seclists_dir)
            if not laravel_paths:
                return

            host = observation.host
            parsed = urlparse(observation.url)
            base_hosts = {parsed.netloc}
            base_hosts.add(host)
            cleaned_hosts = set(h for h in base_hosts if h)

            base_urls = set()
            for netloc in cleaned_hosts:
                base_urls.add(f"http://{netloc}")
                base_urls.add(f"https://{netloc}")
            if parsed.scheme and parsed.netloc:
                base_urls.add(f"{parsed.scheme}://{parsed.netloc}")

            target_urls: List[str] = []
            for base in base_urls:
                for path in laravel_paths:
                    target_urls.append(urljoin(base, path))

            # Deduplicate and skip already observed URLs
            unique_targets: List[str] = []
            seen = set()
            for url in target_urls:
                if url in seen:
                    continue
                seen.add(url)
                if self.observations.has_observed(url):
                    continue
                unique_targets.append(url)

            if not unique_targets:
                return

            connector = aiohttp.TCPConnector(limit=200, limit_per_host=50)
            timeout = aiohttp.ClientTimeout(total=8)
            semaphore = asyncio.Semaphore(200)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as client:
                async def fetch(url: str) -> None:
                    async with semaphore:
                        try:
                            headers = await self.scanner._get_auth_headers(url)
                            async with client.get(url, headers=headers, timeout=timeout.total) as resp:
                                if resp.status not in (200, 201, 202, 203, 204, 301, 302, 307, 308, 401, 403):
                                    return
                                text = await resp.text()
                                metadata: Dict[str, Any] = {}
                                if self.scanner._looks_like_laravel(dict(resp.headers), text, url):
                                    metadata['laravel_detected'] = True
                                app_keys = []
                                for match in re.findall(r'APP_KEY[^A-Za-z0-9+/=]*([A-Za-z0-9+/=:\-]{16,})', text, re.IGNORECASE):
                                    candidate = match.strip().strip('\"\'')
                                    if candidate.lower().startswith('base64:'):
                                        candidate = candidate.split(':', 1)[-1]
                                    if len(candidate) >= 30:
                                        app_keys.append(candidate)
                                if app_keys:
                                    metadata['laravel_app_keys'] = app_keys
                                if 'x-xsrf-token' in text.lower() or any('xsrf-token' in k.lower() for k in resp.headers.keys()):
                                    metadata['xsrf_tokens'] = True

                                try:
                                    forms_found = parse_forms(text, base_url=url)
                                except Exception:
                                    forms_found = []

                                observation_record = Observation(
                                    url=url,
                                    method='GET',
                                    status_code=resp.status,
                                    headers=dict(resp.headers),
                                    cookies={},
                                    forms=forms_found[:5],
                                    body_preview=text[:4000],
                                    metadata=metadata
                                )
                                self.observations.record(observation_record)
                        except Exception as err:
                            logger.debug(f"Laravel wordlist fetch failed for {url}: {err}")

                await asyncio.gather(*[fetch(url) for url in unique_targets])

        except Exception as outer_err:
            logger.debug(f"Laravel wordlist routine failed: {outer_err}")

    def _resolve_seclists_dir(self) -> Optional[Path]:
        if hasattr(self, '_seclists_dir_cache'):
            return self._seclists_dir_cache

        candidates = []
        for env_var in ('SECLISTS_PATH', 'SECLISTS_DIR'):
            val = os.environ.get(env_var)
            if val:
                candidates.append(Path(val).expanduser())

        candidates.extend([
            Path.home() / 'SecLists',
            Path(__file__).resolve().parents[2] / 'SecLists',
            Path('/usr/share/seclists')
        ])

        for cand in candidates:
            if cand.exists():
                self._seclists_dir_cache = cand
                return cand

        self._seclists_dir_cache = None
        logger.debug("No SecLists directory found for targeted Laravel discovery")
        return None

    def _load_laravel_paths(self, seclists_dir: Path) -> List[str]:
        cache_attr = '_laravel_wordlist_cache'
        cached = getattr(self, cache_attr, None)
        if cached is not None:
            return cached

        paths: set[str] = set()
        try:
            for txt_file in seclists_dir.rglob('*laravel*.txt'):
                try:
                    with txt_file.open('r', encoding='utf-8', errors='ignore') as handle:
                        for line in handle:
                            entry = line.strip()
                            if not entry or entry.startswith('#'):
                                continue
                            if ' ' in entry and not entry.startswith('/'):
                                continue
                            if entry.startswith('http://') or entry.startswith('https://'):
                                continue
                            if not entry.startswith('/'):
                                entry = '/' + entry
                            paths.add(entry)
                            if len(paths) >= 1000:
                                break
                except Exception:
                    continue
                if len(paths) >= 1000:
                    break
        except Exception as err:
            logger.debug(f"Could not load Laravel paths: {err}")
            paths = set()

        path_list = sorted(paths)
        setattr(self, cache_attr, path_list)
        return path_list
