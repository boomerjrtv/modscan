#!/usr/bin/env python3
"""
Stateful Flow Explorer (SFE) - Universal

Purpose: Explore common authenticated flows generically using the universal
form parser. No app-specific logic; relies on token preservation and cookies.

API:
- discover_actions: returns candidate (method, action_url, form_data)
- run_sequence: executes a short sequence (e.g., login -> action -> confirm)
"""

from __future__ import annotations
import asyncio
from typing import Dict, List, Tuple
from urllib.parse import urljoin

import aiohttp

from .universal_form_parser import parse_forms, build_form_data


class StatefulFlowExplorer:
    def __init__(self, config: Dict):
        self.config = config or {}

    async def fetch_html(self, session: aiohttp.ClientSession, url: str, headers: Dict[str, str]) -> str:
        try:
            async with session.get(url, headers=headers, timeout=15) as r:
                return await r.text()
        except Exception:
            return ""

    async def discover_actions(self, session: aiohttp.ClientSession, url: str, headers: Dict[str, str]) -> List[Dict]:
        html = await self.fetch_html(session, url, headers)
        if not html:
            return []
        forms = parse_forms(html, base_url=url)
        actions: List[Dict] = []
        for f in forms:
            actions.append({
                'method': (f.get('method') or 'GET').upper(),
                'action_url': f.get('action') or url,
                'inputs': f.get('inputs') or {}
            })
        return actions

    async def run_sequence(self, session: aiohttp.ClientSession, steps: List[Dict], headers: Dict[str, str]) -> List[Tuple[int, str]]:
        results: List[Tuple[int, str]] = []
        for step in steps:
            method = (step.get('method') or 'GET').upper()
            action = step.get('action_url')
            inputs = step.get('inputs') or {}
            data = build_form_data(inputs, payload_data=step.get('payloads') or {})
            try:
                if method == 'POST':
                    async with session.post(action, data=data, headers=headers, timeout=15) as r:
                        results.append((r.status, await r.text()))
                else:
                    async with session.get(action, params=data if data else None, headers=headers, timeout=15) as r:
                        results.append((r.status, await r.text()))
            except Exception:
                results.append((-1, ""))
        return results

