#!/usr/bin/env python3
"""
Deterministic Validation Layer (DVL) - Universal

Purpose: Confirm findings without any target-specific logic by replaying
requests using multiple clients and normalizing responses.

Key ideas:
- Multiple replay backends: aiohttp (in-process) and curl snippet generation.
- Evidence invariants: status, length deltas, regex proof (when provided).
- Stable artifacts: minimal curl command for reproduction.

This module is intentionally lightweight and AI-optional.
"""

from __future__ import annotations
import asyncio
import json
import re
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import aiohttp


@dataclass
class ValidationResult:
    confirmed: bool
    reason: str
    replay_status: Optional[int] = None
    replay_length: Optional[int] = None
    curl_snippet: Optional[str] = None


class ValidationManager:
    def __init__(self, config: Dict):
        self.config = config or {}
        # Heuristic thresholds (universal)
        self.min_delta = int(self.config.get("dvl_min_len_delta", 250))

    def build_curl(self, method: str, url: str, headers: Optional[Dict[str, str]] = None, data: Optional[Dict[str, str]] = None) -> str:
        parts = ["curl", "-iLsS", "--max-time", "15", url]
        if method.upper() == "POST":
            parts += ["-X", "POST"]
        for k, v in (headers or {}).items():
            parts += ["-H", f"{k}: {v}"]
        if data:
            parts += ["--data", json.dumps(data)]
        return " ".join(parts)

    async def replay_aiohttp(self, session: aiohttp.ClientSession, method: str, url: str,
                             headers: Optional[Dict[str, str]] = None, data: Optional[Dict[str, str]] = None,
                             timeout: int = 15) -> Tuple[int, str]:
        try:
            if method.upper() == "POST":
                async with session.post(url, headers=headers, data=data, timeout=timeout) as r:
                    txt = await r.text()
                    return r.status, txt
            else:
                async with session.get(url, headers=headers, timeout=timeout) as r:
                    txt = await r.text()
                    return r.status, txt
        except Exception:
            return -1, ""

    def normalize_and_compare(self, base_status: int, base_text: str, replay_status: int, replay_text: str,
                               proof_regex: Optional[str] = None) -> Tuple[bool, str]:
        # Status agreement helps but is not mandatory for some classes.
        if replay_status < 0:
            return False, "replay_failed"

        # Regex proof (if provided) wins.
        if proof_regex:
            try:
                rgx = re.compile(proof_regex, re.I)
                if rgx.search(replay_text or ""):
                    return True, "regex_matched"
            except Exception:
                pass

        # Length delta heuristic (universal):
        delta = abs(len(replay_text or "") - len(base_text or ""))
        if delta >= self.min_delta:
            return True, f"len_delta>={self.min_delta}"

        # Fallback: status match and small delta is inconclusive
        return False, "inconclusive"

    async def validate(self, session: aiohttp.ClientSession, method: str, url: str,
                        headers: Optional[Dict[str, str]] = None, data: Optional[Dict[str, str]] = None,
                        baseline_status: int = 200, baseline_text: str = "",
                        proof_regex: Optional[str] = None) -> ValidationResult:
        replay_status, replay_text = await self.replay_aiohttp(session, method, url, headers, data)
        ok, reason = self.normalize_and_compare(baseline_status, baseline_text, replay_status, replay_text, proof_regex)
        curl_snip = self.build_curl(method, url, headers, data)
        return ValidationResult(confirmed=ok, reason=reason, replay_status=replay_status,
                                replay_length=len(replay_text or ""), curl_snippet=curl_snip)

