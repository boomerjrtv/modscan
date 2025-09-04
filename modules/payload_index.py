#!/usr/bin/env python3
"""
Payload Retrieval Index (offline)

Aggregates payload strings from local sources (e.g., HackerOne JSON) and
provides simple retrieval by category and optional keyword filters.

Sources used (when available):
- ultimate_payloads/hackerone_payloads_by_category.json

Design constraints:
- Universal, no network, no target-specific logic.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, Iterable, List


class PayloadIndex:
    def __init__(self, base_dir: str | None = None):
        self.base = Path(base_dir) if base_dir else Path('ultimate_payloads')
        self._by_cat: Dict[str, List[str]] = {}
        self._loaded = False

    def _load(self):
        if self._loaded:
            return
        try:
            p = self.base / 'hackerone_payloads_by_category.json'
            if p.exists():
                data = json.loads(p.read_text(encoding='utf-8'))
                self._by_cat = {str(k).lower(): [str(x) for x in (v or [])] for k, v in (data or {}).items()}
        except Exception:
            self._by_cat = {}
        self._loaded = True

    def get(self, category: str, keywords: Iterable[str] | None = None, limit: int = 50) -> List[str]:
        self._load()
        cat = (category or '').lower()
        items = list(self._by_cat.get(cat, []))
        if keywords:
            pats = [re.compile(re.escape(k), re.I) for k in keywords if k]
            if pats:
                items = [s for s in items if any(p.search(s) for p in pats)]
        # Dedup and cap
        out = list(dict.fromkeys(items))
        return out[:max(0, limit)]

