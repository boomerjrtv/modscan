#!/usr/bin/env python3
"""
ML Prioritizer (Multi‑Armed Bandit)

Learns which method families (per vulnerability class) work best in this
environment and orders future tests accordingly. Keeps the platform universal:
- No app-specific hardcoding
- Simple UCB1 bandit with persistence to ml_stats.json

Usage:
    p = MLPrioritizer()
    methods = p.order('xss', ['html','attr','script'])
    ... run methods[0] ...
    p.record('xss','html', success=True)
"""
from __future__ import annotations

import json
from pathlib import Path
from math import log, sqrt
from typing import Dict, List
import threading


class MLPrioritizer:
    def __init__(self, stats_path: Path | None = None):
        base = Path(__file__).resolve().parents[1]
        self.stats_path = stats_path or (base / 'ml_stats.json')
        self._lock = threading.Lock()
        self._stats: Dict[str, Dict[str, Dict[str, float]]] = self._load()

    def _load(self) -> Dict[str, Dict[str, Dict[str, float]]]:
        try:
            if self.stats_path.exists():
                with open(self.stats_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return data if isinstance(data, dict) else {}
        except Exception:
            pass
        return {}

    def _save(self) -> None:
        try:
            with self._lock:
                with open(self.stats_path, 'w', encoding='utf-8') as f:
                    json.dump(self._stats, f)
        except Exception:
            pass

    def record(self, category: str, method: str, success: bool) -> None:
        cat = self._stats.setdefault(category, {})
        arm = cat.setdefault(method, {"trials": 0.0, "success": 0.0})
        arm["trials"] = float(arm.get("trials", 0.0)) + 1.0
        if success:
            arm["success"] = float(arm.get("success", 0.0)) + 1.0
        self._save()

    def order(self, category: str, methods: List[str]) -> List[str]:
        """Return methods ordered best‑first via UCB1 (optimistic initialization)."""
        if not methods:
            return []
        cat = self._stats.setdefault(category, {})
        # Ensure arms exist
        for m in methods:
            cat.setdefault(m, {"trials": 0.0, "success": 0.0})
        # Total plays
        n = sum(arm.get("trials", 0.0) for arm in cat.values())
        # Score each method
        scores = {}
        for m in methods:
            arm = cat[m]
            t = float(arm.get("trials", 0.0))
            s = float(arm.get("success", 0.0))
            # Optimistic prior: 1 virtual success, 1 virtual trial (prevents zero division)
            mean = (s + 1.0) / (t + 1.0)
            bonus = sqrt(2.0 * log((n + 1.0)) / (t + 1.0)) if t > 0 else 1.0
            scores[m] = mean + bonus
        # Return sorted best‑first
        return sorted(methods, key=lambda m: scores.get(m, 0.0), reverse=True)

