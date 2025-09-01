#!/usr/bin/env python3
"""
Universal Payloads Manager

Purpose:
- Optionally load additional payloads from a local copy of PayloadsAllTheThings (or any
  directory structure the user provides), without hardcoding target-specific logic.
- Keeps the core scanner universal: if no external payloads are present, defaults still work.

Usage:
- Set env PAYLOADS_DIR or provide config['payloads_dir'] pointing to a local clone.
- This module only reads files; it never assumes a particular application.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, List, Set
import logging

logger = logging.getLogger("PayloadsManager")


class PayloadsManager:
    def __init__(self, base_dir: str | Path | None = None):
        # Resolve base directory from arg, env, or config later if passed
        self.base_dir = Path(base_dir) if base_dir else self._resolve_from_env()
        self.available = self.base_dir.exists() if self.base_dir else False
        if self.available:
            logger.info(f"✅ PayloadsManager using base: {self.base_dir}")
        else:
            logger.info("PayloadsManager: no external payloads directory configured")

    def _resolve_from_env(self) -> Path:
        for k in ("PAYLOADS_DIR", "PAYLOADS_PATH", "MODSCAN_PAYLOADS"):
            p = os.getenv(k)
            if p and Path(p).exists():
                return Path(p)
        return Path("")

    def _load_lines(self, files: Iterable[Path]) -> List[str]:
        out: List[str] = []
        for f in files:
            try:
                with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        s = line.strip()
                        if not s or s.startswith("#"):
                            continue
                        out.append(s)
            except Exception:
                continue
        # Deduplicate while preserving order
        seen: Set[str] = set()
        dedup: List[str] = []
        for s in out:
            if s not in seen:
                seen.add(s)
                dedup.append(s)
        return dedup

    def get(self, category: str) -> List[str]:
        """Return additional payloads for a category (e.g., 'xss','sqli','lfi','ssrf','redirect','cmdi').

        Attempts to map to common PayloadsAllTheThings paths, but works with any directory
        as long as paths exist. Silent if unavailable.
        """
        if not self.available:
            return []

        base = self.base_dir
        candidates: List[Path] = []

        # Heuristic mapping for PayloadsAllTheThings
        try:
            cat = category.lower()
            if cat in ("xss", "domxss"):
                # e.g. PayloadsAllTheThings/XSS Injection/
                for sub in ("XSS Injection", "XSS", "xss"):
                    d = base / sub
                    if d.exists():
                        candidates.extend(sorted(d.rglob("*.txt")))
            elif cat in ("sqli", "sql"):
                for sub in ("SQL Injection", "SQLi", "sqli"):
                    d = base / sub
                    if d.exists():
                        candidates.extend(sorted(d.rglob("*.txt")))
            elif cat in ("lfi", "rfi", "path-traversal"):
                for sub in ("LFI", "File Inclusion", "Path Traversal"):
                    d = base / sub
                    if d.exists():
                        candidates.extend(sorted(d.rglob("*.txt")))
            elif cat in ("ssrf",):
                for sub in ("SSRF",):
                    d = base / sub
                    if d.exists():
                        candidates.extend(sorted(d.rglob("*.txt")))
            elif cat in ("redirect", "open-redirect"):
                for sub in ("Open Redirect", "Open-Redirect"):
                    d = base / sub
                    if d.exists():
                        candidates.extend(sorted(d.rglob("*.txt")))
            elif cat in ("cmdi", "rce", "command", "os-command"):
                for sub in ("Command Injection", "RCE"):
                    d = base / sub
                    if d.exists():
                        candidates.extend(sorted(d.rglob("*.txt")))
        except Exception:
            candidates = []

        if not candidates:
            return []
        # Cap to a reasonable number per category to avoid bloat
        lines = self._load_lines(candidates[:200])
        return lines[:5000]

