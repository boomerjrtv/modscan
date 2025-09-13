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
        # Fallback to known PayloadsAllTheThings location
        fallback = Path("/home/michael/payloads/PayloadsAllTheThings")
        if fallback.exists():
            return fallback
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

    def _extract_ssti_from_markdown(self, files: Iterable[Path]) -> List[str]:
        """Extract SSTI payloads from markdown files by finding code blocks and template expressions"""
        import re
        payloads: List[str] = []
        
        template_patterns = [
            r'\{\{[^}]+\}\}',  # {{ ... }}
            r'\$\{[^}]+\}',    # ${ ... }
            r'<%[^>]+%>',      # <% ... %>
            r'#\{[^}]+\}',     # #{ ... }
            r'@\([^)]+\)',     # @( ... )
            r'\[\[[^\]]+\]\]', # [[ ... ]]
        ]
        
        for f in files:
            try:
                with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
                    
                    # Extract code blocks and inline code
                    code_blocks = re.findall(r'```[^`]*```|`[^`]+`', content, re.DOTALL)
                    for block in code_blocks:
                        # Clean up markdown formatting
                        clean = block.replace('```', '').replace('`', '').strip()
                        if clean and any(re.search(pattern, clean) for pattern in template_patterns):
                            payloads.append(clean)
                    
                    # Direct pattern matching in content
                    for pattern in template_patterns:
                        matches = re.findall(pattern, content)
                        payloads.extend(matches)
                        
            except Exception:
                continue
                
        # Deduplicate and filter
        seen: Set[str] = set()
        unique_payloads: List[str] = []
        for payload in payloads:
            clean_payload = payload.strip()
            if (clean_payload and len(clean_payload) < 500 and 
                clean_payload not in seen and
                not clean_payload.startswith('#')):
                seen.add(clean_payload)
                unique_payloads.append(clean_payload)
                
        return unique_payloads

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
                for sub in ("Server Side Request Forgery", "SSRF"):
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
            elif cat in ("ssti", "template", "template-injection"):
                # Enhanced SSTI payload extraction
                for sub in ("Server Side Template Injection", "SSTI", "Template Injection"):
                    d = base / sub
                    if d.exists():
                        # Get .fuzz files first (pre-built payloads)
                        candidates.extend(sorted(d.rglob("*.fuzz")))
                        candidates.extend(sorted(d.rglob("*.txt")))
                        # Process markdown files specially for SSTI
                        md_files = list(d.rglob("*.md"))
                        if md_files:
                            ssti_payloads = self._extract_ssti_from_markdown(md_files)
                            return ssti_payloads[:1000]  # Return extracted payloads directly
        except Exception:
            candidates = []

        if not candidates:
            return []
        # Cap to a reasonable number per category to avoid bloat
        lines = self._load_lines(candidates[:200])
        return lines[:5000]

