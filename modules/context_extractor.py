#!/usr/bin/env python3
"""
Universal Context Extractor

Derives target-agnostic context features from responses to guide adaptive testing:
- response_type: html/json/xml/other
- protections: CSP present, nosniff
- forms summary: count, has_file_upload
- dom hints: presence of inline scripts/events

No target-specific logic; purely heuristic and safe.
"""
from __future__ import annotations

import re
from typing import Dict, Tuple

try:
    from bs4 import BeautifulSoup  # type: ignore
except Exception:
    BeautifulSoup = None  # type: ignore


def classify_content_type(ct: str) -> str:
    ct = (ct or '').lower()
    if 'json' in ct:
        return 'json'
    if 'html' in ct:
        return 'html'
    if 'xml' in ct:
        return 'xml'
    return 'other'


def extract(url: str, html_text: str, headers: Dict[str, str]) -> Dict:
    out: Dict = {
        'url': url,
        'response_type': classify_content_type(headers.get('content-type', '')),
        'has_csp': bool(headers.get('content-security-policy')),
        'has_nosniff': headers.get('x-content-type-options', '').lower() == 'nosniff',
        'forms': {'count': 0, 'has_file_upload': False},
        'dom': {'inline_script': False, 'event_handlers': False},
    }

    text = html_text or ''
    if BeautifulSoup and '<html' in text.lower():
        try:
            soup = BeautifulSoup(text, 'html.parser')
            forms = soup.find_all('form')
            out['forms']['count'] = len(forms)
            for f in forms:
                if f.find('input', {'type': 'file'}):
                    out['forms']['has_file_upload'] = True
                    break
            # Inline script hints
            out['dom']['inline_script'] = bool(soup.find('script', text=True))
            # Event handler heuristics
            out['dom']['event_handlers'] = bool(re.search(r'on\w+\s*=\s*', text, re.I))
        except Exception:
            pass
    else:
        # Regex fallbacks
        out['forms']['count'] = len(re.findall(r'<form\b', text, re.I))
        out['forms']['has_file_upload'] = bool(re.search(r'<input[^>]+type=["\']file["\']', text, re.I))
        out['dom']['inline_script'] = bool(re.search(r'<script[^>]*>[^<]', text, re.I))
        out['dom']['event_handlers'] = bool(re.search(r'on\w+\s*=\s*', text, re.I))

    return out

