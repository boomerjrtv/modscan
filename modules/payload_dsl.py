#!/usr/bin/env python3
"""
Universal Payload DSL

Lightweight template system to generate portable payload variants without
target-specific logic. Tokens:

- {SEP}: command separators [';', '&&', '|', '||']
- {QUOTE}: quote styles ['', "'", '"']
- {COMMENT}: SQL comment styles ['-- ', '#', '/*'] (database-agnostic)
- {ENC:URL}: URL-encode the entire expanded payload
- {ENC:HEX}: hex-encode characters (safe subset)
- {WRAP:JSON}: wrap as JSON string
- {WRAP:ATTR}: wrap for HTML attribute context (surrounded by ")

Usage:
  expand("1{QUOTE} OR {QUOTE}1{QUOTE}={QUOTE}1{COMMENT}", ctx)
  expand_many(["{SEP} id", "$(id)"], ctx)

Context (optional hints):
- ctx.get('prefer_windows'): bool
- ctx.get('encodings'): list e.g. ['URL','HEX'] to include encoded variants

This module avoids network and target-specific rules by design.
"""
from __future__ import annotations

import itertools
import urllib.parse
from typing import Dict, Iterable, List


DEFAULT_SEPARATORS = [';', '&&', '|', '||']
DEFAULT_QUOTES = ['', "'", '"']
DEFAULT_COMMENTS = ['-- ', '#', '/*']


def _cartesian_replace(template: str, choices: Dict[str, List[str]]) -> List[str]:
    tokens = []
    parts: List[str] = []
    i = 0
    while i < len(template):
        if template[i] == '{':
            j = template.find('}', i)
            if j == -1:
                parts.append(template[i:])
                break
            token = template[i + 1:j]
            tokens.append(token)
            parts.append(None)  # placeholder
            i = j + 1
        else:
            # accumulate literal until next '{'
            j = template.find('{', i)
            if j == -1:
                parts.append(template[i:])
                break
            parts.append(template[i:j])
            i = j

    # Build products
    pools = []
    for t in tokens:
        pools.append(choices.get(t.upper(), [f'{{{t}}}']))

    out: List[str] = []
    for prod in itertools.product(*pools or [[]]):
        segs: List[str] = []
        pidx = 0
        for seg in parts:
            if seg is None:
                segs.append(prod[pidx])
                pidx += 1
            else:
                segs.append(seg)
        out.append(''.join(segs))
    return out or [template]


def _encode_variants(payload: str, encs: Iterable[str]) -> List[str]:
    variants = [payload]
    for e in encs:
        u = e.upper()
        if u == 'URL':
            variants.append(urllib.parse.quote(payload, safe=''))
        elif u == 'HEX':
            variants.append(''.join(f"%{ord(c):02x}" for c in payload))
    return list(dict.fromkeys(variants))


def expand(template: str, ctx: Dict) -> List[str]:
    choices = {
        'SEP': DEFAULT_SEPARATORS,
        'QUOTE': DEFAULT_QUOTES,
        'COMMENT': DEFAULT_COMMENTS,
    }
    base = _cartesian_replace(template, choices)
    encs = ctx.get('encodings') or []
    out: List[str] = []
    for b in base:
        out.extend(_encode_variants(b, encs))
    # Wrappers are applied as final post-process
    wrap = (ctx.get('wrap') or '').upper()
    if wrap == 'JSON':
        out = [f'"{p}"' for p in out]
    elif wrap == 'ATTR':
        out = [f'"{p}"' for p in out]
    return out[:50]


def expand_many(templates: Iterable[str], ctx: Dict) -> List[str]:
    seen = set()
    out: List[str] = []
    for t in templates:
        for p in expand(str(t), ctx):
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out[:200]

