#!/usr/bin/env python3
"""
HackerOne Reports Ingestor (offline)

Goal:
- Parse a local clone of https://github.com/reddelexc/hackerone-reports for PoC payloads
  in a universal, target-agnostic way.
- Extract commonly useful payload lines and code blocks across categories (xss, sqli, cmdi, ssrf, lfi, ssti, xxe, redirect).
- Write results to JSONL at ultimate_payloads/hackerone_pocs.jsonl and an index by category.

Usage:
  python tools/hackerone_ingest.py --repo /path/to/hackerone-reports [--out ultimate_payloads]

Notes:
- No network access required. Works with any directory containing Markdown/text reports.
- Heuristics favor precision to reduce noise; adjust patterns if needed.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, Iterable, List, Tuple
try:
    from bs4 import BeautifulSoup  # type: ignore
except Exception:
    BeautifulSoup = None  # type: ignore


PAYLOAD_HINTS = {
    'xss': [r'<script', r'onerror\s*=', r'onload\s*=', r'<svg', r'<iframe', r'javascript:\w', r'alert\s*\('],
    'sqli': [r'union\s+select', r"\bor\b\s+1=1", r'sleep\s*\(', r"--\s*$", r"/\*", r"'\s*\bor\b\s*'1'='1"],
    'cmdi': [r';\s*id', r'&&\s*id', r'\|\s*whoami', r'`\w+`', r'\$\(\w+\)', r';\s*sleep\s+\d+'],
    'ssrf': [r'169\.254\.169\.254', r'127\.0\.0\.1', r'localhost', r'file://', r'gopher://', r'ftp://', r'http://.*?/latest/meta-data'],
    'lfi': [r'\.\./\.\./etc/passwd', r'/proc/self/environ', r'php://filter', r'zip://', r'phar://', r'expect://'],
    'ssti': [r'\{\{\s*7\s*\*\s*7\s*\}\}', r'\$\{\s*7\s*\*\s*7\s*\}', r'\{\{.*\}\}', r'<%=?\s*7\*7\s*%>'],
    'xxe': [r'<!DOCTYPE', r'<!ENTITY', r'SYSTEM\s+"?file://'],
    'redirect': [r'\b(?:https?:)?//\w', r'\bredir', r'\bnext='],
}


CODE_FENCE_RE = re.compile(r"^```(\w+)?\s*$")


def _categorize(line: str) -> List[str]:
    cats: List[str] = []
    l = line.lower()
    for cat, pats in PAYLOAD_HINTS.items():
        for pat in pats:
            if re.search(pat, l, re.I):
                cats.append(cat)
                break
    return cats or ['misc']


def _iter_text_files(root: Path) -> Iterable[Path]:
    for ext in ("*.md", "*.markdown", "*.txt", "*.rst", "*.adoc", "*.html", "*.htm"):
        yield from root.rglob(ext)


def _extract_from_html(fp: Path) -> List[Dict]:
    out: List[Dict] = []
    try:
        html = fp.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return out
    if not html:
        return out
    if BeautifulSoup:
        try:
            soup = BeautifulSoup(html, 'html.parser')
            # Extract from pre/code blocks
            blocks = []
            blocks.extend([t.get_text('\n', strip=False) for t in soup.find_all('pre')])
            blocks.extend([t.get_text('\n', strip=False) for t in soup.find_all('code')])
            for text in blocks:
                for raw in (text or '').splitlines():
                    s = (raw or '').strip()
                    if not s or len(s) > 500:
                        continue
                    if any(sym in s for sym in ("<", ">", "'", '"', ";", "|", "`", "$((", "http://", "https://", "file://")):
                        for cat in _categorize(s):
                            out.append({'category': cat, 'payload': s, 'source_file': str(fp), 'language': 'code'})
        except Exception:
            pass
    # Regex fallback: find <pre>...</pre> contents
    if not out:
        import re as _re
        for m in _re.findall(r'<pre[^>]*>(.*?)</pre>', html, _re.I | _re.S):
            for raw in (m or '').splitlines():
                s = (raw or '').strip()
                if not s or len(s) > 500:
                    continue
                if any(sym in s for sym in ("<", ">", "'", '"', ";", "|", "`", "$((", "http://", "https://", "file://")):
                    for cat in _categorize(s):
                        out.append({'category': cat, 'payload': s, 'source_file': str(fp), 'language': 'pre'})
    return out


def _extract_payloads_from_file(fp: Path) -> List[Dict]:
    results: List[Dict] = []
    try:
        text = fp.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return results
    # If HTML, use specialized extractor
    if fp.suffix.lower() in ('.html', '.htm'):
        return _extract_from_html(fp)

    lines = text.splitlines()
    in_fence = False
    fence_lang = ''
    block: List[str] = []

    def flush_block():
        nonlocal block, fence_lang
        if not block:
            return
        snippet = "\n".join(block)
        # Split into candidate payload lines with lightweight filters
        for raw in block:
            s = raw.strip()
            if not s:
                continue
            if len(s) > 500:
                continue
            # Signs of payload-ness: specials, angle brackets, quotes, separators, proto schemes
            if any(sym in s for sym in ("<", ">", "'", '"', ";", "|", "`", "$((", "http://", "https://", "file://")):
                cats = _categorize(s)
                for cat in cats:
                    results.append({
                        'category': cat,
                        'payload': s,
                        'source_file': str(fp),
                        'language': fence_lang or 'text'
                    })
        block = []
        fence_lang = ''

    for line in lines:
        m = CODE_FENCE_RE.match(line)
        if m:
            if not in_fence:
                in_fence = True
                fence_lang = (m.group(1) or '').lower()
                block = []
                continue
            else:
                in_fence = False
                flush_block()
                continue
        if in_fence:
            block.append(line)
        else:
            # Non-fenced single-line candidates
            s = line.strip()
            if not s or len(s) > 300:
                continue
            if any(sym in s for sym in ("<", ">", "'", '"', ";", "|", "`", "$((", "http://", "https://", "file://")):
                cats = _categorize(s)
                for cat in cats:
                    results.append({
                        'category': cat,
                        'payload': s,
                        'source_file': str(fp),
                        'language': 'text'
                    })

    # Flush dangling block if file ends mid-fence
    if in_fence:
        flush_block()

    return results


def _dedup_payloads(items: List[Dict]) -> List[Dict]:
    seen: set[Tuple[str, str]] = set()
    out: List[Dict] = []
    for it in items:
        key = (it.get('category','misc'), it.get('payload',''))
        if not key[1]:
            continue
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo', required=True, help='Path to local hackerone-reports clone')
    ap.add_argument('--out', default='ultimate_payloads', help='Output directory (default: ultimate_payloads)')
    args = ap.parse_args()

    root = Path(args.repo)
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    all_items: List[Dict] = []
    for fp in _iter_text_files(root):
        all_items.extend(_extract_payloads_from_file(fp))

    dedup = _dedup_payloads(all_items)

    # Write JSONL
    jsonl_path = outdir / 'hackerone_pocs.jsonl'
    with jsonl_path.open('w', encoding='utf-8') as f:
        for it in dedup:
            f.write(json.dumps(it, ensure_ascii=False) + "\n")

    # Index by category for easy loading
    by_cat: Dict[str, List[str]] = {}
    for it in dedup:
        cat = it['category']
        by_cat.setdefault(cat, []).append(it['payload'])
    # Cap each category to reasonable size to avoid bloat on load
    by_cat = {k: v[:5000] for k, v in by_cat.items()}
    with (outdir / 'hackerone_payloads_by_category.json').open('w', encoding='utf-8') as f:
        json.dump(by_cat, f, ensure_ascii=False, indent=2)

    print(f"Extracted {len(dedup)} payload lines from HackerOne repo")
    print(f"Wrote: {jsonl_path} and {outdir / 'hackerone_payloads_by_category.json'}")


if __name__ == '__main__':
    main()
