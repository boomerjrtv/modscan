#!/usr/bin/env python3
"""
OOB Smoke Test: SSRF/XXE

- Reads COLLABORATOR_DOMAIN env and exercises SSRF/XXE tests against a small set of URLs.
- Targets URLs with SSRF‑like parameters first (url, redirect, src, href, next);
  if none exist, samples recent assets and uses the scanner's fallback OOB probes.
- Prints results to stdout; does not store findings in DB (smoke test only).

Usage:
  COLLABORATOR_DOMAIN=your.oast.domain \
  python3 tools/oob_smoketest.py --limit 25
"""
from __future__ import annotations
import asyncio
import os
import sqlite3
import argparse
import sys
from pathlib import Path

# Ensure project root is on sys.path for module imports
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import aiohttp

from asset_manager import AssetManager
from modules.vulnerability_scanner import VulnerabilityScanner


def pick_targets(db_path: str, limit: int) -> list[dict]:
    q_candidates = (
        "SELECT id, url FROM assets "
        "WHERE url LIKE '%url=%' OR url LIKE '%redirect=%' OR url LIKE '%src=%' OR url LIKE '%href=%' OR url LIKE '%next=%' "
        "ORDER BY id DESC LIMIT ?"
    )
    q_recent = "SELECT id, url FROM assets ORDER BY id DESC LIMIT ?"
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(q_candidates, (limit,)).fetchall()
        if not rows:
            rows = conn.execute(q_recent, (limit,)).fetchall()
        return [{"id": r[0], "url": r[1]} for r in rows]
    finally:
        conn.close()


async def run(limit: int):
    collab = os.environ.get("COLLABORATOR_DOMAIN")
    if not collab:
        print("ERROR: COLLABORATOR_DOMAIN is not set. Export it and retry.")
        return 2
    print(f"Using collaborator: {collab}")

    am = AssetManager()
    # Load config.json if present
    try:
        import json
        cfg = json.loads(open("config.json", "r").read())
    except Exception:
        cfg = {}
    scanner = VulnerabilityScanner(am, cfg)

    targets = pick_targets(am.db_path, limit)
    if not targets:
        print("No assets found in DB.")
        return 0
    print(f"Testing {len(targets)} URLs for OOB SSRF/XXE...")

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as session:
        ssrf_tasks = [scanner._test_ssrf_vulnerabilities(t["url"], session) for t in targets]
        xxe_tasks = [scanner._test_xxe_vulnerabilities(t["url"], session) for t in targets]
        ssrf_res = await asyncio.gather(*ssrf_tasks, return_exceptions=True)
        xxe_res = await asyncio.gather(*xxe_tasks, return_exceptions=True)

    def flatten(res):
        out = []
        for r in res:
            if isinstance(r, list):
                out.extend(r)
        return out

    ssrf_findings = flatten(ssrf_res)
    xxe_findings = flatten(xxe_res)

    def show(findings, label):
        if not findings:
            print(f"{label}: 0")
            return
        print(f"{label}: {len(findings)}")
        for f in findings[:10]:  # print up to 10
            print(f"- {f.vuln_type} | {f.url} | {str(f.evidence)[:120]}")

    show(ssrf_findings, "SSRF findings (incl. OOB probes)")
    show(xxe_findings, "XXE findings")
    print("Done. Check your Interactsh client for new events during this run.")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=20)
    args = ap.parse_args()
    raise SystemExit(asyncio.run(run(args.limit)))
