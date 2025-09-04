#!/usr/bin/env python3
import asyncio
import json
import logging
import os
from pathlib import Path

import aiohttp

import sys
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from modules.intelligent_xss_detector import IntelligentXSSDetector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("dom-local-test")

HTML = HERE.parent / "tests" / "dom_generic_form.html"
URL = f"file://{HTML}"


async def main():
    try:
        with open(HERE.parent / "config.json") as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}

    det = IntelligentXSSDetector(asset_manager=None, config=cfg)

    # Load HTML locally (no network)
    html_content = HTML.read_text(encoding="utf-8")

    async with aiohttp.ClientSession() as session:
        forms = await det._discover_forms(URL, html_content, session)
        print(f"Forms found: {len(forms)}")
        for i, fm in enumerate(forms):
            print(f"Form[{i}]: action={fm['action']} method={fm['method']} fields={list(fm['fields'].keys())}")

        findings = await det._test_dom_xss_with_browser(URL, forms)
        print(f"DOM findings: {len(findings)}")
        for f in findings:
            print(json.dumps(f, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
