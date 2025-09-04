#!/usr/bin/env python3
"""
HackerOne Hacktivity Scraper (incremental)

Purpose
- Scroll Hacktivity and collect newly disclosed report URLs incrementally, using
  the first entry in an existing CSV as the stop marker. Appends new rows to CSV.

Why this approach
- Hacktivity is infinite-scroll + dynamic; scraping is brittle. This tool uses
  robust selectors and optional headless mode, but a local mirror (e.g., the
  reddelexc/hackerone-reports GitHub repo) remains preferred for stability.

Usage
  python tools/h1_hacktivity_scrape.py \
    --input data.csv --output data.csv [--headless] [--max-pages 50]

Notes
- Requires Selenium + Chrome/Chromium + matching driver in PATH.
- Does not depend on any target-specific logic; it only collects public links.
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

from selenium.webdriver import Chrome, ChromeOptions  # type: ignore
from selenium.webdriver.common.by import By  # type: ignore
from selenium.webdriver.support.ui import WebDriverWait  # type: ignore
from selenium.webdriver.support import expected_conditions as EC  # type: ignore


HACKTIVITY_URL = (
    'https://hackerone.com/hacktivity/overview'
    '?queryString=disclosed%3Atrue&sortField=disclosed_at&sortDirection=DESC&pageIndex=0'
)


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser()
    ap.add_argument('--browser-binary', type=str, default=os.getenv('CHROME_BIN') or '',
                    help='Path to Chrome/Chromium binary (auto-detect if empty)')
    ap.add_argument('--input', '--input-data-file', dest='input_file', type=str, default='data.csv',
                    help='Path to existing CSV with at least one row (for stop marker).')
    ap.add_argument('--output', '--output-data-file', dest='output_file', type=str, default='data.csv',
                    help='Where to write updated CSV.')
    ap.add_argument('--headless', action='store_true', help='Run headless (default).')
    ap.add_argument('--max-pages', type=int, default=100, help='Safety cap on pagination.')
    ap.add_argument('--timeout', type=int, default=15, help='Per-page wait timeout (seconds).')
    return ap.parse_args()


def _auto_chrome_binary() -> Optional[str]:
    candidates = [
        '/usr/bin/google-chrome',
        '/usr/bin/chromium',
        '/usr/bin/chromium-browser',
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        'C:/Program Files/Google/Chrome/Application/chrome.exe',
        'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
    ]
    for p in candidates:
        if Path(p).exists():
            return p
    return None


def _read_csv(path: Path) -> List[Dict]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open('r', newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))


def _write_csv(path: Path, rows: List[Dict]):
    if not rows:
        return
    keys = list(rows[0].keys())
    with path.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)


def _extract_reports(anchors) -> List[Dict]:
    out: List[Dict] = []
    for a in anchors:
        href = a.get_attribute('href') or ''
        if '/reports/' not in href:
            continue
        # Normalize URL (ensure https scheme)
        if href.startswith('http'):
            link = href
        else:
            link = f"https://hackerone.com{href}"
        out.append({
            'program': '',
            'title': '',
            'link': link,
            'upvotes': 0,
            'bounty': 0.0,
            'vuln_type': ''
        })
    return out


def main():
    args = parse_args()
    input_path = Path(args.input_file)
    output_path = Path(args.output_file)

    existing = _read_csv(input_path)
    stop_link = existing[0]['link'] if existing else None

    opts = ChromeOptions()
    if args.browser_binary:
        opts.binary_location = args.browser_binary
    else:
        auto = _auto_chrome_binary()
        if auto:
            opts.binary_location = auto
    opts.add_argument('--no-sandbox')
    opts.add_argument('--disable-dev-shm-usage')
    opts.add_argument('--disable-gpu')
    opts.add_argument('--headless=new')

    driver = Chrome(options=opts)
    driver.set_page_load_timeout(args.timeout)

    new_reports: List[Dict] = []
    try:
        driver.get(HACKTIVITY_URL)
        WebDriverWait(driver, args.timeout).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, 'a[href*="/reports/"]'))
        )

        page = 0
        while page < args.max_pages:
            # Collect current page anchors
            anchors = driver.find_elements(By.CSS_SELECTOR, 'a[href*="/reports/"]')
            batch = _extract_reports(anchors)
            # Dedup while preserving order
            seen = {r['link'] for r in new_reports}
            for r in batch:
                if r['link'] not in seen:
                    new_reports.append(r)
                    seen.add(r['link'])

            # Check for stop condition
            if stop_link:
                for i, r in enumerate(new_reports):
                    if r['link'] == stop_link:
                        # splice: new before stop, then existing
                        combined = new_reports[:i] + existing
                        _write_csv(output_path, combined)
                        print(f"Found stop link on page {page}; added {i} new reports")
                        return

            # Try to paginate
            try:
                next_btn = WebDriverWait(driver, args.timeout).until(
                    EC.element_to_be_clickable((By.CSS_SELECTOR, "button[data-testid='hacktivity-pagination--pagination-next-page']"))
                )
            except Exception:
                break

            driver.execute_script("arguments[0].click();", next_btn)
            time.sleep(1.0)
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            page += 1
            print(f"Page: {page}")

        # If we never hit stop_link, prepend entire new list
        combined = new_reports + existing
        if combined:
            _write_csv(output_path, combined)
            print(f"Completed {page} pages; wrote {len(new_reports)} new + {len(existing)} existing")

    except Exception as e:
        print(f"Error: {e}")
        now = datetime.now().strftime('%Y-%m-%d_%H%M%S')
        try:
            driver.get_screenshot_as_file(f'error-{now}.png')
        except Exception:
            pass
        sys.exit(2)
    finally:
        try:
            driver.quit()
        except Exception:
            pass


if __name__ == '__main__':
    main()

