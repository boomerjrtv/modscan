#!/usr/bin/env python3
"""
Universal Screenshot CLI

Capture a screenshot of any URL with optional Cookie header injection, using
the platform's ScreenshotManager. This is target-agnostic and works with any
HTTP/HTTPS application.

Usage:
  python scripts/screenshot_url.py <URL> [--cookie "k1=v1; k2=v2"] [--domain example.com]

Examples:
  python scripts/screenshot_url.py https://app.example.com/dashboard \
      --cookie "SESSION=abcd; csrftoken=xyz" --domain example.com

Outputs the saved screenshot path on success, or a non-zero exit on failure.
"""
import asyncio
import argparse
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from asset_manager import AssetManager
from modules.screenshot_manager import ScreenshotManager


async def main_async(url: str, cookie: str | None, domain: str | None, bearer: str | None, headers: list[str], proxy: str | None) -> int:
    am = AssetManager()
    config = {
        'screenshot_dir': 'screenshots',
        'auth_cookie': cookie,
        'auth_domain': domain,
        'auth_bearer': bearer,
        'proxy_server': proxy,
    }
    # Parse headers as key=value
    if headers:
        hmap = {}
        for h in headers:
            if '=' in h:
                k, v = h.split('=', 1)
                hmap[k.strip()] = v.strip()
        if hmap:
            config['auth_headers'] = hmap
    sm = ScreenshotManager(am, config)
    await sm.initialize()
    path = await sm.capture_url(url)
    if path:
        print(path)
        return 0
    else:
        print("Failed to capture screenshot", file=sys.stderr)
        return 2


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Universal screenshot for any URL with optional cookies, headers, bearer, and proxy")
    p.add_argument('url', help='Target URL to screenshot')
    p.add_argument('--cookie', help='Cookie header string, e.g., "k1=v1; k2=v2"', default=None)
    p.add_argument('--domain', help='Auth domain for cookie scoping (e.g., example.com)', default=None)
    p.add_argument('--bearer', help='Bearer token for Authorization header', default=None)
    p.add_argument('--header', action='append', default=[], help='Extra header key=value; can repeat')
    p.add_argument('--proxy', help='Proxy server, e.g., http://127.0.0.1:8080', default=None)
    return p.parse_args()


def main() -> None:
    args = parse_args()
    exit(asyncio.run(main_async(args.url, args.cookie, args.domain, args.bearer, args.header, args.proxy)))


if __name__ == '__main__':
    main()
