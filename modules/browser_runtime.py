#!/usr/bin/env python3
"""
Browser Runtime Utilities

Centralizes Playwright runtime configuration and common helpers to avoid
duplication across modules. Target-agnostic and driven by environment flags.

Env flags (all optional):
- MODSCAN_BROWSER_HEADFUL=1      -> Run headful (default: headless)
- MODSCAN_BROWSER_DEVTOOLS=1     -> Open DevTools by default
- MODSCAN_BROWSER_RDP_PORT=9222  -> Expose Chromium DevTools on this port
- MODSCAN_BROWSER_RDP_ADDR=0.0.0.0 -> Bind DevTools to this address
"""

from __future__ import annotations
import os
import socket
from typing import Dict, List, Optional, Tuple


def _env_on(name: str, default: str = '0') -> bool:
    val = str(os.environ.get(name, default)).lower()
    return val in ('1', 'true', 'yes', 'on')


def detect_lan_ip() -> str:
    """Best-effort LAN IP selection for logging purposes."""
    try:
        hostname = socket.gethostname()
        candidates = []
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM):
            ip = info[4][0]
            if ip.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.',
                              '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                              '172.30.', '172.31.')):
                candidates.append(ip)
        return candidates[0] if candidates else socket.gethostbyname(hostname)
    except Exception:
        return '127.0.0.1'


def get_launch_options(env: Optional[Dict[str, str]] = None) -> Dict[str, object]:
    """Compute Playwright Chromium launch options from environment.

    Returns dict: {
      'headless': bool,
      'devtools': bool,
      'args': List[str],
      'rdp_port': Optional[int],
      'rdp_addr': str
    }
    """
    _ = env or os.environ

    headful = _env_on('MODSCAN_BROWSER_HEADFUL')
    devtools = _env_on('MODSCAN_BROWSER_DEVTOOLS')
    try:
        rdp_port = int(_.get('MODSCAN_BROWSER_RDP_PORT', '0')) or None
    except Exception:
        rdp_port = None
    rdp_addr = _.get('MODSCAN_BROWSER_RDP_ADDR', '0.0.0.0')

    args: List[str] = []
    if rdp_port:
        args.append(f'--remote-debugging-port={rdp_port}')
        if rdp_addr:
            args.append(f'--remote-debugging-address={rdp_addr}')

    return {
        'headless': not headful,
        'devtools': devtools,
        'args': args,
        'rdp_port': rdp_port,
        'rdp_addr': rdp_addr,
    }


def extend_args(base_args: List[str], extra: List[str]) -> List[str]:
    """Merge launch args without duplicates, preserving order preference.
    Later args win when duplicates occur (simple contains check).
    """
    existing = set(base_args)
    merged = list(base_args)
    for a in extra:
        if a not in existing:
            merged.append(a)
    return merged


def setup_observers(page, console_sink, network_sink, structured: bool = False) -> None:
    """Attach console and response observers to a Playwright page.
    - If structured=False (default): console entries are strings "type: text".
    - If structured=True: console entries are dicts {'type': str, 'text': str}.
    Network entries are dicts in both modes.
    """
    try:
        if structured:
            page.on("console", lambda msg: console_sink.append({
                'type': getattr(msg, 'type', 'log'),
                'text': getattr(msg, 'text', '')
            }))
        else:
            page.on("console", lambda msg: console_sink.append(
                f"{getattr(msg, 'type', 'log')}: {getattr(msg, 'text', '')}"
            ))

        page.on("response", lambda res: network_sink.append({
            'url': getattr(res, 'url', '')[:256],
            'status': getattr(res, 'status', None),
            'type': getattr(getattr(res, 'request', None), 'resource_type', 'unknown')
        }))
    except Exception:
        # Observers are optional; failure should not break runs
        pass

