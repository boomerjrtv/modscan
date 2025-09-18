#!/usr/bin/env python3
"""
Lightweight Collaborator HTTP Receiver

- Logs every inbound HTTP request as JSON to stdout (and optional file)
- Use behind your own subdomain (e.g., collab.yourdomain.com) for SSRF/XXE/Blind XSS OOB beacons
- No target-specific logic; purely a universal sink for callbacks

Usage:
  python3 tools/collaborator_receiver.py --host 0.0.0.0 --port 80

Options:
  --host 0.0.0.0       Bind address (default 0.0.0.0)
  --port 80            Port (default 80)
  --log-file path      Optional log file to append JSON lines

Verify:
  curl http://<your-subdomain>/health
  curl http://<your-subdomain>/test123
"""

import argparse
import asyncio
import json
import os
from datetime import datetime
from aiohttp import web


def make_app(log_file: str | None = None) -> web.Application:
    async def handle(request: web.Request) -> web.StreamResponse:
        payload = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "remote": request.remote,
            "host": request.host,
            "path": str(request.rel_url),
            "method": request.method,
            "headers": dict(request.headers),
            "query": dict(request.query),
        }
        line = json.dumps(payload)
        print(line, flush=True)
        if log_file:
            try:
                with open(log_file, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception:
                pass
        return web.Response(text="ok\n")

    async def health(request: web.Request) -> web.StreamResponse:
        return web.Response(text="ok\n")

    app = web.Application()
    app.router.add_get("/health", health)
    app.router.add_route("*", "/{tail:.*}", handle)
    return app


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=os.environ.get("COLLAB_BIND_HOST", "0.0.0.0"))
    p.add_argument("--port", type=int, default=int(os.environ.get("COLLAB_BIND_PORT", "80")))
    p.add_argument("--log-file", default=os.environ.get("COLLAB_LOG_FILE"))
    args = p.parse_args()

    app = make_app(args.log_file)
    web.run_app(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()

