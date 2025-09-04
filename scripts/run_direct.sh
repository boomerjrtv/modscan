#!/usr/bin/env bash
set -euo pipefail

# Usage: scripts/run_direct.sh URL [URL2 ...]
# Example: scripts/run_direct.sh http://192.168.1.42/dvwa/vulnerabilities/xss_r/

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 URL [URL2 ...]" >&2
  exit 1
fi

# Build JSON array without external deps if jq not present
if command -v jq >/dev/null 2>&1; then
  URLS_JSON=$(printf '%s\n' "$@" | jq -R . | jq -s .)
else
  URLS_JSON="[\"$1\"]"
  if [ "$#" -gt 1 ]; then
    shift
    for u in "$@"; do
      URLS_JSON=${URLS_JSON%]}
      URLS_JSON+=" , \"$u\"]"
    done
  fi
fi

MODSCAN_DIRECT_URL_TESTING=1 \
MODSCAN_ONLY_DIRECT_URLS=1 \
MODSCAN_DIRECT_URLS="$URLS_JSON" \
python3 engine.py --direct --only-direct --urls "$URLS_JSON"

