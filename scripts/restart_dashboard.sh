#!/usr/bin/env bash
set -euo pipefail

# Restart the ModScan dashboard safely.
# - Kills any process bound to the configured dashboard port
# - Kills any running dashboard.py processes
# - Starts a fresh dashboard in the background and prints the PID

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

# Resolve dashboard port from config.json (fallback 8000)
PORT=$(python3 - <<'PY'
import json
try:
    with open('config.json','r') as f:
        cfg=json.load(f)
    print(cfg.get('dashboard_port', 8000))
except Exception:
    print(8000)
PY
)

echo "🔧 Restarting dashboard on port ${PORT}..."

# Kill by port (prefer fuser, fallback to lsof)
if command -v fuser >/dev/null 2>&1; then
  fuser -k "${PORT}/tcp" 2>/dev/null || true
elif command -v lsof >/dev/null 2>&1; then
  PIDS=$(lsof -ti:"${PORT}" || true)
  if [ -n "${PIDS}" ]; then
    echo "Killing PIDs on port ${PORT}: ${PIDS}"
    kill -9 ${PIDS} || true
  fi
fi

# Kill any dashboard.py processes
pkill -f "python.*dashboard.py" 2>/dev/null || true
pkill -f "dashboard.py" 2>/dev/null || true

sleep 0.5

echo "🚀 Starting dashboard..."
nohup python3 dashboard.py >/dev/null 2>&1 &
NEW_PID=$!
echo "✅ Dashboard started (pid ${NEW_PID}) on port ${PORT}"
