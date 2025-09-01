#!/usr/bin/env bash
set -euo pipefail

# Print a clean repo tree, excluding noisy runtime folders/files.

EXCLUDES=(
  ".git" ".venv" "__pycache__" ".pytest_cache"
  "logs" "screenshots" "evidence" "storage_states"
  "node_modules" "SecLists" "models"
  "*.db" "*.sqlite" "*.log" "*.bak" "*.tmp"
)

EXCLUDE_ARGS=()
for e in "${EXCLUDES[@]}"; do
  EXCLUDE_ARGS+=( -I "$e" )
done

if command -v tree >/dev/null 2>&1; then
  tree -a -I ".git|.venv|__pycache__|.pytest_cache|logs|screenshots|evidence|storage_states|node_modules|SecLists|models|*.db|*.sqlite|*.log|*.bak|*.tmp"
else
  echo "Install 'tree' for a nice view (e.g., apt-get install tree). Falling back to find."
  find . \( \
    -path './.git' -o -path './.venv' -o -path './__pycache__' -o -path './.pytest_cache' -o \
    -path './logs' -o -path './screenshots' -o -path './evidence' -o -path './storage_states' -o \
    -path './node_modules' -o -path './SecLists' -o -path './models' \) -prune -o \
    -name '*.db' -prune -o -name '*.sqlite' -prune -o -name '*.log' -prune -o -name '*.bak' -prune -o -name '*.tmp' -prune -o \
    -print | sed 's#^\./##'
fi

