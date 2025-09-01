#!/usr/bin/env bash
set -euo pipefail

echo "This will remove transient artifacts (logs, caches, screenshots, evidence)."
read -p "Proceed? [y/N] " ans
case "${ans:-N}" in
  y|Y|yes|YES) ;;
  *) echo "Aborted"; exit 1;;
esac

rm -rf \
  logs \
  screenshots \
  evidence \
  .pytest_cache \
  **/__pycache__

echo "Done."

