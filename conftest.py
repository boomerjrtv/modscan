import sys
from pathlib import Path

# Repo root (same dir as this file)
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
