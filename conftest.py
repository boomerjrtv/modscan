import os, sys, types
from pathlib import Path

# Make repo root importable
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Disable AI paths in tests and stub the heaviest module so imports don't cascade
os.environ.setdefault("MODSCAN_DISABLE_AI", "1")

if "google.generativeai" not in sys.modules:
    # Ensure top-level google pkg exists
    sys.modules.setdefault("google", types.ModuleType("google"))
    # Minimal stub so "import google.generativeai as genai" succeeds
    genai_stub = types.ModuleType("google.generativeai")
    # Optional: provide no-op configure() so accidental calls don't crash
    def _noop(*a, **k): pass
    genai_stub.configure = _noop
    sys.modules["google.generativeai"] = genai_stub
