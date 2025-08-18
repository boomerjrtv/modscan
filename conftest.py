import os, sys, types
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("MODSCAN_DISABLE_AI", "1")

if "google.generativeai" not in sys.modules:
    sys.modules.setdefault("google", types.ModuleType("google"))
    genai_stub = types.ModuleType("google.generativeai")
    def _noop(*a, **k): pass
    genai_stub.configure = _noop
    sys.modules["google.generativeai"] = genai_stub
