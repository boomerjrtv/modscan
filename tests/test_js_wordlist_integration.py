import asyncio
import importlib.util
import sys
import types
from pathlib import Path

MODULE_DIR = Path(__file__).resolve().parent.parent / "modules"

class DummyClientSession:
    pass

aiohttp_stub = types.SimpleNamespace(
    ClientSession=DummyClientSession,
    TCPConnector=object,
    ClientTimeout=object,
    ClientError=Exception,
)
sys.modules["aiohttp"] = aiohttp_stub

enhanced_spec = importlib.util.spec_from_file_location(
    "enhanced_wordlist_generator", MODULE_DIR / "enhanced_wordlist_generator.py"
)
enhanced_mod = importlib.util.module_from_spec(enhanced_spec)
enhanced_spec.loader.exec_module(enhanced_mod)
sys.modules["modules.enhanced_wordlist_generator"] = enhanced_mod

class DummySecListsManager:
    def __init__(self, *args, **kwargs):
        self.wordlists = {"directories": []}

    async def initialize(self):
        return

sys.modules["modules.seclists_manager"] = types.SimpleNamespace(
    SecListsManager=DummySecListsManager
)

spec_ude = importlib.util.spec_from_file_location(
    "ultimate_discovery_engine", MODULE_DIR / "ultimate_discovery_engine.py"
)
ude = importlib.util.module_from_spec(spec_ude)
spec_ude.loader.exec_module(ude)
UltimateDiscoveryEngine = ude.UltimateDiscoveryEngine


class DummyAssetManager:
    def log_activity(self, *args, **kwargs):
        pass


def test_js_wordlist_integration(monkeypatch):
    engine = UltimateDiscoveryEngine(DummyAssetManager(), {"max_words_per_dir": 10})
    engine.seclists_manager = type("dummy", (), {"wordlists": {"directories": ["admin", "login"]}})()

    async def fake_generate(self, target_url, js_files):
        return ["api", "admin"]

    monkeypatch.setattr(
        enhanced_mod.EnhancedWordlistGenerator,
        "generate_wordlist_from_target",
        fake_generate,
    )

    async def run_test():
        words = await engine._build_candidate_wordlist(
            "http://example.com", ["http://example.com/app.js"]
        )
        assert set(words) == {"admin", "login", "api"}
        assert words.count("admin") == 1

    asyncio.run(run_test())
