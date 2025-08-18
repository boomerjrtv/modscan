import pathlib
import importlib.util
import sys


def _load_engine():
    """Load DiscoveryEngine without importing modules package"""
    path = pathlib.Path(__file__).resolve().parent.parent / 'modules' / 'ultimate_discovery_engine.py'
    spec = importlib.util.spec_from_file_location('ude', path)
    module = importlib.util.module_from_spec(spec)
    # Provide lightweight aiohttp stub if library missing
    if 'aiohttp' not in sys.modules:
        import types
        aiohttp_stub = types.ModuleType('aiohttp')
        class _Stub:
            pass
        aiohttp_stub.ClientSession = _Stub
        aiohttp_stub.TCPConnector = _Stub
        aiohttp_stub.ClientTimeout = _Stub
        sys.modules['aiohttp'] = aiohttp_stub
    spec.loader.exec_module(module)
    return module.DiscoveryEngine, module.visited


class DummyAssetManager:
    pass


def test_parent_directory_queued_once():
    DiscoveryEngine, visited = _load_engine()
    visited.clear()
    engine = DiscoveryEngine(DummyAssetManager(), {})
    engine._handle_discovered_url('GET', 'http://example.com/app/login.php')
    assert engine.bruteforce_queue == ['http://example.com/app/']
    engine._handle_discovered_url('GET', 'http://example.com/app/admin.php')
    assert engine.bruteforce_queue == ['http://example.com/app/']
