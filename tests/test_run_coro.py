import asyncio
import os
import sys

import pytest
import types

# Stub out external dependencies so we can import the module without installing
sys.modules.setdefault('requests', types.ModuleType('requests'))
aiohttp_stub = types.ModuleType('aiohttp')
class _DummySession:
    pass
aiohttp_stub.ClientSession = _DummySession
sys.modules.setdefault('aiohttp', aiohttp_stub)

import importlib.util

# Load vulnerability_scanner module directly to avoid heavy package imports
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
module_path = os.path.join(repo_root, "modules", "vulnerability_scanner.py")
spec = importlib.util.spec_from_file_location("vulnerability_scanner", module_path)
vs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vs)
_run_coro = vs._run_coro

async def sample_coro(x, y):
    await asyncio.sleep(0)
    return x + y


def test_run_coro_outside_event_loop():
    assert _run_coro(sample_coro(2, 3)) == 5


def test_run_coro_inside_event_loop():
    async def runner():
        task = _run_coro(sample_coro(4, 5))
        # When called inside a running loop, _run_coro should return a Task
        assert isinstance(task, asyncio.Future)
        return await task

    result = asyncio.run(runner())
    assert result == 9
