import os
from asset_manager import AssetManager

# Try to import the discovery engine and wrap any likely entrypoints
try:
    from modules.ultimate_discovery_engine import UltimateDiscoveryEngine as _UDE
except Exception as e:
    print("[dedup] unable to import UltimateDiscoveryEngine:", e)
else:
    _AM = AssetManager()
    _TTL = None
    def _ttl():
        global _TTL
        if _TTL is None:
            try: _TTL = int(os.environ.get("MODSCAN_TTL_HOURS","24"))
            except Exception: _TTL = 24
        return _TTL

    def _pick_host(self, args, kwargs):
        # best-effort to find the domain/host argument or attr
        for k in ("domain","root_domain","target_domain","target","host"):
            if k in kwargs and kwargs[k]: return kwargs[k]
        if args: return args[0]
        for k in ("domain","root_domain","target_domain","target","host"):
            v = getattr(self, k, None)
            if v: return v
        return None

    def _wrap(fn):
        def _inner(self, *args, **kwargs):
            host = _pick_host(self, args, kwargs)
            if host and hasattr(_AM, "should_scan_host") and not _AM.should_scan_host(host, ttl_hours=_ttl()):
                try:
                    self.logger.info(f"⏭️  Skipping {host}: scanned within {_ttl()}h")
                except Exception:
                    print(f"[dedup] skip {host} within TTL {_ttl()}h")
                return
            return fn(self, *args, **kwargs)
        return _inner

    # Wrap the most likely entrypoints (whichever exist)
    for name in ("run_discovery","discover","run","start","execute","run_ultimate_discovery"):
        if hasattr(_UDE, name):
            setattr(_UDE, name, _wrap(getattr(_UDE, name)))
            print(f"[dedup] wrapped UltimateDiscoveryEngine.{name}")
