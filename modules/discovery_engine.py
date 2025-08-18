"""
Compatibility shim for legacy imports:
    from modules.discovery_engine import DiscoveryEngine

We re-export DiscoveryEngine from the implementation that exists in this repo.
Order of preference:
  - proper_recon_engine.DiscoveryEngine
  - ultimate_discovery_engine.DiscoveryEngine
"""
# Try preferred modern name first
try:
    from .proper_recon_engine import DiscoveryEngine  # noqa: F401
except Exception:
    try:
        from .ultimate_discovery_engine import DiscoveryEngine  # noqa: F401
    except Exception as e:
        class DiscoveryEngine:  # fallback that fails loudly with context
            def __init__(self, *args, **kwargs):
                raise ImportError(
                    "No DiscoveryEngine implementation found. "
                    "Tried: proper_recon_engine.DiscoveryEngine, "
                    "ultimate_discovery_engine.DiscoveryEngine"
                ) from e
