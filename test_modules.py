#!/usr/bin/env python3
"""Test individual module initialization to find the hanging module"""

import asyncio
import logging
import sys
sys.path.append('.')

from engine import ModularVulnerabilityScanner

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_module_init():
    """Test each module initialization individually"""
    
    scanner = ModularVulnerabilityScanner()
    
    modules_to_test = [
        ("SecLists", scanner.seclists_manager.initialize()),
        ("VulnerabilityScanner", scanner.vulnerability_scanner.initialize()),
        ("TechnologyDetector", scanner.technology_detector.initialize()),
        ("ProxyManager", scanner.proxy_manager.initialize()),
        ("MLEngine", scanner.ml_engine.initialize()),
        ("ScreenshotManager", scanner.screenshot_manager.initialize()),
        ("WAFBypass", scanner.waf_bypass.initialize()),
        ("Reconnaissance", scanner.reconnaissance.initialize()),
    ]
    
    for name, init_task in modules_to_test:
        try:
            logger.info(f"Testing {name}...")
            await asyncio.wait_for(init_task, timeout=5.0)
            logger.info(f"✅ {name} initialized successfully")
        except asyncio.TimeoutError:
            logger.error(f"❌ {name} TIMED OUT - this is the problematic module!")
        except Exception as e:
            logger.error(f"❌ {name} failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_module_init())