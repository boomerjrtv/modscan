#!/usr/bin/env python3
"""
Screenshot Manager Module - Advanced screenshot capture with AssetManager
"""

import asyncio
import logging
import subprocess
import os
import hashlib
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from typing import Dict, Optional

logger = logging.getLogger("ScreenshotManager")

class ScreenshotManager:
    """Advanced screenshot management using AssetManager field mappings"""
    
    def __init__(self, asset_manager, config: Dict):
        self.asset_manager = asset_manager  # Use YOUR AssetManager
        self.config = config
        self.max_concurrent = 100  # AGGRESSIVE: 100 concurrent screenshots with 1Gb bandwidth
        
        # Screenshot settings
        self.screenshot_dir = Path(config.get('screenshot_dir', 'screenshots'))
        self.screenshot_dir.mkdir(exist_ok=True)

        # AGGRESSIVE Browser settings for speed
        self.browser_timeout = 8  # Fast timeout - don't wait for slow sites
        self.window_size = "1366,768"
        self.enabled = True

        logger.info("📸 ScreenshotManager initialized with AssetManager integration")
    
    async def initialize(self):
        """Initialize screenshot manager with hang prevention"""
        try:
            # Use asyncio.wait_for to prevent hangs
            chrome_available = await asyncio.wait_for(
                self._check_chrome_availability(),
                timeout=8.0
            )

            if not chrome_available:
                logger.warning("⚠️ Chrome not available - screenshots will be disabled")
                self.enabled = False
            
            # Log initialization using AssetManager
            self.asset_manager.log_activity(
                'SCREENSHOT_INIT',
                f'ScreenshotManager initialized - Chrome available: {chrome_available}'
            )
            
            logger.info("✅ ScreenshotManager initialization complete")
            
        except asyncio.TimeoutError:
            logger.warning("⚠️ Chrome check timed out - screenshots will be disabled")
            self.enabled = False
        except Exception as e:
            logger.error(f"ScreenshotManager initialization failed: {e}")
            self.enabled = False
            # Continue anyway - don't let screenshot issues block the engine
    
    def adjust_performance(self, direction: str, max_concurrent: int):
        """Adjust screenshot performance based on CPU usage"""
        if direction == "increase":
            self.max_concurrent = min(15, max_concurrent // 20)
        else:
            self.max_concurrent = max(5, max_concurrent // 30)
        
        logger.debug(f"ScreenshotManager performance adjusted: {self.max_concurrent} concurrent")
    
    async def _check_chrome_availability(self) -> bool:
        """Check if Chrome/Chromium is available for screenshots"""
        chrome_commands = [
            'google-chrome',
            'chromium-browser',
            'chromium',
            'chrome'
        ]
        
        for chrome_cmd in chrome_commands:
            try:
                # More robust Chrome check with shorter timeout
                result = subprocess.run(
                    [chrome_cmd, '--version'],
                    capture_output=True,
                    text=True,
                    timeout=2  # Reduced from 5 to 2 seconds
                )
                if result.returncode == 0:
                    logger.info(f"✅ Found Chrome: {chrome_cmd}")
                    return True
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
                logger.debug(f"Chrome check failed for {chrome_cmd}: {e}")
                continue
            except Exception as e:
                logger.debug(f"Unexpected error checking {chrome_cmd}: {e}")
                continue
        
        return False
    
    async def process_pending_screenshots(self, session, limit: int = 30) -> int:
        """Process assets needing screenshots"""
        
        if not self.enabled:
            return 0

        # Get assets needing screenshots using AssetManager
        pending_assets = self.asset_manager.get_assets_needing_screenshots(limit)

        if not pending_assets:
            return 0
        
        logger.info(f"📸 Processing {len(pending_assets)} assets for screenshot capture")
        
        semaphore = asyncio.Semaphore(min(self.max_concurrent, len(pending_assets)))
        screenshot_tasks = []
        
        for asset in pending_assets:
            screenshot_tasks.append(
                self._capture_asset_screenshot(asset, semaphore)
            )
        
        if screenshot_tasks:
            results = await asyncio.gather(*screenshot_tasks, return_exceptions=True)
            completed = sum(1 for r in results if r is True)
            
            logger.info(f"✅ Screenshot capture completed: {completed}/{len(screenshot_tasks)} assets")
            return completed
        
        return 0
    
    async def _capture_asset_screenshot(self, asset: Dict, semaphore: asyncio.Semaphore) -> bool:
        """Capture screenshot for single asset"""
        async with semaphore:
            try:
                url = asset['url']
                asset_id = asset['id']
                
                # Generate screenshot filename
                screenshot_path = self._generate_screenshot_path(url)
                
                # Capture screenshot
                success = await self._take_screenshot_with_chrome(url, screenshot_path)
                
                if success:
                    # Update asset with screenshot path using AssetManager
                    update_success = self.asset_manager.update_screenshot_path(asset_id, str(screenshot_path))
                    
                    if update_success:
                        logger.debug(f"📸 Screenshot captured and stored: {url}")
                        return True
                    else:
                        logger.warning(f"⚠️ Screenshot captured but database update failed: {url}")
                        return False
                else:
                    logger.debug(f"❌ Screenshot capture failed: {url}")
                    return False
                    
            except Exception as e:
                logger.error(f"Screenshot capture error for {asset.get('url', 'unknown')}: {e}")
                return False
    
    def _generate_screenshot_path(self, url: str) -> Path:
        """Generate unique screenshot file path"""
        try:
            parsed = urlparse(url)
            
            # Create safe filename
            hostname = parsed.netloc.replace(':', '_').replace('/', '_')
            path_part = parsed.path.replace('/', '_').replace('?', '_').replace('&', '_')
            
            # Create unique identifier
            url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
            
            # Generate filename
            filename = f"{hostname}_{path_part}_{url_hash}.png"
            filename = filename.replace('__', '_').strip('_')
            
            return self.screenshot_dir / filename
            
        except Exception as e:
            logger.debug(f"Error generating screenshot path for {url}: {e}")
            # Fallback to hash-based filename
            url_hash = hashlib.md5(url.encode()).hexdigest()
            return self.screenshot_dir / f"screenshot_{url_hash}.png"
    
    async def _take_screenshot_with_chrome(self, url: str, screenshot_path: Path) -> bool:
        """Take screenshot using headless Chrome"""
        try:
            chrome_commands = [
                'google-chrome',
                'chromium-browser', 
                'chromium',
                'chrome'
            ]
            
            chrome_cmd = None
            for cmd in chrome_commands:
                try:
                    # Test if command exists
                    subprocess.run([cmd, '--version'], capture_output=True, timeout=2)
                    chrome_cmd = cmd
                    break
                except:
                    continue
            
            if not chrome_cmd:
                logger.debug("No Chrome browser found for screenshots")
                return False
            
            # Chrome arguments for headless screenshot
            chrome_args = [
                chrome_cmd,
                '--headless',
                '--no-sandbox',
                '--disable-gpu',
                '--disable-software-rasterizer',
                '--disable-dev-shm-usage',
                '--disable-extensions',
                '--disable-plugins',
                '--disable-images',  # Faster loading
                '--disable-background-timer-throttling',
                f'--window-size={self.window_size}',
                f'--screenshot={screenshot_path}',
                '--virtual-time-budget=10000',  # 10 second budget
                url
            ]
            
            # Execute Chrome screenshot
            process = await asyncio.create_subprocess_exec(
                *chrome_args,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            
            try:
                await asyncio.wait_for(process.wait(), timeout=self.browser_timeout)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                logger.debug(f"Screenshot timeout for {url}")
                return False
            
            # Check if screenshot was created and is valid
            if screenshot_path.exists():
                file_size = screenshot_path.stat().st_size
                
                if file_size > 1000:  # Valid PNG should be > 1KB
                    logger.debug(f"✅ Screenshot captured: {url} ({file_size} bytes)")
                    return True
                else:
                    # Remove invalid screenshot
                    screenshot_path.unlink()
                    logger.debug(f"⚠️ Screenshot too small, removed: {url}")
                    return False
            else:
                logger.debug(f"❌ Screenshot file not created: {url}")
                return False
                
        except Exception as e:
            logger.debug(f"Chrome screenshot failed for {url}: {e}")
            return False
    
    def get_screenshot_statistics(self) -> Dict:
        """Get screenshot capture statistics"""
        try:
            screenshot_files = list(self.screenshot_dir.glob("*.png"))
            total_screenshots = len(screenshot_files)
            total_size = sum(f.stat().st_size for f in screenshot_files)
            
            return {
                "total_screenshots": total_screenshots,
                "total_size_mb": round(total_size / (1024 * 1024), 2),
                "average_size_kb": round(total_size / max(total_screenshots, 1) / 1024, 2),
                "screenshot_directory": str(self.screenshot_dir)
            }
        except Exception as e:
            logger.debug(f"Error getting screenshot statistics: {e}")
            return {
                "total_screenshots": 0,
                "total_size_mb": 0,
                "average_size_kb": 0,
                "screenshot_directory": str(self.screenshot_dir)
            }
    
    def cleanup_old_screenshots(self, days_old: int = 30):
        """Clean up screenshots older than specified days"""
        try:
            import time
            cutoff_time = time.time() - (days_old * 24 * 60 * 60)
            cleaned = 0
            
            for screenshot_file in self.screenshot_dir.glob("*.png"):
                if screenshot_file.stat().st_mtime < cutoff_time:
                    screenshot_file.unlink()
                    cleaned += 1
            
            logger.info(f"🧹 Cleaned up {cleaned} old screenshots (>{days_old} days)")
            
            # Log cleanup using AssetManager
            self.asset_manager.log_activity(
                'SCREENSHOT_CLEANUP',
                f'Cleaned up {cleaned} old screenshots older than {days_old} days'
            )
            
            return cleaned
            
        except Exception as e:
            logger.error(f"Screenshot cleanup failed: {e}")
            return 0
