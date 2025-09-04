import asyncio
from playwright.async_api import async_playwright
from playwright.sync_api import sync_playwright
import os
from urllib.parse import urlparse
import time
import logging

logger = logging.getLogger(__name__)

class ScreenshotManager:
    def __init__(self, asset_manager, config):
        self.asset_manager = asset_manager
        self.config = config
        self.p_async = None
        self.browser_async = None
        self.p_sync = None
        self.browser_sync = None
        self.screenshot_dir = config.get('screenshot_dir', 'screenshots')
        os.makedirs(self.screenshot_dir, exist_ok=True)

    async def get_browser(self):
        if not self.p_async:
            self.p_async = await async_playwright().start()
        if not self.browser_async or not self.browser_async.is_connected():
            self.browser_async = await self.p_async.chromium.launch()
        return self.browser_async

    def get_browser_sync(self):
        if not self.p_sync:
            self.p_sync = sync_playwright().start()
        if not self.browser_sync or not self.browser_sync.is_connected():
            self.browser_sync = self.p_sync.chromium.launch()
        return self.browser_sync

    def capture_url_sync(self, url, asset_id=None, force=False):
        """Synchronous version of capture_url"""
        try:
            parsed_url = urlparse(url)
            host = parsed_url.netloc
            # Sanitize filename
            safe_host = "".join([c if c.isalnum() else "_" for c in host])
            filename = f"screenshot_{safe_host}_{int(time.time())}.png"
            path = os.path.join(self.screenshot_dir, filename)

            if not force and os.path.exists(path):
                if asset_id:
                    asset = self.asset_manager.get_asset_by_id(asset_id)
                    if asset and asset.get('screenshot_path'):
                        return asset.get('screenshot_path')

            browser = self.get_browser_sync()
            page = browser.new_page()
            page.goto(url, wait_until='domcontentloaded', timeout=15000)
            page.screenshot(path=path)
            page.close()
            return path
        except Exception as e:
            logger.error(f"Error capturing screenshot for {url}: {e}")
            return None

    async def capture_url(self, url, asset_id=None, force=False):
        """
        Asynchronously captures a screenshot of a given URL.
        """
        try:
            parsed_url = urlparse(url)
            host = parsed_url.netloc
            safe_host = "".join([c if c.isalnum() else "_" for c in host])
            filename = f"screenshot_{safe_host}_{int(time.time())}.png"
            path = os.path.join(self.screenshot_dir, filename)

            if not force and os.path.exists(path):
                if asset_id:
                    asset = self.asset_manager.get_asset_by_id(asset_id)
                    if asset and asset.get('screenshot_path'):
                        return asset.get('screenshot_path')

            browser = await self.get_browser()
            page = await browser.new_page()
            await page.goto(url, wait_until='domcontentloaded', timeout=15000)
            await page.screenshot(path=path)
            await page.close()
            return path
        except Exception as e:
            logger.error(f"Error capturing screenshot for {url}: {e}")
            return None

    async def close(self):
        if self.browser_async:
            await self.browser_async.close()
        if self.p_async:
            await self.p_async.stop()

    def close_sync(self):
        if self.browser_sync:
            self.browser_sync.close()
        if self.p_sync:
            self.p_sync.stop()