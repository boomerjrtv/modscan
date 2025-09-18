#!/usr/bin/env python3
"""
🔍 BROWSER DISCOVERY RUNNER
Standalone script to run browser-assisted discovery on Bykea targets
"""

import asyncio
import logging
import sys
import os

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.browser_assisted_discovery import BrowserAssistedDiscovery
from asset_manager import AssetManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def discover_bykea_targets():
    """Run browser discovery on Bykea targets to find hidden functionality."""

    # Initialize asset manager
    asset_manager = AssetManager()

    # Get Bykea targets from database
    targets = []
    try:
        conn = asset_manager.get_connection()
        cursor = conn.cursor()

        # Get unique Bykea URLs
        cursor.execute("""
            SELECT DISTINCT url FROM assets
            WHERE host LIKE '%bykea%'
            AND status_code = 200
            ORDER BY discovered_at DESC
            LIMIT 10
        """)

        targets = [row[0] for row in cursor.fetchall()]
        conn.close()

    except Exception as e:
        logger.error(f"Failed to get targets from database: {e}")
        # Fallback to manual targets
        targets = [
            'https://api.bykea.net',
            'https://kronos.bykea.net',
            'https://api.bykea.net/api',
            'https://api.bykea.net/health'
        ]

    logger.info(f"🔍 Starting browser discovery on {len(targets)} Bykea targets")

    # Initialize browser discovery
    browser_discovery = BrowserAssistedDiscovery(asset_manager)

    all_discoveries = []

    for target in targets:
        try:
            logger.info(f"🔍 Analyzing: {target}")

            # Run browser discovery
            discoveries = await browser_discovery.discover_dynamic_content(target)

            if discoveries:
                logger.info(f"🔍 Found {len(discoveries)} items on {target}:")

                for discovery in discoveries:
                    discovery_type = discovery.get('type', 'unknown')
                    discovery_url = discovery.get('url', target)
                    vuln_potential = discovery.get('vulnerability_potential', 'medium')

                    logger.info(f"  📋 {discovery_type}: {discovery_url} (potential: {vuln_potential})")

                    # Store interesting discoveries
                    if vuln_potential in ['high', 'critical']:
                        all_discoveries.append(discovery)

                        # Add to database as new asset
                        try:
                            from urllib.parse import urlparse
                            parsed = urlparse(discovery_url)
                            asset_manager.add_asset(
                                url=discovery_url,
                                host=parsed.netloc,
                                status_code=200,
                                tech_stack='',
                                discovery_method='browser_discovery'
                            )
                            logger.info(f"  ✅ Added to database: {discovery_url}")
                        except Exception as e:
                            logger.debug(f"  ⚠️ Failed to add to database: {e}")
            else:
                logger.info(f"🔍 No discoveries on {target}")

        except Exception as e:
            logger.error(f"❌ Browser discovery failed for {target}: {e}")

    # Summary report
    logger.info(f"\n🔍 BROWSER DISCOVERY SUMMARY:")
    logger.info(f"Targets analyzed: {len(targets)}")
    logger.info(f"High-value discoveries: {len(all_discoveries)}")

    if all_discoveries:
        logger.info(f"\n🎯 HIGH-VALUE TARGETS FOUND:")
        for i, discovery in enumerate(all_discoveries[:10], 1):
            logger.info(f"{i}. {discovery.get('type', 'unknown')} - {discovery.get('url', 'N/A')}")

        # Test discovered targets with SPA routes
        logger.info(f"\n🔍 Testing SPA routes on discovered targets...")
        for discovery in all_discoveries[:3]:  # Test top 3
            base_url = discovery.get('url', '')
            if base_url:
                try:
                    spa_discoveries = await browser_discovery.test_spa_routes(base_url)
                    if spa_discoveries:
                        logger.info(f"🔍 SPA routes found on {base_url}: {len(spa_discoveries)}")
                        for spa in spa_discoveries:
                            logger.info(f"  📋 {spa.get('url', 'N/A')} - {spa.get('title', 'No title')}")
                except Exception as e:
                    logger.debug(f"SPA testing failed for {base_url}: {e}")

    logger.info(f"\n🎯 Browser discovery complete!")
    return all_discoveries

if __name__ == "__main__":
    try:
        discoveries = asyncio.run(discover_bykea_targets())

        if discoveries:
            print(f"\n✅ Found {len(discoveries)} high-value targets for vulnerability testing!")
        else:
            print(f"\n⚠️ No high-value targets discovered - Bykea may have good security!")

    except Exception as e:
        print(f"❌ Browser discovery failed: {e}")
        import traceback
        traceback.print_exc()