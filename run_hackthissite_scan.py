import asyncio
import aiohttp
from asset_manager import AssetManager
from modules.vulnerability_scanner import VulnerabilityScanner

async def main():
    # Configuration for the scanner
    config = {
        'enable_sqlmap': True,
        'enable_dalfox': True,
        'enable_ffuf': True,
        'enable_dom_xss': True,
        'enable_blind_xss': True,
        'enable_nuclei': True,
        'enable_headless_crawl': True,
        'enable_default_creds': True,
        'enable_brute_force_testing': True
    }

    # Initialize AssetManager and VulnerabilityScanner
    am = AssetManager()
    scanner = VulnerabilityScanner(am, config)

    async with aiohttp.ClientSession() as session:
        # Here you can define your own targets or asset lists
        targets = []

        # Run the scanner on the targets
        results = await scanner._scan_assets_for_vulnerabilities_with_session(targets, session)

        # Print the results
        print("\nScan Results:")
        for result in results:
            print(result)

if __name__ == "__main__":
    asyncio.run(main())
