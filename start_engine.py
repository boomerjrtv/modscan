import asyncio
from engine import ModularVulnerabilityScanner

async def main():
    scanner = ModularVulnerabilityScanner()
    await scanner.run_modular_progressive_scan()

if __name__ == "__main__":
    asyncio.run(main())