import asyncio
import aiohttp
from asset_manager import AssetManager
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.intelligent_targeting import IntelligentTargeting, VulnTarget

async def main():
    config = {
        'enable_sqlmap': False,
        'enable_dalfox': False,
        'enable_ffuf': False,
        'enable_dom_xss': False,
        'enable_blind_xss': False,
        'enable_nuclei': False,
        'enable_headless_crawl': False,
        'enable_default_creds': False,
        'enable_brute_force_testing': False
    }
    am = AssetManager()
    scanner = VulnerabilityScanner(am, config)

    # Fake intelligent targeting that returns a small prioritized list
    it = IntelligentTargeting()
    async def fake_analyze_and_prioritize(assets):
        targets = []
        for a in assets:
            targets.append(VulnTarget(
                url=a.get('url',''),
                risk_score=8,
                vulnerability_classes=set(['XSS']),
                technology_stack=a.get('tech_stack',''),
                target_type='page',
                confidence=0.8,
                reasoning='unit-test'
            ))
        return targets
    it.analyze_and_prioritize = fake_analyze_and_prioritize
    scanner.intelligent_targeting = it

    # Stub the execution to avoid real network-heavy tests
    async def stub_execute_intelligent_scan(targets, session):
        print('Stub _execute_intelligent_scan called for targets:', [t.url for t in targets])
        return []
    scanner._execute_intelligent_scan = stub_execute_intelligent_scan

    async with aiohttp.ClientSession() as session:
        assets = [{'url':'http://example.com','id':1,'tech_stack':'php','status_code':200}]
        res = await scanner._scan_assets_for_vulnerabilities_with_session(assets, session)
        print('Smoke test result length:', len(res))

if __name__ == "__main__":
    asyncio.run(main())
