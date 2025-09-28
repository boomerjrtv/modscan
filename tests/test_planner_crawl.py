import asyncio

from modules.ai_strategy_planner import AIStrategyPlanner
from modules.observation_store import Observation, ObservationStore

class FakeScanner:
    def __init__(self):
        self._headers_calls = []

    async def _get_auth_headers(self, url):
        self._headers_calls.append(url)
        return {}

    def _looks_like_laravel(self, headers, body, url):
        return 'laravel' in body.lower()

class FakeResponse:
    def __init__(self, text, headers=None, status=200):
        self._text = text
        self.headers = headers or {}
        self.status = status

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

class FakeSession:
    def __init__(self, responses):
        self._responses = responses

    def get(self, url, headers=None, timeout=None):
        resp = self._responses.get(url)
        if not resp:
            resp = FakeResponse('', {})
        return resp


def test_laravel_probe_uses_discovered_links():
    async def _run():
        store = ObservationStore()
        scanner = FakeScanner()
        planner = AIStrategyPlanner(store, scanner)

        base_url = 'http://example.com/app'
        html = '''
            <html>
                <body>
                    <form action="/get-key"><input name="a"></form>
                    <a href="/cve.php">helper</a>
                </body>
            </html>
        '''
        obs = Observation(
            url=base_url,
            method='GET',
            status_code=200,
            headers={'Content-Type': 'text/html'},
            cookies={},
            forms=[],
            body_preview=html,
            metadata={'laravel_detected': True}
        )
        store.record(obs)

        laravel_text = 'This is laravel APP_KEY=base64:ABCDEFGHIJKLMNOPQRSTUVWX1234567890\nX-XSRF-TOKEN: token'
        responses = {
            'http://example.com/get-key': FakeResponse(laravel_text, {'X-XSRF-TOKEN': 'token'}),
            'http://example.com/cve.php': FakeResponse(laravel_text, {'X-XSRF-TOKEN': 'token'})
        }
        session = FakeSession(responses)

        await planner._probe_laravel_endpoints(obs, session)

        meta = store.get_host_metadata('example.com')
        assert 'laravel_app_keys' in meta and meta['laravel_app_keys'], 'APP_KEY should be recorded'
        assert meta.get('xsrf_tokens_exposed'), 'XSRF exposure should be noted'
        observed_urls = {o.url for o in store.get_observations('example.com')}
        assert 'http://example.com/get-key' in observed_urls
        assert 'http://example.com/cve.php' in observed_urls

    asyncio.run(_run())
