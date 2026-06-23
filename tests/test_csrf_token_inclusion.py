import os
import sys
import types


class FakeResponse:
    def __init__(self, status=200, headers=None, text_data="", cookies=None):
        self.status = status
        self.headers = headers or {}
        self._text = text_data
        self.cookies = cookies or {}

    async def text(self):
        return self._text

    def release(self):
        pass


class FakeCookieJar(dict):
    def update_cookies(self, cookies):
        if cookies:
            self.update(cookies)


class FakeSession:
    def __init__(self):
        self.cookie_jar = FakeCookieJar()
        self.last_request = None

    async def post(self, url, data=None, headers=None, cookies=None, allow_redirects=False):
        self.last_request = {'method': 'POST', 'url': url, 'data': data, 'headers': headers, 'cookies': cookies}
        return FakeResponse()

    async def get(self, url, params=None, headers=None, cookies=None, allow_redirects=False):
        self.last_request = {'method': 'GET', 'url': url, 'data': params, 'headers': headers, 'cookies': cookies}
        return FakeResponse()


# Stub external modules before importing scanner
project_root = os.path.dirname(os.path.dirname(__file__))
sys.path.append(project_root)

# Create a stub package for 'modules' to avoid executing its __init__
modules_pkg = types.ModuleType('modules')
modules_pkg.__path__ = [os.path.join(project_root, 'modules')]
sys.modules['modules'] = modules_pkg

sys.modules.setdefault('requests', types.SimpleNamespace())
sys.modules.setdefault('aiohttp', types.SimpleNamespace(ClientSession=FakeSession))
sys.modules.setdefault('modules.ml_engine', types.ModuleType('ml_engine'))

from modules.vulnerability_scanner import VulnerabilityScanner


class DummyAssetManager:
    def log_activity(self, *args, **kwargs):
        pass


def test_csrf_token_inclusion():
    html = (
        "<html><head><meta name='csrf-token' content='META123'></head>"
        "<body><form action='/submit' method='POST'>"
        "<input type='hidden' name='csrf_token' value='ABCDEF'>"
        "<input type='text' name='username'></form></body></html>"
    )

    import asyncio

    scanner = VulnerabilityScanner(DummyAssetManager(), {})
    forms = asyncio.get_event_loop().run_until_complete(
        scanner._parse_forms_with_values(html)
    )
    form = forms[0]
    tokens = form['tokens']

    session = FakeSession()
    asyncio.get_event_loop().run_until_complete(
        scanner._submit_form(session, "http://example.com", 'POST', {'username': 'bob'}, tokens)
    )

    assert session.last_request['data']['csrf_token'] == 'ABCDEF'
    assert session.last_request['headers']['X-CSRF-Token'] == 'META123'
