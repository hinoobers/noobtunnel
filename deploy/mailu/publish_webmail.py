"""Publish Mailu's TLS web UI through the existing noobtunnel HTTPS port.

Run on clarine with NOOBTUNNEL_ADMIN_PASSWORD in the environment. Mailu itself
continues to listen independently on port 9443 and on its direct mail ports.
"""

import http.cookiejar
import json
import os
import ssl
import urllib.error
import urllib.request


BASE = 'https://127.0.0.1:8443'
DOMAIN = 'mail.byenoob.com'
password = os.environ.get('NOOBTUNNEL_ADMIN_PASSWORD')
if not password:
    raise SystemExit('Control-node admin password is unavailable')

cookies = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cookies),
    urllib.request.HTTPSHandler(context=ssl._create_unverified_context()),
)


def api(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(BASE + path, data=data, method=method,
                                     headers={'Content-Type': 'application/json', 'X-Noobtunnel': '1'})
    try:
        with opener.open(request, timeout=20) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        detail = error.read(500).decode('utf-8', 'replace')
        raise RuntimeError(f'{method} {path} returned HTTP {error.code}: {detail}') from None


api('POST', '/api/login', {'username': 'admin', 'password': password})
resources = api('GET', '/api/resources')['resources']
if any(item.get('domain') == DOMAIN for item in resources):
    print('mail.byenoob.com is already published')
else:
    api('POST', '/api/resources', {
        'name': 'Mailu webmail',
        'protocol': 'https',
        'domain': DOMAIN,
        'listenPort': 443,
        'strategy': 'round-robin',
        'enabled': True,
        'targets': [
            {'agentId': 0, 'host': '127.0.0.1', 'port': 8080},
        ],
    })
    print('Published mail.byenoob.com through existing HTTPS listener')
