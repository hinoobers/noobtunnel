"""One-time DNS setup using clarine's existing Cloudflare token.

Run on clarine only. The token is read in memory and copied to Certbot's
root-owned credential file so certificate renewal does not depend on noobtunnel.
"""

import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path


STATE = Path('/var/lib/noobtunnel/state.json')
CERTBOT_CREDENTIALS = Path('/etc/letsencrypt/cloudflare.ini')
BASE = 'https://api.cloudflare.com/client/v4'
DOMAIN = 'byenoob.com'
MAIL_HOST = 'mail.byenoob.com'


def token_from_state():
    providers = json.loads(STATE.read_text()).get('dnsProviders', [])
    for provider in providers:
        if provider.get('kind') == 'cloudflare' and provider.get('enabled') and provider.get('token'):
            return provider['token']
    raise RuntimeError('No enabled Cloudflare DNS provider exists on clarine')


def request(token, method, path, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method, headers={
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json',
    })
    with urllib.request.urlopen(req, timeout=20) as response:
        answer = json.load(response)
    if not answer.get('success'):
        raise RuntimeError('Cloudflare API rejected ' + method + ' ' + path)
    return answer['result']


def zone_id(token):
    zones = request(token, 'GET', '/zones?name=' + DOMAIN)
    if len(zones) != 1 or zones[0]['name'] != DOMAIN:
        raise RuntimeError('Cloudflare zone for ' + DOMAIN + ' was not found')
    return zones[0]['id']


def ensure_record(token, zone, kind, name, content, **extra):
    query = urllib.parse.urlencode({'type': kind, 'name': name})
    current = request(token, 'GET', f'/zones/{zone}/dns_records?{query}')
    wanted = {'type': kind, 'name': name, 'content': content, 'ttl': 300, **extra}
    for record in current:
        if record['name'] != name or record['type'] != kind:
            continue
        if (record['content'].rstrip('.') == content.rstrip('.') and
                all(record.get(key) == value for key, value in extra.items())):
            print(kind, name, 'already correct')
            return
        raise RuntimeError(f'Existing {kind} record for {name} needs review before changing')
    request(token, 'POST', f'/zones/{zone}/dns_records', wanted)
    print(kind, name, 'created')


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ('prepare', 'activate'):
        raise SystemExit('usage: cloudflare_setup.py prepare|activate')
    token = token_from_state()
    zone = zone_id(token)
    if sys.argv[1] == 'prepare':
        ensure_record(token, zone, 'A', MAIL_HOST, '89.144.8.232', proxied=False)
        CERTBOT_CREDENTIALS.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(CERTBOT_CREDENTIALS, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as out:
            out.write('dns_cloudflare_api_token = ' + token + '\n')
        os.chmod(CERTBOT_CREDENTIALS, 0o600)
        print('Certbot credential file prepared')
    else:
        exported = subprocess.check_output([
            'docker', 'compose', '-f', '/srv/mailu/compose.yaml',
            '--env-file', '/srv/mailu/mailu.env', 'exec', '-T', 'admin',
            'flask', 'mailu', 'config-export', '--dns', '--json', 'domain',
        ], text=True)
        domains = json.loads(exported)['domain']
        signing_key = next((entry.get('dkim_publickey') for entry in domains
                            if entry.get('name') == DOMAIN), None)
        if not signing_key:
            raise RuntimeError('Mailu has no DKIM public key for ' + DOMAIN)
        ensure_record(token, zone, 'TXT', 'dkim._domainkey.' + DOMAIN,
                      'v=DKIM1; k=rsa; p=' + signing_key)
        ensure_record(token, zone, 'MX', DOMAIN, MAIL_HOST, priority=10)
        ensure_record(token, zone, 'TXT', DOMAIN, 'v=spf1 mx -all')
        ensure_record(token, zone, 'TXT', '_dmarc.' + DOMAIN,
                      'v=DMARC1; p=none; rua=mailto:admin@byenoob.com')


if __name__ == '__main__':
    main()
