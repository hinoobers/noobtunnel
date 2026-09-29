"""Create the first Mailu administrator and the domain signing key on clarine."""

import json
import subprocess
from pathlib import Path


compose = ['docker', 'compose', '-f', '/srv/mailu/compose.yaml',
           '--env-file', '/srv/mailu/mailu.env', 'exec', '-T', 'admin', 'flask', 'mailu']
password = Path('/root/mailu-admin-password').read_text().strip()

subprocess.run(compose + ['admin', 'admin', 'byenoob.com', password],
               check=True, stdout=subprocess.DEVNULL)
print('Created admin@byenoob.com')

domain = json.dumps({'domain': [{'name': 'byenoob.com', 'dkim_key': '-generate-'}]})
subprocess.run(compose + ['config-import', '--update', '--quiet', '-'],
               input=domain, text=True, check=True, stdout=subprocess.DEVNULL)
print('Generated the byenoob.com DKIM signing key')
