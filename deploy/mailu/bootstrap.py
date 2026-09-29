"""Create Mailu's local secrets on clarine without putting them in Git or logs."""

import os
import secrets
from pathlib import Path


ROOT = Path('/srv/mailu')
template = (ROOT / 'mailu.env.template').read_text()
env_path = ROOT / 'mailu.env'
password_path = Path('/root/mailu-admin-password')

if not env_path.exists():
    content = template.replace('REPLACE_WITH_RANDOM_SECRET', secrets.token_hex(16))
    fd = os.open(env_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as out:
        out.write(content)
    print('Created root-only Mailu environment')

if not password_path.exists():
    fd = os.open(password_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as out:
        out.write(secrets.token_urlsafe(24) + '\n')
    print('Created root-only initial admin password')
