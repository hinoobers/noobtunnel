"""Back up Mailu to Cassandra over the mesh with encrypted restic snapshots."""

import os
import sqlite3
import subprocess
from pathlib import Path


STAGING = Path('/var/lib/mailu-backup/databases')
REPOSITORY = 'sftp:cassandra-mail-backup:/srv/mailu-backup/repo'
PASSWORD_FILE = '/etc/mailu-backup/restic-password'


def sqlite_snapshot(source: Path, name: str) -> None:
    destination = STAGING / name
    temporary = STAGING / (name + '.tmp')
    temporary.unlink(missing_ok=True)
    with sqlite3.connect(f'file:{source}?mode=ro', uri=True) as live:
        with sqlite3.connect(temporary) as copy:
            live.backup(copy)
    os.chmod(temporary, 0o600)
    temporary.replace(destination)


def restic(*arguments: str) -> None:
    environment = os.environ.copy()
    environment['RESTIC_PASSWORD_FILE'] = PASSWORD_FILE
    subprocess.run(['restic', '-r', REPOSITORY, *arguments], env=environment, check=True)


def main() -> None:
    STAGING.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(STAGING, 0o700)
    sqlite_snapshot(Path('/srv/mailu/data/main.db'), 'main.db')
    sqlite_snapshot(Path('/srv/mailu/webmail/roundcube.db'), 'roundcube.db')
    restic(
        'backup', '--tag', 'mailu', '--host', 'clarine',
        '--exclude', '/srv/mailu/data/main.db',
        '--exclude', '/srv/mailu/webmail/roundcube.db',
        '--exclude', '/srv/mailu/redis',
        '/srv/mailu', str(STAGING),
        '/root/mailu-noreply-password',
        '/etc/letsencrypt/cloudflare.ini',
        '/etc/letsencrypt/renewal/mail.byenoob.com.conf',
    )
    restic('forget', '--keep-daily', '7', '--keep-weekly', '5',
           '--keep-monthly', '12', '--prune')


if __name__ == '__main__':
    main()
