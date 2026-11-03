"""Private single-host durable intent and non-expiring per-ARN process lock."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat

from certlord.cloudfront.config import JobError, require


class Ledger:
    def __init__(self, directory):
        self.directory = Path(directory)
        require(self.directory.is_absolute(), 'invalid_state_dir')
        info = self.directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                and not stat.S_IMODE(info.st_mode) & 0o077, 'insecure_state_dir')
        self.path = self.directory / 'intent.sqlite3'
        if self.path.exists() or self.path.is_symlink():
            info = self.path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                    and not stat.S_IMODE(info.st_mode) & 0o077, 'insecure_ledger')
        else:
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                os.close(fd)
            except FileExistsError:
                info = self.path.lstat()
                require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                        and not stat.S_IMODE(info.st_mode) & 0o077, 'insecure_ledger')
        self.db = sqlite3.connect(self.path, timeout=5)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS intents (arn TEXT PRIMARY KEY, data TEXT NOT NULL)')
        self.db.commit()

    def close(self):
        self.db.close()

    @contextmanager
    def locked(self, arn):
        path = self.directory / (hashlib.sha256(arn.encode()).hexdigest() + '.lock')
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise JobError('arn_busy') from None
            yield
        finally:
            os.close(fd)

    def read(self, arn):
        row = self.db.execute('SELECT data FROM intents WHERE arn=?', (arn,)).fetchone()
        return json.loads(row[0]) if row else None

    def save(self, arn, entry):
        # Never store PEM/key material or raw exception messages in this database.
        allowed = {'intent_id', 'profile', 'generation', 'fingerprint', 'state', 'deadline',
                   'error_code', 'reconciled_fingerprint', 'material_sha256'}
        require(set(entry) <= allowed, 'invalid_ledger_entry')
        with self.db:
            self.db.execute('INSERT INTO intents VALUES (?,?) ON CONFLICT(arn) DO UPDATE SET data=excluded.data',
                            (arn, json.dumps(entry, sort_keys=True)))
