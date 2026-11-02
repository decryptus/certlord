"""Disposable durable CAS store for restart and conflict fault injection."""
import copy
import json
from pathlib import Path
from unittest.mock import Mock

from certlord.ports.certificates import StorageConflict
from certlord.services.runtime import CertificateRuntime

IDENTITY = '6ff9418a-a4d7-5964-b0a3-78f920426989'
DOMAIN = 'import.example.test'


class FileStore:
    def __init__(self, path, record=None):
        self.path = Path(path)
        if record is not None:
            self.path.write_text(json.dumps({'version': 1, 'record': record}))

    def get_versioned(self, identity, domain):
        assert (identity, domain) == (IDENTITY, DOMAIN)
        value = json.loads(self.path.read_text())
        return value['record'], value['version']

    def replace_if_version(self, identity, domain, version, record):
        _, current = self.get_versioned(identity, domain)
        if current != version:
            raise StorageConflict()
        path = self.path.with_suffix('.new')
        path.write_text(json.dumps({'version': current + 1, 'record': copy.deepcopy(record)}))
        path.replace(self.path)


def runtime(store, targets):
    value = object.__new__(CertificateRuntime)
    value._store = store
    value.deployment_targets = {IDENTITY: targets}
    value.CERTIFICATES_LOCK, value.LOCK = Mock(), Mock()
    value.lock_timeout = 1
    value.evt_tcrawler = Mock()
    value.bound_domains = Mock(return_value=[DOMAIN])
    value.list_certificates = Mock(return_value=[DOMAIN])
    value.get_certificate = lambda *_: store.get_versioned(IDENTITY, DOMAIN)[0]
    return value
