"""Vault KV v2 certificate repository; authentication is supplied separately."""
import copy
from certlord.services.identity_definition import identity_fingerprint
from certlord.services.certificate_ids import valid_certificate_id, require_certificate_id

import hvac

from certlord.classes.config import STATUS_DELETE, STATUS_REMOVED

from certlord.ports.certificates import CertificateStore, StorageError, StorageNotFound, StorageConflict


class VaultCertificateStore(CertificateStore):
    def __init__(self, session, key_name, mount='secret'):
        self._session, self._key_name, self._mount = session, key_name.rstrip('/'), mount

    def _path(self, certificate_id=None, domain=None):
        if certificate_id is not None:
            certificate_id = require_certificate_id(certificate_id)
        return '/'.join(str(x) for x in (self._key_name, certificate_id, domain) if x is not None)

    def _call(self, method, path, **kwargs):
        try:
            client = self._session.client()
            return getattr(client.secrets.kv.v2, method)(path=path, mount_point=self._mount, **kwargs)
        except hvac.exceptions.InvalidPath:
            raise StorageNotFound('Certificate storage path not found')
        except hvac.exceptions.InvalidRequest:
            if 'cas' in kwargs:
                raise StorageConflict('Certificate changed before conditional write')
            raise StorageError('Certificate storage rejected the operation')
        except StorageError:
            raise
        except Exception:
            raise StorageError('Certificate storage operation failed')

    def put(self, certificate_id, domain, data):
        self._call('create_or_update_secret', self._path(certificate_id, domain), secret=copy.deepcopy(data))

    def get(self, certificate_id, domain):
        try:
            data, _version = self.get_versioned(certificate_id, domain)
        except StorageNotFound:
            return {}
        return data

    def get_versioned(self, certificate_id, domain):
        result = self._call('read_secret_version', self._path(certificate_id, domain),
                            raise_on_deleted_version=True)
        data = result['data']['data']
        if data.get('status') == STATUS_REMOVED:
            raise StorageNotFound('Certificate has been removed')
        return copy.deepcopy(data), result['data']['metadata']['version']

    def replace_if_version(self, certificate_id, domain, version, data):
        self._call('create_or_update_secret', self._path(certificate_id, domain),
                   secret=copy.deepcopy(data), cas=version)

    def update(self, certificate_id, domain, data):
        self._call('patch', self._path(certificate_id, domain), secret=copy.deepcopy(data))

    def delete(self, certificate_id, domain):
        _data, version = self.get_versioned(certificate_id, domain)
        # Advancing the version invalidates old save/deployment snapshots. Never
        # delete metadata: recreating it resets the counter and permits ABA writes.
        self.replace_if_version(certificate_id, domain, version, {'status': STATUS_DELETE})
        metadata = self._call('read_secret_metadata', self._path(certificate_id, domain))['data']
        versions = sorted(int(number) for number, value in metadata['versions'].items()
                          if int(number) <= version and not value.get('destroyed'))
        if versions:
            self._call('destroy_secret_versions', self._path(certificate_id, domain), versions=versions)
        # A failure above leaves a visible delete marker for retry. The final
        # marker is hidden from managed inventory, but retains the version counter.
        self.replace_if_version(certificate_id, domain, version + 1, {'status': STATUS_REMOVED})

    def _list(self, path):
        try:
            return self._call('list_secrets', path)['data']['keys']
        except StorageNotFound:
            return []

    def list_domains(self, certificate_id):
        return [name.lower() for name in self._list(self._path(certificate_id))
                if self.get(certificate_id, name)]

    def list_certificate_ids(self):
        return [name.removesuffix('/') for name in self._list(self._path())
                if valid_certificate_id(name.removesuffix('/'))]

    def bound_domains(self, certificate_id):
        # Include removed tombstones: an identity must never silently change domain.
        return [name.lower() for name in self._list(self._path(certificate_id))]


    def reserve_identity(self, definition, candidate_id):
        """Durable digest lookup and CAS=0 reservation; retries reuse the same UUID."""
        digest = identity_fingerprint(definition)
        candidate_id = require_certificate_id(candidate_id)
        path = self._key_name + '/_identities/' + digest

        def read():
            record = self._call('read_secret_version', path, raise_on_deleted_version=True)['data']['data']
            # Compare original data, not just the digest, and reject corrupt indexes.
            if record.get('definition') != definition or record.get('sha256') != digest:
                raise StorageConflict('Certificate identity index conflicts with its definition')
            return require_certificate_id(record['certificate_id'])

        try:
            return read()
        except StorageNotFound:
            pass
        # Adopt a unique pre-index record. Never silently pick one of existing duplicates.
        matches = [value for value in self.list_certificate_ids()
                   if sorted(self.bound_domains(value)) == definition['domains']]
        if len(matches) > 1:
            raise StorageConflict('Multiple certificates have this identity; reconciliation required')
        record = {'definition': copy.deepcopy(definition), 'sha256': digest,
                  'certificate_id': matches[0] if matches else candidate_id}
        try:
            self._call('create_or_update_secret', path, secret=record, cas=0)
        except StorageConflict:
            return read()
        return record['certificate_id']
