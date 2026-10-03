# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
"""Certificate use cases; the injected backend supplies storage and DNS ports."""
from contextlib import contextmanager
from certlord.services.verification import verification_metadata
from datetime import datetime, timezone
from certlord.services.observations import certificate_observation, prometheus_metrics
from certlord.services.certificate_ids import require_certificate_id
from certlord.services.operation_tracking import tracked, record_id
import re
import secrets
from uuid import uuid4
from certlord.services.identity_definition import identity_definition, identity_fingerprint
from certlord.services.import_material import validate_import, InvalidMaterial

from certlord.ports.certificates import StorageConflict, StorageNotFound

from certlord.classes.config import (DEFAULT_CERT_VENDOR, STATUS_CREATE, STATUS_DELETE,
                                    STATUS_EXISTS, STATUS_GENERATED,
                                    STATUS_PROCESSING)


class CertificateError(Exception):
    """Expected application error, translated to HTTP only by the transport."""


class CertificateConflict(CertificateError):
    pass


class CertificateNotFound(CertificateError):
    pass


class CertificateBusy(CertificateError):
    pass


class CertificateService(object):
    def __init__(self, backend):
        self.backend = backend

    @contextmanager
    def _lock(self, write=False, certificate_id=None):
        backend = self.backend
        if certificate_id is not None:
            if not backend.CERTIFICATES_LOCK.try_acquire(certificate_id):
                raise CertificateBusy("operation already in progress for certificate_id: %r" % certificate_id)
        else:
            acquire = backend.LOCK.acquire_write if write else backend.LOCK.acquire_read
            if not acquire(backend.lock_timeout):
                raise CertificateBusy("unable to take LOCK for %s after %s seconds" %
                                      ('writing' if write else 'reading', backend.lock_timeout))
        try:
            yield
        finally:
            if certificate_id is not None:
                backend.CERTIFICATES_LOCK.release(certificate_id)
            else:
                backend.LOCK.release()

    def _validate_domain(self, domain):
        try:
            if not self.backend.check_dns_resolv(domain):
                raise CertificateConflict("invalid DNS resolution for domain: %r" % domain)
            if not self.backend.check_caa_records(domain):
                raise CertificateConflict("invalid CAA DNS records for domain: %r" % domain)
        except CertificateError:
            raise
        except Exception:
            raise CertificateBusy("DNS validation unavailable") from None

    def deploy(self):
        with self._lock():
            self.backend.evt_tcrawler.set()

    def validate(self, domain):
        with self._lock():
            self._validate_domain(domain.lower())
            return True

    def begin_issuance(self, domain):
        domain = domain.lower()
        attempt = secrets.token_hex(32)
        with self._lock(write=True):
            certificate_ids = self.backend.get_certificate_ids_for_domain(domain).get('certificate_ids', [])
            if not certificate_ids:
                raise CertificateNotFound('No certificate_ids associated with issuance')
            snapshots = [(certificate_id, self.backend.certificate_snapshot(certificate_id, domain)) for certificate_id in certificate_ids]
            if any(snapshot[0].get('origin') == 'external' for _, snapshot in snapshots):
                raise CertificateConflict('Externally renewed certificate cannot enter ACME issuance')
            if any(snapshot[0].get('status') == STATUS_DELETE for _, snapshot in snapshots):
                raise CertificateConflict('Certificate removal is pending')
            for certificate_id, snapshot in snapshots:
                self.backend.bind_issuance(certificate_id, domain, attempt, snapshot)
        return attempt

    def save(self, payload, issuance_id=None):
        # Requests and their payloads remain owned by the transport.
        if not isinstance(issuance_id, str) or not re.fullmatch(r'[0-9a-f]{64}', issuance_id):
            raise CertificateConflict('Missing or invalid issuance identity')
        data = dict(payload)
        domain = data.pop('domain').lower()
        data['issuance_id'] = issuance_id
        data['issuance_complete'] = True
        data['chain'] = data.get('chain') or ''
        data['status'] = STATUS_GENERATED
        with self._lock(write=True):
            certificate_ids = self.backend.get_certificate_ids_for_domain(domain)
            if not certificate_ids or not certificate_ids.get('certificate_ids'):
                raise CertificateNotFound("unable to find certificate_ids for domain: %s" % domain)
            snapshots = []
            for certificate_id in certificate_ids['certificate_ids']:
                try:
                    snapshot = self.backend.certificate_snapshot(certificate_id, domain)
                except StorageNotFound:
                    raise CertificateNotFound('Certificate association no longer exists') from None
                if snapshot[0].get('status') == STATUS_DELETE:
                    raise CertificateConflict('Certificate removal is pending')
                current = snapshot[0]
                if current.get('issuance_id') != issuance_id:
                    raise CertificateConflict('Issuance has been superseded')
                if (current.get('issuance_complete') and any(
                        current.get(field) != data.get(field) for field in ('cert', 'key', 'chain'))):
                    raise CertificateConflict('Issuance already accepted different material')
                snapshots.append((certificate_id, snapshot))
            try:
                for certificate_id, snapshot in snapshots:
                    self.backend.save_certificate(certificate_id, domain, data, snapshot)
            except StorageConflict:
                raise CertificateConflict('Certificate changed during save; retry after reconciliation') from None
            finally:
                # A failed/uncertain later write must not hide earlier accepted work.
                self.backend.evt_tcrawler.set()
            return certificate_ids

    @tracked('import_certificate')
    def import_certificate(self, payload):
        # Validate all material before even reserving persistent identity.
        definition, material = validate_import(payload)
        backend = self.backend
        try:
            certificate_id = backend.reserve_identity(definition, str(uuid4()))
            domain = definition['domains'][0]
            with self._lock(certificate_id=certificate_id):
                current = backend.get_certificate(certificate_id, domain)
                if current:
                    if (current.get('status') == STATUS_DELETE
                            or current.get('origin') != 'external'
                            or any(current.get(field) != material[field] for field in ('cert', 'key', 'chain'))):
                        raise CertificateConflict('Existing certificate cannot be implicitly replaced or converted')
                else:
                    if backend.bound_domains(certificate_id):
                        raise CertificateConflict('Removed identity cannot be implicitly restored')
                    data = dict(material, status=STATUS_GENERATED, vendor='external',
                                origin='external', renewal_owner='external',
                                identity_definition=definition,
                                identity_sha256=identity_fingerprint(definition))
                    backend.create_import(certificate_id, domain, data)
                # Reconcile this step on replay after a partial Vault/Redis failure.
                backend.change_certificate_id(domain, certificate_id, True)
                backend.evt_tcrawler.set()
                return self.detail(certificate_id)
        except StorageConflict:
            raise CertificateConflict('Certificate changed during import; reconcile before retry') from None

    @tracked('replace_import')
    def replace_import(self, certificate_id, payload):
        certificate_id = require_certificate_id(certificate_id)
        if (not isinstance(payload, dict)
                or set(payload) - {'expected_version', 'cert', 'key', 'chain'}
                or type(payload.get('expected_version')) is not int
                or payload['expected_version'] <= 0):
            raise InvalidMaterial('A positive integer expected_version and PEM material are required')
        backend = self.backend
        with self._lock(certificate_id=certificate_id):
            domains = backend.bound_domains(certificate_id)
            if not domains:
                raise CertificateNotFound('Certificate not found')
            if len(domains) != 1:
                raise CertificateConflict('Certificate identity has multiple domains; repair storage')
            domain = domains[0]
            try:
                snapshot = backend.certificate_snapshot(certificate_id, domain)
            except StorageNotFound:
                raise CertificateNotFound('Certificate not found') from None
            current, version = snapshot
            if current.get('origin') != 'external' or current.get('status') == STATUS_DELETE:
                raise CertificateConflict('Only active external certificates can be replaced')
            if payload['expected_version'] != version:
                raise CertificateConflict('Certificate version changed; read current metadata before retry')
            material_input = {key: value for key, value in payload.items() if key != 'expected_version'}
            definition, material = validate_import(dict(material_input, domain=domain))
            if definition['domains'] != [domain]:
                raise CertificateConflict('Certificate domain cannot change')
            try:
                backend.replace_import(certificate_id, domain, material, snapshot)
            except StorageConflict:
                raise CertificateConflict('Certificate changed during replacement; read current metadata') from None
            finally:
                # An ambiguous storage reply may follow a committed new version.
                backend.evt_tcrawler.set()
            return self.detail(certificate_id)

    def upsert(self, certificate_id, domains):
        certificate_id = require_certificate_id(certificate_id)
        desired = set(domain.lower() for domain in domains)
        if len(desired) > 1:
            raise CertificateConflict('One domain per certificate is currently supported')
        backend = self.backend
        with self._lock(certificate_id=certificate_id):
            bound = set(backend.bound_domains(certificate_id))
            if desired and bound and desired != bound:
                raise CertificateConflict('A certificate UUID cannot be assigned to another domain')
            acerts = backend.fetch_acerts(certificate_id)
            current = set(backend.list_certificates(certificate_id))
            # Validate the whole requested set before any persistent change.
            for domain in sorted(desired):
                self._validate_domain(domain)
            reverse_certificate_ids = {}
            for domain in sorted(desired - current):
                acerts.add_dom(domain)
                reverse_certificate_ids[domain] = backend.get_certificate_ids_for_domain(domain)
                if certificate_id not in reverse_certificate_ids[domain]['certificate_ids']:
                    reverse_certificate_ids[domain]['certificate_ids'].append(certificate_id)
                if backend.duplicate_certificate(certificate_id, domain):
                    acerts.set_dom_status(domain, STATUS_EXISTS)
                else:
                    backend._create_certificate(certificate_id, domain, DEFAULT_CERT_VENDOR)
            for domain in sorted(current - desired):
                # Invalidate any pre-deployment Vault version before queueing removal.
                backend.update_certificate(certificate_id, domain, {'status': STATUS_DELETE, 'issuance_id': None})
                acerts.set_dom_status(domain, STATUS_DELETE)
                reverse_certificate_ids[domain] = backend.get_certificate_ids_for_domain(domain)
                if certificate_id in reverse_certificate_ids[domain]['certificate_ids']:
                    reverse_certificate_ids[domain]['certificate_ids'].remove(certificate_id)
            for domain in sorted(desired):
                if domain in current:
                    certificate = backend.get_certificate(certificate_id, domain)
                    if certificate.get('status') == STATUS_DELETE:
                        restored = (STATUS_GENERATED if certificate.get('cert') and certificate.get('key')
                                    else STATUS_CREATE)
                        backend.update_certificate(certificate_id, domain, {'status': restored})
                        acerts.set_dom_status(domain, STATUS_EXISTS if restored == STATUS_GENERATED else STATUS_CREATE)
                if acerts.get_dom_status(domain) in (None, STATUS_DELETE):
                    state = backend.get_certificate(certificate_id, domain).get('status')
                    acerts.set_dom_status(domain, STATUS_CREATE if state == STATUS_CREATE else STATUS_EXISTS)
                if domain not in reverse_certificate_ids:
                    reverse_certificate_ids[domain] = backend.get_certificate_ids_for_domain(domain)
                if certificate_id not in reverse_certificate_ids[domain]['certificate_ids']:
                    reverse_certificate_ids[domain]['certificate_ids'].append(certificate_id)
            backend.save_acerts(acerts)
            for domain in reverse_certificate_ids:
                backend.change_certificate_id(domain, certificate_id, domain in desired)
            return sorted(desired)

    @tracked('update_existing')
    def update_existing(self, certificate_id, domains):
        certificate_id = require_certificate_id(certificate_id)
        if not self.backend.bound_domains(certificate_id):
            raise CertificateNotFound('Certificate not found')
        return self.upsert(certificate_id, domains)

    def index(self, certificate_id):
        certificate_id = require_certificate_id(certificate_id)
        with self._lock():
            result = {}
            for domain in self.backend.list_certificates(str(certificate_id)):
                cert = self.backend.get_certificate(str(certificate_id), domain)
                result[domain] = ((cert.get('status') or STATUS_PROCESSING)
                                  if cert.get('cert') and cert.get('key') else STATUS_PROCESSING)
            return result


    @tracked('create')
    def create(self, domains):
        try:
            definition = identity_definition(domains)
        except (ValueError, UnicodeError):
            raise CertificateConflict('Invalid certificate domains') from None
        if len(definition['domains']) != 1:
            raise CertificateConflict('One domain per certificate is currently supported')
        try:
            certificate_id = self.backend.reserve_identity(definition, str(uuid4()))
        except StorageConflict as error:
            raise CertificateConflict(str(error)) from None
        # A reserved UUID survives a failed or ambiguous write. Retry reconciles
        # that same record; it never generates a second externally visible identity.
        with self._lock(certificate_id=certificate_id):
            domain = definition['domains'][0]
            record = self.backend.get_certificate(certificate_id, domain)
            if record.get('status') == STATUS_DELETE:
                raise CertificateConflict('Certificate removal is pending')
            if record:
                if record.get('status') == STATUS_CREATE:
                    self.upsert(certificate_id, definition['domains'])
                return self.detail(certificate_id)
            if self.backend.bound_domains(certificate_id):
                raise CertificateConflict('Certificate was removed; explicit restoration required')
            self.upsert(certificate_id, definition['domains'])
            return self.detail(certificate_id)

    def detail(self, certificate_id):
        certificate_id = require_certificate_id(certificate_id)
        with self._lock():
            domains = self.backend.list_certificates(certificate_id)
            if not domains:
                raise CertificateNotFound('Certificate not found')
            if len(domains) != 1:
                raise CertificateConflict('Certificate identity has multiple domains; repair storage')
            record = self.backend.get_certificate(certificate_id, domains[0])
            result = {'certificate_id': certificate_id, 'domains': domains,
                      'status': record.get('status') or STATUS_PROCESSING,
                      'verification': verification_metadata(record)}
            if record.get('origin') == 'external':
                try:
                    record, version = self.backend.certificate_snapshot(certificate_id, domains[0])
                except StorageNotFound:
                    raise CertificateNotFound('Certificate not found') from None
                result['status'] = record.get('status') or STATUS_PROCESSING
                result['version'] = version
                result['verification'] = verification_metadata(record)
                result.update({name: record.get(name) for name in
                               ('origin', 'renewal_owner', 'fingerprint_sha256', 'not_after')})
            if record_id(record):
                result['operation_id'] = record_id(record)
            return result

    def inventory(self):
        result = []
        for certificate_id in sorted(self.backend.get_certificate_ids()):
            try:
                result.append(self.detail(certificate_id))
            except CertificateNotFound:
                # Completed removals retain Vault metadata for CAS safety.
                continue
        return result

    def observations(self):
        started = datetime.now(timezone.utc).isoformat()
        records = []
        with self._lock():
            for certificate_id in sorted(self.backend.get_certificate_ids()):
                domains = self.backend.list_certificates(certificate_id)
                if not domains:
                    continue
                if len(domains) != 1:
                    raise CertificateConflict('Certificate identity has multiple domains; repair storage')
                domain = domains[0]
                try:
                    record, version = self.backend.certificate_snapshot(certificate_id, domain)
                except StorageNotFound:
                    # A concurrent confirmed removal is not a storage outage.
                    continue
                pending = self.backend.fetch_acerts(certificate_id).get_obj().get(domain, {})
                records.append(certificate_observation(certificate_id, domain, record, version, pending))
        completed = datetime.now(timezone.utc)
        return {'schema_version': 1, 'started_at': started, 'completed_at': completed.isoformat(),
                'completed_timestamp_seconds': completed.timestamp(), 'certificates': records}

    def metrics(self):
        return prometheus_metrics(self.observations())

    @tracked('remove')
    def remove(self, certificate_id):
        self.upsert(certificate_id, [])
        return {'certificate_id': certificate_id, 'removal_requested': True}
