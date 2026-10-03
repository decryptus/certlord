# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
"""Certificate application and worker lifecycle, without an HTTP dependency."""
from certlord.services.operation_tracking import stamp, current_id, record_id, emit
import math
import logging
import time
import threading
from datetime import datetime
from sonicprobe.libs.moresynchro import RWLock, ListLock
from certlord.services.certificates import CertificateService
from certlord.services.identity_definition import identity_definition, identity_fingerprint
from certlord.ports.certificates import StorageNotFound
from certlord.classes.config import STATUS_CREATE, STATUS_GENERATED, STATUS_DEPLOYED, DEFAULT_CERT_VENDOR, DEFAULT_WORKER_STOP_TIMEOUT, DEFAULT_MAX_RETRIES
from certlord.classes.certbot_handler import SslCertsCertbotHandler
from certlord.classes.vault_crawler import SslCertsVaultCrawler
from certlord.classes.deployer import SslCertsDeployer

class CertificateRuntime(object):
    def __init__(self, config, modconf, store, pending, dns_policy, commands, monitoring, cycles=None):
        self.config, self.modconf = config, modconf
        self.lock_timeout = config['general']['lock_timeout']
        self.LOCK, self.CERTIFICATES_LOCK = RWLock(), ListLock()
        self._store, self._pending = store, pending
        self.reserve_identity = store.reserve_identity
        self._commands, self._monitoring = commands, monitoring
        self._redis = pending._redis
        self.evt_deployer, self.evt_tcrawler = threading.Event(), threading.Event()
        self.service = CertificateService(self)
        self._worker_stop_timeout = float(modconf.get('worker_stop_timeout', DEFAULT_WORKER_STOP_TIMEOUT))
        if not math.isfinite(self._worker_stop_timeout) or self._worker_stop_timeout <= 0:
            raise ValueError('Worker stop timeout must be finite and positive')
        self._cycles = cycles
        self._workers = []
        self._started = False
        self._stopping = False
        self._operation_scan_limit = modconf.get('operation_scan_limit', 10000)
        if type(self._operation_scan_limit) is not int or self._operation_scan_limit <= 0:
            raise ValueError('operation_scan_limit must be a positive integer')
        self.check_dns_resolv = dns_policy.check_dns_resolv
        self.check_caa_records = dns_policy.check_caa_records
        self.fetch_acerts = pending.fetch_acerts
        self.save_acerts = pending.save_acerts
        self.get_certificate_ids_for_domain = pending.get_certificate_ids_for_domain
        self.set_certificate_ids_for_domain = pending.set_certificate_ids_for_domain
        self.change_certificate_id = pending.change_certificate_id
        self.create_ssl_check = monitoring.create_ssl_check
        self.delete_ssl_check = monitoring.delete_ssl_check
        self.fetch_ssl_checks = monitoring.fetch_ssl_checks

    def start(self):
        if self._workers:
            raise RuntimeError('Certificate workers already started')
        self._workers = [SslCertsCertbotHandler(self, self._redis),
                         SslCertsVaultCrawler(self, self._redis, None),
                         SslCertsDeployer(self, self._redis)]
        try:
            for worker in self._workers:
                worker._cycle_tracker = self._cycles
                worker.daemon = True
                worker.start()
            self._started = True
        except Exception:
            self.stop()
            raise

    def stop(self):
        self._stopping = True
        for worker in self._workers:
            worker.terminate()
        deadline = time.monotonic() + self._worker_stop_timeout
        for worker in self._workers:
            if worker.ident is not None and worker is not threading.current_thread():
                worker.join(max(0, deadline - time.monotonic()))
        alive = [worker.name for worker in self._workers if worker.is_alive()]
        if alive:
            logging.getLogger(__name__).error('Workers still stopping: %s', ', '.join(alive))
        return not alive

    def live(self):
        return {'alive': True, 'phase': 'stopping' if self._stopping else
                ('running' if self._started else 'starting')}

    def readiness(self):
        dependencies = {}
        for name, check in (('storage', self._store.list_certificate_ids), ('redis', self._redis.ping)):
            try:
                result = check()
                dependencies[name] = bool(result) and all(result.values()) if name == 'redis' else True
            except Exception:
                dependencies[name] = False
        workers = {worker.name: worker.is_alive() for worker in self._workers}
        ready = (self._started and not self._stopping and len(workers) == 3
                 and all(workers.values()) and all(dependencies.values()))
        return {'ready': bool(ready), 'phase': self.live()['phase'],
                'dependencies': dependencies, 'workers': workers}

    def operations(self):
        result = self._pending.operations(self.config['general']['server_id'],
                                          self._operation_scan_limit, self.modconf.get('max_retries') or DEFAULT_MAX_RETRIES)
        if self._cycles is not None:
            result['cycles'] = self._cycles.snapshot()
        return result

    def _get_auton_cred(self):
        return self._commands._get_auton_cred()


    def certbot_cmd(self):
        return self._commands.certbot_cmd()


    def auton_cmd(self):
        return self._commands.auton_cmd()


    def _create_certificate(self, certificate_id, domain, vendor = None, data = None):
        if not data:
            data = {'cert':       "",
                    'chain':      "",
                    'key':        "",
                    'status':     STATUS_CREATE}

        data = stamp(dict(data), force_new=True)
        definition = identity_definition([domain])
        data['identity_definition'] = definition
        data['identity_sha256'] = identity_fingerprint(definition)
        data['vendor']     = vendor or data.get('vendor') or ""
        data['updated_at'] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")

        self._store.put(certificate_id, domain, data)
        emit('certificate_stored', record_id(data), certificate_id)


    def certificate_snapshot(self, certificate_id, domain):
        return self._store.get_versioned(certificate_id, domain)

    def bind_issuance(self, certificate_id, domain, attempt, snapshot):
        current, version = snapshot
        payload = dict(current, issuance_id=attempt, issuance_complete=False)
        self._store.replace_if_version(certificate_id, domain, version, payload)
        emit('issuance_bound', record_id(payload), certificate_id)

    def save_certificate(self, certificate_id, domain, data, snapshot):
        current, version = snapshot
        payload = dict(data)
        payload.pop('operation_id', None)
        for field in ('identity_definition', 'identity_sha256', 'operation_id'):
            if field in current:
                payload[field] = current[field]
        payload['vendor'] = DEFAULT_CERT_VENDOR
        if (current.get('status') in (STATUS_GENERATED, STATUS_DEPLOYED)
                and all(current.get(field) == payload.get(field)
                        for field in ('cert', 'key', 'chain', 'vendor', 'issuance_id', 'issuance_complete'))):
            return
        payload['updated_at'] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")
        self._store.replace_if_version(certificate_id, domain, version, payload)
        emit('issuance_material_stored', record_id(payload), certificate_id)

    def create_import(self, certificate_id, domain, data):
        payload = dict(data, updated_at=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00"))
        stamp(payload, force_new=True)
        self._store.replace_if_version(certificate_id, domain, 0, payload)
        emit('import_stored', record_id(payload), certificate_id)

    def replace_import(self, certificate_id, domain, material, snapshot):
        current, version = snapshot
        payload = dict(current)
        payload.update(material)
        payload.pop('deployment_receipt', None)
        stamp(payload, force_new=True)
        payload.pop('verification', None)
        payload.update(status=STATUS_GENERATED, origin='external', renewal_owner='external',
                       vendor='external', updated_at=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00"))
        self._store.replace_if_version(certificate_id, domain, version, payload)
        emit('replacement_stored', record_id(payload), certificate_id)

    def record_verification(self, certificate_id, domain, snapshot, verification):
        data, version = snapshot
        payload = dict(data, verification=dict(verification))
        self._store.replace_if_version(certificate_id, domain, version, payload)

    def mark_deployed(self, certificate_id, domain, snapshot, verification=None, receipt=None):
        data, version = snapshot
        payload = dict(data)
        payload['status'] = STATUS_DEPLOYED
        payload.pop('deployment_receipt', None)
        if receipt is not None:
            payload['deployment_receipt'] = dict(receipt)
        payload.pop('verification', None)
        if verification is not None:
            payload['verification'] = dict(verification)
        payload['updated_at'] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")
        self._store.replace_if_version(certificate_id, domain, version, payload)
        emit('deployment_stored', record_id(payload), certificate_id)

    def update_certificate(self, certificate_id, domain, data):
        if not isinstance(data, dict):
            return
        payload = dict(data)
        if current_id():
            stamp(payload)
        payload['updated_at'] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")
        self._store.update(certificate_id, domain, payload)
        emit('certificate_update_stored', record_id(payload), certificate_id)


    def duplicate_certificate(self, certificate_id, domain):
        associations = self.get_certificate_ids_for_domain(domain)
        if not associations \
           or not associations.get('certificate_ids'):
            return False

        for other_certificate_id in associations['certificate_ids']:
            cert = self.get_certificate(other_certificate_id, domain)
            if not cert.get('cert') or not cert.get('key'):
                continue
            if certificate_id == other_certificate_id:
                return True

            cert.pop('issuance_id', None)
            cert.pop('issuance_complete', None)
            cert.pop('verification', None)
            cert.pop('deployment_receipt', None)
            cert['status'] = STATUS_GENERATED
            self._create_certificate(certificate_id, domain, data = cert)
            return True

        return False


    def get_certificate(self, certificate_id, domain):
        return self._store.get(certificate_id, domain)


    def delete_certificate(self, certificate_id, domain):
        certificate_ids = self.get_certificate_ids_for_domain(domain)['certificate_ids']
        remaining = [member for member in certificate_ids if member != certificate_id]
        if not remaining:
            self.delete_ssl_check(domain)
        try:
            self._store.delete(certificate_id, domain)
        except StorageNotFound:
            pass
        # Repair a stale reverse association after a partial removal as well.
        if remaining != certificate_ids:
            self.change_certificate_id(domain, certificate_id, False)


    def list_certificates(self, certificate_id):
        return self._store.list_domains(certificate_id)


    def get_certificate_ids(self):
        return self._store.list_certificate_ids()



    def bound_domains(self, certificate_id):
        return self._store.bound_domains(certificate_id)
