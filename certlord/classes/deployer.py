# -*- coding: utf-8 -*-
# Copyright (C) 2019-2022 fjord-technologies
# SPDX-License-Identifier: GPL-3.0-or-later
"""certlord.classes.deployer"""

from uuid import uuid4
from certlord.adapters.auton_receipt import run_receipted
from certlord.services.operation_tracking import emit, record_id
import json
import logging
import threading

from certlord.services.cycle_progress import run_cycle

import six

from certlord.adapters.processes import CommandRunner, CommandInterrupted
from certlord.adapters.tls_verification import TlsVerifier
from certlord.adapters.deployment_queue import DeploymentQueue, certificate_generation
from certlord.adapters.deployment_lease import DeploymentLease, LeaseLost
from certlord.ports.certificates import StorageConflict, StorageError, StorageNotFound
from certlord.classes.config import (DEFAULT_COMMAND_TIMEOUT, DEFAULT_PROCESS_STOP_GRACE,
                                    DEFAULT_DEPLOYER_CHECK_INTERVAL, DEFAULT_DEPLOY_LEASE_MARGIN,
                                    DEPLOY_SEARCH_FORMAT, STATUS_DEPLOYED, STATUS_GENERATED)

LOG = logging.getLogger('certlord.classes.deployer')

class SslCertsDeployer(threading.Thread):
    def __init__(self, module, redis):
        threading.Thread.__init__(self)

        self.name = 'certlord-deployer'
        self._module        = module
        self._modconf       = module.modconf
        self._redis         = redis
        self._queue = DeploymentQueue(redis)
        self._cmd           = module.auton_cmd()
        self._server_id     = module.config['general']['server_id']
        self._proc          = None

        self._stop_event = threading.Event()
        self._runner = CommandRunner(self._stop_event,
            float(self._modconf.get('command_timeout', DEFAULT_COMMAND_TIMEOUT)),
            float(self._modconf.get('process_stop_grace', DEFAULT_PROCESS_STOP_GRACE)))

        self._verifier = TlsVerifier(self._modconf.get('tls_verification'), self._stop_event, self._runner.grace)
        self._lease = DeploymentLease(redis, self._server_id,
            max(self._runner.timeout, self._verifier.runner.timeout if self._verifier.targets else 0) + 3 * self._runner.grace + DEFAULT_DEPLOY_LEASE_MARGIN)
        self.killed         = False
        self.check_interval = self._modconf.get('deployer_check_interval') or DEFAULT_DEPLOYER_CHECK_INTERVAL

    def _run(self, on_start = False):
        if self.killed or not self._lease.acquire():
            return
        # An uncertain command outcome retains the lease until its TTL expires.
        # It may have submitted a remote job which survives the local CLI.
        release = True
        try:
            deployed = {}
            for keys in six.itervalues(self._redis.sort(self._server_id, by=DEPLOY_SEARCH_FORMAT)):
                for key in keys:
                    raw = self._redis.hget_key(key, 'obj')
                    if not raw:
                        continue
                    obj = json.loads(raw)
                    try:
                        snapshot = self._module.certificate_snapshot(obj['certificate_id'], obj['domain'])
                    except StorageNotFound:
                        # A removed certificate cannot be deployed. Storage outages
                        # remain errors; only a confirmed missing record is cleaned.
                        self._lease.acknowledge(self._server_id, key)
                        continue
                    data, version = snapshot
                    if not self._lease.renew():
                        raise LeaseLost('Deployment lease expired during discovery')
                    generation = obj.get('generation')
                    if generation and generation != certificate_generation(data):
                        if data.get('status') in (STATUS_GENERATED, '', None) and data.get('cert') and data.get('key'):
                            self._queue.enqueue(self._server_id, obj['certificate_id'], obj['domain'], data)
                        self._lease.acknowledge(self._server_id, key)
                        continue
                    if data.get('status') not in (STATUS_GENERATED, '', None):
                        self._lease.acknowledge(self._server_id, key)
                        continue
                    if not data.get('cert') or not data.get('key'):
                        raise StorageError('Cannot deploy incomplete certificate material')
                    deployed[key] = (obj, snapshot)
            if not deployed or self.killed:
                return
            if not self._lease.renew():
                raise LeaseLost('Deployment lease expired before command launch')
            release = False
            attempt_id = str(uuid4())
            def progress(event):
                for obj, snapshot in deployed.values():
                    emit(event, record_id(snapshot[0]), obj['certificate_id'], attempt_id)
            progress('deployment_command_started')
            receipt = None
            def received(value):
                for obj, snapshot in deployed.values():
                    emit('auton_job_observed', record_id(snapshot[0]), obj['certificate_id'], attempt_id,
                         remote_job=value['uid'])
            try:
                if self._cmd.get('receipt_target'):
                    code, receipt = run_receipted(self._runner, self._cmd, attempt_id, received)
                else:
                    code, stdout, stderr = self._runner.run(self._cmd['args'], self._cmd['env'])
            except Exception:
                progress('deployment_command_uncertain')
                LOG.error('Deployment command failed; work retained until lease expiry')
                return
            if code != 0 or self.killed:
                progress('deployment_command_unacknowledged')
                return
            progress('deployment_command_returned')
            release = True
            for key, (obj, snapshot) in six.iteritems(deployed):
                if self.killed:
                    break
                if not self._lease.renew():
                    raise LeaseLost('Deployment lease lost after command completion')
                try:
                    if self._verifier.configured(obj['certificate_id']):
                        try:
                            verification = self._verifier.verify(obj['certificate_id'], obj['domain'], snapshot[0])
                        except CommandInterrupted:
                            return
                        if self.killed:
                            return
                        if not self._lease.renew():
                            raise LeaseLost('Deployment lease lost during TLS verification')
                        if verification['status'] != 'verified':
                            self._module.record_verification(obj['certificate_id'], obj['domain'], snapshot, verification)
                            LOG.warning('TLS verification failed; deployment remains pending (%s)', verification['error_code'])
                            continue
                        if receipt is None:
                            self._module.mark_deployed(obj['certificate_id'], obj['domain'], snapshot, verification)
                        else:
                            self._module.mark_deployed(obj['certificate_id'], obj['domain'], snapshot, verification, receipt=receipt)
                    else:
                        if receipt is None:
                            self._module.mark_deployed(obj['certificate_id'], obj['domain'], snapshot)
                        else:
                            self._module.mark_deployed(obj['certificate_id'], obj['domain'], snapshot, receipt=receipt)
                except StorageConflict:
                    LOG.warning('Certificate changed during deployment; operation retained')
                    continue
                self._lease.acknowledge(self._server_id, key)
                emit('deployment_acknowledged', record_id(snapshot[0]), obj['certificate_id'], attempt_id)
                self._module.create_ssl_check(obj['domain'])
        finally:
            if release:
                self._lease.release()

    def run(self):
        try:
            if not self.killed:
                run_cycle(self, True)
        except Exception:
            LOG.error('Deployment cycle failed')

        while not self.killed:
            if not self._module.evt_deployer.is_set():
                self._module.evt_deployer.wait(self.check_interval)
            else:
                self._module.evt_deployer.clear()

            if self.killed:
                return

            try:
                run_cycle(self)
            except Exception:
                LOG.error('Deployment cycle failed')

    def terminate(self):
        self.killed = True
        self._runner.stop()
        self._module.evt_deployer.set()
