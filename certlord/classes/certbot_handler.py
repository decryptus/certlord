# -*- coding: utf-8 -*-
# Copyright (C) 2019-2022 fjord-technologies
# SPDX-License-Identifier: GPL-3.0-or-later
"""certlord.classes.redis_handler"""

import logging
import threading

from certlord.services.cycle_progress import run_cycle
import time

from datetime import datetime

from certlord.ports.certificates import StorageNotFound
import six

from certlord.adapters.issuance_command import issuance_command
from certlord.adapters.processes import CommandRunner, CommandInterrupted
from certlord.classes.config import (DEFAULT_COMMAND_TIMEOUT, DEFAULT_PROCESS_STOP_GRACE,
CERT_KEY_PREFIX,
                                       DEFAULT_CERTBOT_CHECK_INTERVAL,
                                       DEFAULT_DELAY_RESET_RETRIES,
                                       DEFAULT_PROCESSING_DELAY,
                                       DEFAULT_MAX_RETRIES,
                                       STATUS_CREATE,
                                       STATUS_RENEW,
                                       STATUS_DELETE)

LOG = logging.getLogger('certlord.classes.certbot_handler')


class SslCertsCertbotHandler(threading.Thread):
    def __init__(self, module, redis):
        threading.Thread.__init__(self)

        self.name = 'certlord-certbot_handler'
        self._module             = module
        self._modconf            = module.modconf
        self._redis              = redis
        self._cmd                = module.certbot_cmd()
        self._proc               = None

        self._stop_event = threading.Event()
        self._runner = CommandRunner(self._stop_event,
            float(self._modconf.get('command_timeout', DEFAULT_COMMAND_TIMEOUT)),
            float(self._modconf.get('process_stop_grace', DEFAULT_PROCESS_STOP_GRACE)))

        self.killed              = False
        self.check_interval      = self._modconf.get('certbot_check_interval') or DEFAULT_CERTBOT_CHECK_INTERVAL
        self.processing_delay    = self._modconf.get('processing_delay') or DEFAULT_PROCESSING_DELAY
        self.max_retries         = self._modconf.get('max_retries') or DEFAULT_MAX_RETRIES
        self.delay_reset_retries = self._modconf.get('delay_reset_retries') or DEFAULT_DELAY_RESET_RETRIES

    def _create_certs(self, doms, acerts, renew = False):
        if not renew:
            status = STATUS_CREATE
        else:
            status = STATUS_RENEW

        for dom in doms[status]:
            if self.killed:
                break
            args   = self._cmd['args'] + ['-d', dom]

            try:
                LOG.debug("Starting certificate issuance command")
                attempt = self._module.service.begin_issuance(dom)
                with issuance_command(dict(self._cmd, args=args), attempt) as (bound_args, bound_env):
                    code, _, _ = self._runner.run(bound_args, bound_env)
            except CommandInterrupted:
                break
            except Exception:
                acerts.incr_retry(dom)
                LOG.error('Certificate issuance command failed; retry retained')
            else:
                if code == 0:
                    LOG.info("Certificate issuance command exited with code 0")
                    acerts.rem_dom(dom)
                else:
                    LOG.error("Certificate issuance command exited with code %d; retry retained", code)
                    acerts.incr_retry(dom)

        self._module.save_acerts(acerts, utc_date = acerts.get_date())

    def _renew_certs(self, doms, acerts):
        self._create_certs(doms, acerts, renew = True)

    def _delete_certs(self, doms, acerts):
        for dom in doms[STATUS_DELETE]:
            if self.killed:
                break
            try:
                self._module.delete_certificate(doms['certificate_id'], dom)
            except StorageNotFound:
                acerts.rem_dom(dom)
            except Exception:
                acerts.incr_retry(dom)
                LOG.error('Certificate removal failed; retry retained')
            else:
                acerts.rem_dom(dom)

        self._module.save_acerts(acerts, utc_date = acerts.get_date())

    def _run(self):
        for x in self._redis.keys("%s*" % CERT_KEY_PREFIX)['ssl_certs']:
            if self.killed:
                break
            acerts = self._module.fetch_acerts(key = x)
            if not acerts.get_certificate_id() or not acerts.has_certs():
                self._redis.del_key(x)
                continue

            certificate_id = acerts.get_certificate_id()
            curdate = datetime.utcnow()
            reqdate = datetime.strptime(acerts.get_date(), "%Y-%m-%d %H:%M:%S")

            if (curdate - reqdate).total_seconds() < self.processing_delay:
                if int(time.time()) % 2:
                    LOG.debug("processing delay not reached. (certificate_id: %s)", certificate_id)
                continue

            if not self._module.CERTIFICATES_LOCK.try_acquire(certificate_id):
                LOG.warning("operation already in progress. (certificate_id: %s)", certificate_id)
                continue

            doms = {STATUS_CREATE: [],
                    STATUS_DELETE: [],
                    STATUS_RENEW:  [],
                    'certificate_id':     certificate_id}

            try:
                for sdomain, sdinfo in six.iteritems(acerts.get_obj()):
                    if sdinfo.get('last_retry'):
                        retrydate = datetime.strptime(sdinfo['last_retry'], "%Y-%m-%d %H:%M:%S")
                        if (curdate - retrydate).total_seconds() >= self.delay_reset_retries:
                            if sdinfo.get('retry'):
                                LOG.info("resetting retries. (domain: %s, certificate_id: %s)", sdomain, certificate_id)
                            sdinfo['retry'] = 0

                    if 'retry' in sdinfo and sdinfo['retry'] >= self.max_retries:
                        if int(time.time()) % 2:
                            LOG.warning("max retries exceeded. (domain: %s, certificate_id: %s)", sdomain, certificate_id)
                        continue

                    if sdinfo['status'] in (STATUS_CREATE, STATUS_DELETE, STATUS_RENEW):
                        doms[sdinfo['status']].append(sdomain)

                self._create_certs(doms, acerts)
                self._renew_certs(doms, acerts)
                self._delete_certs(doms, acerts)
            except Exception:
                LOG.error('Certificate pending operation failed')
            finally:
                self._module.CERTIFICATES_LOCK.release(certificate_id)

    def run(self):
        while not self.killed:
            try:
                run_cycle(self)
            except Exception:
                LOG.error('Issuance cycle failed')
            self._stop_event.wait(self.check_interval)

    def terminate(self):
        self.killed = True
        self._runner.stop()
