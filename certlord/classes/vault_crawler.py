# -*- coding: utf-8 -*-
# Copyright (C) 2019-2022 fjord-technologies
# SPDX-License-Identifier: GPL-3.0-or-later
"""certlord.classes.vault_crawler"""

import json
import logging
import threading

from certlord.services.cycle_progress import run_cycle

from datetime import datetime, timedelta
from OpenSSL import crypto

from certlord.ports.certificates import StorageNotFound
from certlord.adapters.deployment_queue import DeploymentQueue
import six

from certlord.classes.config import (DEFAULT_VAULT_CHECK_INTERVAL,
                                       DEFAULT_VAULT_BUSY_RETRY_INTERVAL,
                                       DEFAULT_RENEW_BEFORE_EXPIRY,
                                       CERT_VENDORS_AUTO,
                                       STATUS_CREATE,
                                       STATUS_DELETE,
                                       STATUS_EXISTS,
                                       STATUS_INVALID_DNS,
                                       STATUS_GENERATED,
                                       STATUS_DEPLOYED,
                                       STATUS_RENEW)

LOG = logging.getLogger('certlord.classes.vault_crawler')


class SslCertsVaultCrawler(threading.Thread):
    def __init__(self, module, redis, key_name):
        threading.Thread.__init__(self)

        self.name = 'certlord-crawler'
        self._module             = module
        self._modconf            = module.modconf
        self._redis              = redis
        self._queue = DeploymentQueue(redis)
        self.key_name            = key_name
        self._server_id          = module.config['general']['server_id']

        self._retry_busy = False
        self.killed              = False
        self.check_interval      = (self._modconf.get('vault_check_interval')
                                    or DEFAULT_VAULT_CHECK_INTERVAL)
        self.renew_before_expiry = self._modconf.get('renew_before_expiry') or DEFAULT_RENEW_BEFORE_EXPIRY

    def _set_to_deploy(self, certificate_id, domain, certificate):
        self._queue.enqueue(self._server_id, certificate_id, domain, certificate)
        return True

    def _run(self):
        self._retry_busy = False
        to_deploy = False
        if self.killed:
            return
        self._module.fetch_ssl_checks()

        for certificate_id in self._module.get_certificate_ids():
            if self.killed:
                break
            if not self._module.CERTIFICATES_LOCK.try_acquire(certificate_id):
                self._retry_busy = True
                LOG.warning("operation already in progress. (certificate_id: %s)", certificate_id)
                continue

            try:
                acerts = self._module.fetch_acerts(certificate_id)
                utc_date = acerts.get_date()

                for domain in self._module.list_certificates(certificate_id):
                    if self.killed:
                        break
                    cert = self._module.get_certificate(certificate_id, domain)
                    rstatus = STATUS_CREATE

                    acerts.add_dom(domain)

                    LOG.info("check certificate %s for certificate_id %s. (status: %r)",
                             domain,
                             certificate_id,
                             cert.get('status'))

                    # A requested removal remains authoritative until the worker completes it.
                    if (cert.get('status') == STATUS_DELETE
                            or acerts.get_dom_status(domain) == STATUS_DELETE):
                        rstatus = STATUS_DELETE
                        acerts.set_dom_status(domain, STATUS_DELETE)

                        if cert.get('vendor') not in CERT_VENDORS_AUTO:
                            try:
                                self._module.delete_certificate(certificate_id, domain)
                            except StorageNotFound:
                                acerts.rem_dom(domain)
                            except Exception:
                                LOG.error('Certificate removal failed; pending work retained')
                            else:
                                acerts.rem_dom(domain)
                        continue

                    self._module.change_certificate_id(domain, certificate_id, True)

                    if acerts.get_dom_status(domain) == STATUS_EXISTS \
                       and cert.get('status') == STATUS_CREATE \
                       and not (cert.get('cert') and cert.get('key')):
                        acerts.rem_dom(domain)
                        continue

                    if cert.get('cert') and cert.get('key'):
                        acerts.set_dom_status(domain, STATUS_EXISTS)

                        if cert.get('status') in (STATUS_GENERATED, "", None):
                            to_deploy = self._set_to_deploy(certificate_id, domain, cert)
                            acerts.rem_dom(domain)
                            continue

                        if cert.get('status') == STATUS_DEPLOYED:
                            self._module.create_ssl_check(domain)

                        if cert.get('vendor') not in CERT_VENDORS_AUTO:
                            acerts.rem_dom(domain)
                            continue

                        x509   = crypto.load_certificate(crypto.FILETYPE_PEM, cert['cert'])
                        expiry = datetime.strptime(six.ensure_str(x509.get_notAfter()), '%Y%m%d%H%M%SZ')

                        if (expiry - timedelta(days = self.renew_before_expiry)) <= datetime.utcnow():
                            rstatus = STATUS_RENEW
                            acerts.set_dom_status(domain, STATUS_RENEW)
                        else:
                            acerts.rem_dom(domain)
                            continue

                    try:
                        if not self._module.check_dns_resolv(domain):
                            raise ValueError("invalid DNS resolution for domain: %s" % domain)

                        if not self._module.check_caa_records(domain):
                            raise ValueError("invalid CAA DNS records for domain: %s" % domain)
                    except Exception:
                        rstatus = STATUS_INVALID_DNS
                        acerts.set_dom_status(domain, STATUS_INVALID_DNS)
                        LOG.error('Certificate DNS policy check failed')
                    else:
                        if acerts.get_dom_status(domain) == STATUS_INVALID_DNS:
                            acerts.set_dom_status(domain, rstatus)

                    try:
                        self._module.update_certificate(certificate_id, domain, {'status': rstatus})
                    except Exception:
                        LOG.error('Certificate status update failed')

                self._module.save_acerts(acerts, utc_date = utc_date)
            except Exception:
                LOG.error('Certificate crawl failed; pending work retained')
            finally:
                self._module.CERTIFICATES_LOCK.release(certificate_id)

        if to_deploy:
            self._module.evt_deployer.set()
            to_deploy = False

    def run(self):
        try:
            run_cycle(self)
        except Exception:
            LOG.error('Crawler cycle failed')

        while not self.killed:
            if not self._module.evt_tcrawler.is_set():
                timeout = (min(self.check_interval, DEFAULT_VAULT_BUSY_RETRY_INTERVAL)
                           if self._retry_busy else self.check_interval)
                self._module.evt_tcrawler.wait(timeout)
            else:
                self._module.evt_tcrawler.clear()

            if self.killed:
                return

            try:
                run_cycle(self)
            except Exception:
                LOG.error('Crawler cycle failed')

    def terminate(self):
        self.killed = True
        self._module.evt_tcrawler.set()

