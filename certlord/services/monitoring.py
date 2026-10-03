# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
"""Optional monitoring integration; failures are reported without aborting certificates."""
import logging
from six import iteritems
LOG = logging.getLogger(__name__)

class CertificateMonitoring(object):
    def __init__(self, checkers):
        self.checkers = dict(checkers)
        self._ready = set()

    def _prepare(self, name, checker):
        if name not in self._ready:
            checker.connect()
            # Discover existing controls before allowing create/delete after restart.
            checker.list(True, True)
            self._ready.add(name)

    def create_ssl_check(self, domain, collector = True, exists = True):
        for name, checker in iteritems(self.checkers):
            try:
                self._prepare(name, checker)
                result = checker.create(domain, collector, exists)
                if result is False:
                    # An uncertain write must be reconciled by listing before reuse.
                    self._ready.discard(name)
                elif result:
                    LOG.info("created ssl check for domain %r on %r",
                             domain,
                             name)
            except Exception:
                self._ready.discard(name)
                LOG.error("unable to create ssl check for domain %r on %r",
                          domain,
                          name)


    def delete_ssl_check(self, domain, unset = True):
        for name, checker in iteritems(self.checkers):
            try:
                self._prepare(name, checker)
                key = domain if domain.startswith('https://') else 'https://' + domain
                if not checker.collector.get(key):
                    LOG.warning("unable to find domain %r in %r collector's",
                                domain,
                                name)
                    continue

                result = checker.delete(checker.collector[key], unset)
                if result is False:
                    self._ready.discard(name)
                elif result:
                    LOG.info("deleted ssl check for domain %r on %r",
                             domain,
                             name)
            except Exception:
                self._ready.discard(name)
                LOG.error("unable to delete ssl check for domain %r on %r",
                          domain,
                          name)


    def fetch_ssl_checks(self, xset = True, xraise = False):
        for name, checker in iteritems(self.checkers):
            try:
                checker.connect()
                checker.list(xset, True)
                if xset:
                    self._ready.add(name)
            except Exception:
                self._ready.discard(name)
                LOG.error("unable to fetch all ssl checks on %r",
                          name)

