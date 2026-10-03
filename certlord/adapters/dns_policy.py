# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
"""DNS authorization policy, independent of HTTP and certificate storage."""
import math
import re
import time

import dns.exception
import dns.resolver
from six import iteritems
from certlord.classes.exceptions import CertLordConfigError
from certlord.classes.config import ALLOWED_DNS_RTYPE, DNS_RTYPE_CAA, DEFAULT_DNS_TIMEOUT
DNS_RDATA_CAA_MATCH = re.compile(r'^\s*[0-9]+\s*issue\s*"(.+)"$', re.I).match

class DnsPolicy(object):
    def __init__(self, modconf, resolver=None):
        self.modconf = modconf
        try:
            self.timeout = float(modconf.get('dns_timeout', DEFAULT_DNS_TIMEOUT))
        except (TypeError, ValueError):
            raise CertLordConfigError('DNS timeout must be finite and positive')
        if isinstance(modconf.get('dns_timeout'), bool) or not math.isfinite(self.timeout) or self.timeout <= 0:
            raise CertLordConfigError('DNS timeout must be finite and positive')
        self.resolver = resolver if resolver is not None else dns.resolver.Resolver()
        self._allow_dns_resolv = {}
        self._expected_caa_rec = set()
        self._load_allow_dns_resolv()
        self._load_expected_caa_records()

    def _load_allow_dns_resolv(self):
        if not self.modconf.get('allow_dns_resolv'):
            return

        for rtype, rregex in iteritems(self.modconf['allow_dns_resolv']):
            if rtype not in ALLOWED_DNS_RTYPE:
                raise CertLordConfigError("invalid allow_dns_resolv type: %s" % rtype)

            if rtype not in self._allow_dns_resolv:
                self._allow_dns_resolv[rtype] = []

            for r in rregex:
                self._allow_dns_resolv[rtype].append(re.compile(r).match)

            if not self._allow_dns_resolv[rtype]:
                del self._allow_dns_resolv[rtype]


    def _load_expected_caa_records(self):
        if not self.modconf.get('expected_caa_records'):
            return

        for caa_entry in self.modconf['expected_caa_records']:
            if caa_entry is None:
                self._expected_caa_rec.add(None)
            else:
                self._expected_caa_rec.add(re.compile(caa_entry, re.I).match)


    def _query(self, rname, rtype, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise dns.exception.Timeout()
        return self.resolver.query(rname, rtype, lifetime=remaining)

    def check_dns_resolv(self, rname):
        if not self._allow_dns_resolv:
            return True

        deadline = time.monotonic() + self.timeout
        for rtype, rregex in iteritems(self._allow_dns_resolv):
            try:
                answers = self._query(rname, rtype, deadline)
            except (dns.resolver.NoAnswer,
                    dns.resolver.NXDOMAIN):
                continue

            for rdata in answers:
                txt = rdata.to_text().rstrip('.')
                for r in rregex:
                    if r(txt):
                        return True

        return False


    def check_caa_records(self, rname):
        if not self._expected_caa_rec:
            return True

        rname_splitted = rname.split('.')
        answers        = None
        sdom           = rname

        deadline = time.monotonic() + self.timeout
        for i in range(0, len(rname_splitted)):
            sdom = '.'.join(rname_splitted[i:])

            try:
                answers = self._query(sdom, DNS_RTYPE_CAA, deadline)
            except (dns.resolver.NoAnswer,
                    dns.resolver.NXDOMAIN):
                continue
            else:
                break

        if not answers:
            return None in self._expected_caa_rec

        for rregex in self._expected_caa_rec:
            if rregex is None:
                continue

            for rdata in answers:
                m = DNS_RDATA_CAA_MATCH(rdata.to_text())
                if m and rregex(m.group(1)):
                    return True

        return False


