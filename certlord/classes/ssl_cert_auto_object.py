# -*- coding: utf-8 -*-
# Copyright (C) 2019-2022 fjord-technologies
# SPDX-License-Identifier: GPL-3.0-or-later
"""certlord.classes.ssl_cert_auto_object"""

import json
from certlord.services.certificate_ids import require_certificate_id

from datetime import datetime

from certlord.classes.config import STATUS_CREATE


class SslCertAutoObject(object): # pylint: disable-msg=useless-object-inheritance
    def __init__(self, certificate_id, obj = None, date = None):
        if not obj:
            obj = {}

        if not date:
            date = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        self._certificate_id = require_certificate_id(certificate_id)
        self._date    = date
        self._obj     = obj

    def has_certs(self):
        return len(self._obj) > 0

    def init_dom(self, domain, status = STATUS_CREATE):
        self._obj[domain] = {'last_retry': None,
                             'retry':      0,
                             'status':     status}

    def add_dom(self, domain, status = STATUS_CREATE):
        if domain not in self._obj:
            self.init_dom(domain, status)

    def set_dom_status(self, domain, status):
        self.add_dom(domain, status)
        self._obj[domain]['status'] = status

    def get_dom_status(self, domain):
        if domain in self._obj:
            return self._obj[domain]['status']

        return None

    def get_certificate_id(self):
        return self._certificate_id

    def get_date(self):
        return self._date

    def get_obj(self):
        return self._obj

    def rem_dom(self, domain):
        self._obj.pop(domain, None)

    def incr_retry(self, domain):
        self.add_dom(domain)

        if 'retry' not in self._obj[domain]:
            self._obj[domain]['retry'] = 0

        if 'last_retry' not in self._obj[domain]:
            self._obj[domain]['last_retry'] = None

        self._obj[domain]['retry']      += 1
        self._obj[domain]['last_retry']  = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    def dumps(self, date = None):
        if not date:
            self._date = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        return json.dumps({'certs':   self._obj,
                           'date':    self._date,
                           'certificate_id': self._certificate_id})

