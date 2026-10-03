# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
"""Redis pending certificates and reverse-certificate_id index."""
import json
from certlord.adapters.operations import operations_snapshot
from certlord.services.certificate_ids import require_certificate_id
from datetime import datetime
from sonicprobe.libs.moresynchro import ListLock
from certlord.classes.config import CERT_KEY_PREFIX, DOMAIN_KEY_PREFIX
from certlord.classes.ssl_cert_auto_object import SslCertAutoObject

# One-certificate_id mutation preserves concurrent associations without replacing their list.
CHANGE_CERTIFICATE_ID = """local raw = redis.call('GET', KEYS[1])
local record = raw and cjson.decode(raw) or {certificate_ids={}}
local certificate_ids = {}
local seen = {}
for _, certificate_id in ipairs(record.certificate_ids) do
    certificate_id = tostring(certificate_id)
    if certificate_id ~= ARGV[1] and not seen[certificate_id] then
        table.insert(certificate_ids, certificate_id)
        seen[certificate_id] = true
    end
end
if ARGV[2] == '1' then table.insert(certificate_ids, ARGV[1]) end
local encoded = #certificate_ids == 0 and '[]' or cjson.encode(certificate_ids)
local result = '{"certificate_ids":' .. encoded .. ',"date":' .. cjson.encode(ARGV[3]) ..
    ',"domain":' .. cjson.encode(ARGV[4]) .. '}'
redis.call('SET', KEYS[1], result)
return result"""


class PendingCertificates(object):
    def __init__(self, redis):
        self._redis = redis
        self.DOMAIN_LOCK = ListLock()

    def operations(self, server_id, limit, max_retries):
        return operations_snapshot(self._redis, server_id, limit, max_retries)

    def fetch_acerts(self, certificate_id = None, key = None):
        if certificate_id is not None:
            certificate_id = require_certificate_id(certificate_id)
            key = "%s%s" % (CERT_KEY_PREFIX, certificate_id)

        if not key:
            raise ValueError("unable to fetch certificates.")

        rs = self._redis.get_key(key)
        if rs:
            rs = json.loads(rs)

        if not rs:
            rs = {}

        return SslCertAutoObject(certificate_id or rs['certificate_id'], rs.get('certs'), rs.get('date'))


    def save_acerts(self, obj, utc_date = None):
        self._redis.set_key("%s%s" % (CERT_KEY_PREFIX, obj.get_certificate_id()),
                            obj.dumps(utc_date))


    def get_certificate_ids_for_domain(self, domain):
        r = self._redis.get_key("%s%s" % (DOMAIN_KEY_PREFIX, domain))
        if r:
            return json.loads(r)

        return {'certificate_ids': [], 'date': None, 'domain': domain}


    def change_certificate_id(self, domain, certificate_id, present):
        certificate_id = require_certificate_id(certificate_id)
        if len(self._redis.servers) != 1:
            raise RuntimeError('Reverse-certificate_id coordination requires one Redis server')
        connection = next(iter(self._redis.servers.values()))['conn']
        result = connection.eval(CHANGE_CERTIFICATE_ID, 1, DOMAIN_KEY_PREFIX + domain,
                                 str(certificate_id), '1' if present else '0',
                                 datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), domain)
        return json.loads(result)

    def set_certificate_ids_for_domain(self, domain, certificate_ids, utc_date = None):
        certificate_ids = [require_certificate_id(value) for value in certificate_ids]
        # Explicit whole-index replacement for controlled maintenance/fixtures.
        # Runtime lifecycle mutations must use change_certificate_id instead.
        if not self.DOMAIN_LOCK.try_acquire(domain):
            raise RuntimeError("Reverse-certificate_id index is busy")

        if not utc_date:
            utc_date = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        try:
            self._redis.set_key("%s%s" % (DOMAIN_KEY_PREFIX, domain),
                                json.dumps({'certificate_ids':  certificate_ids,
                                         'date':   utc_date,
                                         'domain': domain}))
        finally:
            self.DOMAIN_LOCK.release(domain)


