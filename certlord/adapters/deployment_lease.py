# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exclusive bounded deployment lease on one authoritative Redis server."""
import hashlib
import math
from uuid import uuid4

from certlord.classes.exceptions import CertLordConfigError

OWNED = "return redis.call('GET', KEYS[1]) == ARGV[1] and 1 or 0"
RENEW = "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('PEXPIRE', KEYS[1], ARGV[2]) end return 0"
RELEASE = "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end return 0"
ACK = """if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
redis.call('SREM', KEYS[2], KEYS[3])
redis.call('DEL', KEYS[3])
return 1"""


class LeaseLost(Exception):
    pass


class DeploymentLease(object):
    def __init__(self, redis, server_id, timeout):
        if len(redis.servers) != 1:
            raise CertLordConfigError('Deployment coordination requires one authoritative Redis server')
        if not math.isfinite(timeout) or timeout <= 0:
            raise CertLordConfigError('Deployment lease duration must be finite and positive')
        self.conn = next(iter(redis.servers.values()))['conn']
        self.key = 'deployment-lock:' + hashlib.sha256(str(server_id).encode('utf-8')).hexdigest()
        self.timeout_ms = int(math.ceil(timeout * 1000))
        self.token = None

    def acquire(self):
        token = str(uuid4())
        if self.conn.set(self.key, token, nx=True, px=self.timeout_ms):
            self.token = token
            return True
        return False

    def renew(self):
        return bool(self.token and self.conn.eval(RENEW, 1, self.key, self.token, self.timeout_ms))

    def release(self):
        if self.token:
            return bool(self.conn.eval(RELEASE, 1, self.key, self.token))
        return False

    def acknowledge(self, server_id, key):
        if not self.token or not self.conn.eval(ACK, 3, self.key, server_id, key, self.token):
            raise LeaseLost('Deployment lease lost; pending work retained')
