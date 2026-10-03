# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
"""Generation-specific deployment entries, atomic within each Redis server."""
import hashlib
from certlord.services.certificate_ids import require_certificate_id
import json
import time
from six import iteritems


def certificate_generation(certificate):
    material = [certificate.get('cert', ''), certificate.get('chain', '')]
    return hashlib.sha256(json.dumps(material, separators=(',', ':')).encode('utf-8')).hexdigest()


class DeploymentQueue(object):
    def __init__(self, redis):
        self.redis = redis

    def enqueue(self, server_id, certificate_id, domain, certificate):
        certificate_id = require_certificate_id(certificate_id)
        identity = [str(server_id), str(certificate_id), domain.lower(),
                    certificate.get('cert', ''), certificate.get('chain', '')]
        key = 'deploy:' + hashlib.sha256(json.dumps(identity, separators=(',', ':')).encode('utf-8')).hexdigest()
        payload = json.dumps({'certificate_id': str(certificate_id), 'domain': domain.lower(),
                              'generation': certificate_generation(certificate)})
        for _, server in iteritems(self.redis.servers):
            with server['conn'].pipeline(transaction=True) as pipe:
                pipe.hsetnx(key, 'ts', '%.6f' % time.time())
                pipe.hset(key, 'obj', payload)
                pipe.sadd(server_id, key)
                pipe.execute()
        return key

    def acknowledge(self, server_id, key):
        for _, server in iteritems(self.redis.servers):
            with server['conn'].pipeline(transaction=True) as pipe:
                pipe.srem(server_id, key)
                pipe.delete(key)
                pipe.execute()
