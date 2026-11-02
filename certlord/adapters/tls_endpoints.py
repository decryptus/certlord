"""Configured TLS probes and short-lived Redis evidence, independent of deployment."""
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import sys

from certlord.adapters.processes import CommandInterrupted, CommandTimeout
from certlord.services.tls_endpoints import NAME, FINGERPRINT, validated_result


def host(value):
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError('TLS host must be an IP address or DNS name')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', part)
                   for part in value.split('.')):
            raise ValueError('TLS host must be an IP address or DNS name') from None
    return value.lower()


class EndpointPlan:
    def __init__(self, config):
        config = {} if config is None else config
        if not isinstance(config, dict) or set(config) - {'timeout', 'interval', 'stale_after', 'endpoints'}:
            raise ValueError('Invalid tls_monitoring configuration')
        self.timeout = config.get('timeout', 10)
        self.interval = config.get('interval', 300)
        for value, minimum, maximum in ((self.timeout, 0.1, 30), (self.interval, 10, 86400)):
            if type(value) not in (float, int) or not math.isfinite(value) or not minimum <= value <= maximum:
                raise ValueError('Invalid TLS monitoring timing bounds')
        definitions = config.get('endpoints', {})
        if not isinstance(definitions, dict) or len(definitions) > 32:
            raise ValueError('TLS monitoring accepts at most 32 named endpoints')
        self.stale_after = config.get('stale_after', self.interval + self.timeout * len(definitions) + 30)
        if (type(self.stale_after) not in (float, int) or not math.isfinite(self.stale_after)
                or not self.interval <= self.stale_after <= 604800):
            raise ValueError('Invalid TLS monitoring freshness bound')
        self.targets = {}
        for name, spec in definitions.items():
            if not isinstance(name, str) or not NAME.fullmatch(name):
                raise ValueError('Invalid TLS endpoint name')
            if not isinstance(spec, dict) or set(spec) - {'host', 'port', 'server_name', 'ca_file', 'expected_fingerprint_sha256'}:
                raise ValueError('Invalid TLS endpoint fields')
            port = spec.get('port', 443)
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError('TLS endpoint port must be between 1 and 65535')
            ca = spec.get('ca_file')
            if ca is not None and (not isinstance(ca, str) or not Path(ca).is_absolute() or not Path(ca).is_file()):
                raise ValueError('TLS CA must be an existing absolute file')
            expected = spec.get('expected_fingerprint_sha256')
            if expected is not None and (not isinstance(expected, str) or not FINGERPRINT.fullmatch(expected)):
                raise ValueError('TLS fingerprint must be 64 lowercase hexadecimal characters')
            self.targets[name] = {'host': host(spec.get('host')), 'port': port,
                'server_name': host(spec.get('server_name')), 'ca_file': ca, 'expected': expected,
                'ca_sha256': hashlib.sha256(Path(ca).read_bytes()).hexdigest() if ca else None,
                'timeout': self.timeout}


class EndpointProbe:
    def __init__(self, runner):
        self.runner = runner

    def __call__(self, target):
        try:
            # A changed trust file requires configuration reload, not stale evidence.
            if target['ca_file'] and hashlib.sha256(Path(target['ca_file']).read_bytes()).hexdigest() != target['ca_sha256']:
                return {'status': 'failed', 'error_code': 'connection_or_trust_store_failed'}
            args = [sys.executable, '-m', 'certlord.adapters.tls_probe', target['host'], str(target['port']),
                    target['server_name'], target['ca_file'] or '', target['expected'] or '', str(target['timeout'])]
            code, output, _ = self.runner.run(args, os.environ.copy())
            if code or len(output) > 4096:
                raise ValueError('Invalid probe response')
            result = validated_result(json.loads(output))
            if result['status'] == 'verified' and target['expected'] and result['observed_fingerprint_sha256'] != target['expected']:
                raise ValueError('Probe returned a different fingerprint')
            return result
        except CommandInterrupted:
            raise
        except CommandTimeout:
            return {'status': 'failed', 'error_code': 'timeout'}
        except Exception:
            return {'status': 'failed', 'error_code': 'probe_failed'}


WRITE = '''
local previous = redis.call('GET', KEYS[1])
if previous and cjson.decode(previous).started_at > tonumber(ARGV[1]) then return 0 end
redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3])
return 1
'''


class EndpointStore:
    def __init__(self, redis, server_id, retention):
        self.redis, self.retention = redis, max(3600, math.ceil(retention * 2))
        self.prefix = 'tls-observation:' + hashlib.sha256(str(server_id).encode()).hexdigest() + ':'

    def connection(self):
        if len(self.redis.servers) != 1:
            raise ValueError('One authoritative Redis server required')
        return next(iter(self.redis.servers.values()))['conn']

    def key(self, name, signature):
        return self.prefix + name + ':' + signature

    def read(self, name, signature):
        raw = self.connection().get(self.key(name, signature))
        if raw is None:
            return None
        if len(raw) > 4096:
            raise ValueError('Oversized TLS evidence')
        return json.loads(raw)

    def write(self, name, signature, record):
        return self.connection().eval(WRITE, 1, self.key(name, signature), record['started_at'],
                                      json.dumps(record), self.retention) == 1
