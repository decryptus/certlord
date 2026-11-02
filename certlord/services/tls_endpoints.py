"""Independent TLS observations; no issuance, deployment or certificate storage."""
import hashlib
import json
import math
import re
import time

ERRORS = frozenset(('fingerprint_mismatch', 'tls_validation_failed', 'timeout',
    'tls_handshake_failed', 'connection_or_trust_store_failed', 'probe_failed'))
NAME = re.compile(r'[a-z][a-z0-9_-]{0,63}')
FINGERPRINT = re.compile(r'[0-9a-f]{64}')


def digest(target):
    return hashlib.sha256(json.dumps(target, sort_keys=True).encode()).hexdigest()


def validated_result(result):
    if not isinstance(result, dict) or result.get('status') not in ('verified', 'failed'):
        raise ValueError('Invalid TLS observation')
    error = result.get('error_code')
    fingerprint = result.get('observed_fingerprint_sha256')
    if fingerprint is not None and (not isinstance(fingerprint, str) or not FINGERPRINT.fullmatch(fingerprint)):
        raise ValueError('Invalid TLS fingerprint')
    if result['status'] == 'verified' and (error is not None or fingerprint is None):
        raise ValueError('Missing TLS verification evidence')
    if result['status'] == 'failed' and error not in ERRORS:
        raise ValueError('Invalid TLS error')
    return {'status': result['status'], 'error_code': error,
            'observed_fingerprint_sha256': fingerprint}


class EndpointObservations:
    def __init__(self, targets, store, probe, stale_after, clock=time.time):
        self.targets, self.store, self.probe = targets, store, probe
        self.stale_after, self.clock = stale_after, clock

    def check(self, stopped=lambda: False):
        for name, target in self.targets.items():
            if stopped():
                return
            started = self.clock()
            result = validated_result(self.probe(target))
            if stopped():
                return  # Interrupted checks never replace prior evidence.
            record = dict(result, started_at=started, checked_at=self.clock())
            self.store.write(name, digest(target), record)

    def snapshot(self):
        now = self.clock()
        records = []
        for name, target in self.targets.items():
            record = self.store.read(name, digest(target))
            result = {'name': name, 'connect_host': target['host'], 'port': target['port'],
                'server_name': target['server_name'], 'expected_fingerprint_sha256': target['expected'],
                'status': 'unknown', 'last_status': None, 'error_code': None,
                'observed_fingerprint_sha256': None, 'checked_at': None, 'fresh': False}
            if record is not None:
                value = validated_result(record)
                checked = record['checked_at']
                if type(checked) not in (int, float) or not math.isfinite(checked) or checked < 0:
                    raise ValueError('Invalid TLS observation timestamp')
                fresh = 0 <= now - checked <= self.stale_after
                # Even a well-formed stored result must match the configured pin.
                if value['status'] == 'verified' and target['expected'] and value['observed_fingerprint_sha256'] != target['expected']:
                    raise ValueError('TLS evidence does not match configured fingerprint')
                result.update(value, checked_at=checked, last_status=value['status'], fresh=fresh)
                if not fresh:
                    result['status'] = 'stale'
            records.append(result)
        verified = sum(r['status'] == 'verified' for r in records)
        status = ('disabled' if not records else 'verified' if verified == len(records) else
                  'partial' if verified else 'failed' if any(r['status'] == 'failed' for r in records) else 'unknown')
        return {'status': status, 'verified': verified, 'total': len(records),
                'observed_at': now, 'stale_after': self.stale_after, 'endpoints': records}


def endpoint_metrics(snapshot):
    lines = ['# HELP certlord_tls_endpoint_verified Fresh successful independent TLS check.',
             '# TYPE certlord_tls_endpoint_verified gauge',
             '# HELP certlord_tls_endpoint_fresh Whether independent TLS evidence is current.',
             '# TYPE certlord_tls_endpoint_fresh gauge',
             '# HELP certlord_tls_endpoint_checked_timestamp_seconds Last completed check.',
             '# TYPE certlord_tls_endpoint_checked_timestamp_seconds gauge']
    for row in snapshot['endpoints']:
        label = '{endpoint=' + json.dumps(row['name']) + '}'
        lines.extend(['certlord_tls_endpoint_verified%s %d' % (label, row['status'] == 'verified'),
                      'certlord_tls_endpoint_fresh%s %d' % (label, row['fresh']),
                      'certlord_tls_endpoint_checked_timestamp_seconds%s %s' % (label, row['checked_at'] or 0)])
    return '\n'.join(lines) + '\n'
