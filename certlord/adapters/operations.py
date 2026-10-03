"""Bounded read-only observations of current Redis work, never queue repair."""
import hashlib
import json
import math
import re
import time
from certlord.services.certificate_ids import valid_certificate_id


def operations_snapshot(redis, server_id, limit, max_retries):
    if len(redis.servers) != 1:
        raise ValueError('One authoritative Redis server required')
    connection = next(iter(redis.servers.values()))['conn']
    started = time.time()
    pending = {'create': 0, 'renew': 0, 'delete': 0, 'invalid-dns': 0, 'other': 0}
    retries = blocked = 0
    seen = set()
    for raw_key in connection.scan_iter(match='cert:*', count=100):
        key = raw_key.decode() if isinstance(raw_key, bytes) else raw_key
        if key in seen:
            continue
        seen.add(key)
        if len(seen) > limit:
            raise ValueError('Pending observation limit exceeded')
        if not valid_certificate_id(key[5:]):
            continue
        raw = connection.get(raw_key)
        if raw is None:
            continue
        records = json.loads(raw)['certs']
        for record in records.values():
            status = record.get('status')
            pending[status if status in pending else 'other'] += 1
            retry = record.get('retry', 0)
            if type(retry) is not int or retry < 0:
                raise ValueError('Invalid retry state')
            if status in ('create', 'renew', 'delete'):
                retries += retry
                blocked += int(retry >= max_retries)
    members = set()
    oldest = None
    missing = 0
    for raw_key in connection.sscan_iter(server_id, count=100):
        key = raw_key.decode() if isinstance(raw_key, bytes) else raw_key
        if key in members:
            continue
        members.add(key)
        if len(members) > limit:
            raise ValueError('Deployment observation limit exceeded')
        if not re.fullmatch(r'deploy:[0-9a-f]{64}', key):
            raise ValueError('Invalid deployment queue key')
        timestamp = connection.hget(raw_key, 'ts')
        if timestamp is None:
            missing += 1
            continue
        timestamp = float(timestamp)
        if not math.isfinite(timestamp) or timestamp <= 0:
            raise ValueError('Invalid deployment timestamp')
        oldest = timestamp if oldest is None else min(oldest, timestamp)
    lease_key = 'deployment-lock:' + hashlib.sha256(str(server_id).encode()).hexdigest()
    ttl = connection.pttl(lease_key)
    completed = time.time()
    return {'started_timestamp_seconds': started, 'completed_timestamp_seconds': completed,
            'pending_actions': pending, 'pending_retry_count': retries,
            'pending_at_retry_limit': blocked, 'deployment_entries': len(members),
            'deployment_missing_timestamps': missing,
            'deployment_oldest_age_seconds': None if oldest is None else max(0, completed-oldest),
            'deployment_lease_ttl_seconds': ttl/1000 if ttl >= 0 else None,
            'deployment_lease_state': 'held' if ttl >= 0 else ('absent' if ttl == -2 else 'unbounded')}
