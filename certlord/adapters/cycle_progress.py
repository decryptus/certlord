"""Bounded cycle evidence in Redis; never a work queue or an execution lease."""
import hashlib
import json
import math
import uuid

WORKERS = ('certlord-certbot_handler', 'certlord-crawler', 'certlord-deployer')

START = """
local old = redis.call('HGET', KEYS[1], 'current')
if old and cjson.decode(old).instance_id ~= ARGV[1] then
    redis.call('HSET', KEYS[1], 'previous_instance', old)
end
redis.call('HSET', KEYS[1], 'current', ARGV[2])
return 1
"""
FINISH = """
local old = redis.call('HGET', KEYS[1], 'current')
if not old or cjson.decode(old).cycle_id ~= ARGV[1] then return 0 end
redis.call('HSET', KEYS[1], 'current', ARGV[2])
return 1
"""


def record_value(raw):
    """Reject corrupt records instead of returning arbitrary Redis content."""
    if raw is None:
        return None
    value = json.loads(raw)
    fields = {'instance_id', 'cycle_id', 'state', 'started_timestamp_seconds',
              'finished_timestamp_seconds', 'duration_seconds'}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('Invalid cycle record')
    for field in ('instance_id', 'cycle_id'):
        if str(uuid.UUID(value[field])) != value[field]:
            raise ValueError('Invalid cycle identity')
    if value['state'] not in ('running', 'returned', 'raised', 'stopped'):
        raise ValueError('Invalid cycle state')
    for field in ('started_timestamp_seconds', 'finished_timestamp_seconds', 'duration_seconds'):
        number = value[field]
        if number is None and field != 'started_timestamp_seconds' and value['state'] == 'running':
            continue
        if type(number) not in (int, float) or not math.isfinite(number) or number < 0:
            raise ValueError('Invalid cycle timestamp or duration')
        if value['state'] == 'running' and field != 'started_timestamp_seconds':
            raise ValueError('Running cycle has completion evidence')
    return value


class CycleProgressStore:
    def __init__(self, redis, server_id):
        self.redis = redis
        self.prefix = 'cycle-progress:' + hashlib.sha256(str(server_id).encode()).hexdigest() + ':'

    def connection(self):
        if len(self.redis.servers) != 1:
            raise ValueError('One authoritative Redis server required')
        return next(iter(self.redis.servers.values()))['conn']

    def key(self, worker):
        if worker not in WORKERS:
            raise ValueError('Unknown cycle worker')
        return self.prefix + worker

    def start(self, worker, record):
        return self.connection().eval(START, 1, self.key(worker), record['instance_id'], json.dumps(record)) == 1

    def finish(self, worker, record):
        return self.connection().eval(FINISH, 1, self.key(worker), record['cycle_id'], json.dumps(record)) == 1

    def read(self):
        connection = self.connection()
        result = {}
        for worker in WORKERS:
            current, previous = connection.hmget(self.key(worker), 'current', 'previous_instance')
            result[worker] = {'current': record_value(current), 'previous_instance': record_value(previous)}
        return result
