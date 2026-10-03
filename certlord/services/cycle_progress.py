"""Observe scheduler cycles without turning telemetry failure into work failure."""
import json
import logging
import threading
import time
import uuid

LOG = logging.getLogger(__name__)


class CycleProgress:
    def __init__(self, store):
        self.store = store
        self.instance_id = str(uuid.uuid4())
        self._lock = threading.Lock()
        self._local = {}

    def _record(self, worker, record, starting):
        persisted = False
        with self._lock:
            self._local[worker] = dict(record, persisted=False)
        try:
            persisted = (self.store.start if starting else self.store.finish)(worker, record)
        except Exception:
            # Never interpolate backend exceptions (URLs, credentials, material).
            LOG.warning('Cycle evidence persistence unavailable: worker=%s cycle_id=%s', worker, record['cycle_id'])
        with self._lock:
            self._local[worker] = dict(record, persisted=bool(persisted))
        LOG.info('cycle_progress %s', json.dumps(dict(record, worker=worker, persisted=bool(persisted)), sort_keys=True))
        return persisted

    def run(self, worker, callback, *args):
        record = {'instance_id': self.instance_id, 'cycle_id': str(uuid.uuid4()),
                  'state': 'running', 'started_timestamp_seconds': time.time(),
                  'finished_timestamp_seconds': None, 'duration_seconds': None}
        started = time.monotonic()
        persisted = self._record(worker.name, record, True)
        state = 'raised'
        try:
            if worker.killed:
                state = 'stopped'
                return None
            result = callback(*args)
            state = 'stopped' if worker.killed else 'returned'
            return result
        finally:
            record.update(state=state, finished_timestamp_seconds=time.time(),
                          duration_seconds=max(0, time.monotonic() - started))
            if persisted:
                self._record(worker.name, record, False)
            else:
                # An uncertain start is not repaired by an unconditional finish.
                # Avoid a second backend timeout after an unsuccessful start.
                with self._lock:
                    self._local[worker.name] = dict(record, persisted=False)
                LOG.info('cycle_progress %s', json.dumps(dict(record, worker=worker.name, persisted=False), sort_keys=True))

    def snapshot(self):
        durable = self.store.read()
        with self._lock:
            local = {name: dict(record) for name, record in self._local.items()}
        return {'instance_id': self.instance_id, 'local': local, 'stored': durable}


def run_cycle(worker, *args):
    tracker = getattr(worker, '_cycle_tracker', None)
    if tracker is None:
        return worker._run(*args)
    return tracker.run(worker, worker._run, *args)
