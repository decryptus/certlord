"""Cycle evidence must not become a certificate state machine or an error sink."""
import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from certlord.adapters.cycle_progress import CycleProgressStore, WORKERS, record_value
from certlord.services.cycle_progress import CycleProgress, run_cycle


class CycleProgressTests(unittest.TestCase):
    def setup_tracker(self):
        store = Mock()
        store.start.return_value = store.finish.return_value = True
        store.read.return_value = {}
        worker = SimpleNamespace(name=WORKERS[0], killed=False)
        return store, worker, CycleProgress(store)

    def test_running_is_observable_and_return_is_not_operation_success(self):
        store, worker, tracker = self.setup_tracker()
        def operation():
            snapshot = tracker.snapshot()
            self.assertEqual(snapshot['local'][worker.name]['state'], 'running')
            self.assertIsNone(snapshot['local'][worker.name]['duration_seconds'])
            return 'handled-failure'
        with self.assertLogs('certlord.services.cycle_progress', level='INFO') as logs:
            self.assertEqual(tracker.run(worker, operation), 'handled-failure')
        record = tracker.snapshot()['local'][worker.name]
        self.assertEqual(record['state'], 'returned')
        self.assertGreaterEqual(record['duration_seconds'], 0)
        self.assertEqual(store.finish.call_args.args[1]['cycle_id'], record['cycle_id'])
        self.assertNotIn('handled-failure', ''.join(logs.output))
        self.assertIn(record['cycle_id'], ''.join(logs.output))

    def test_exception_propagates_without_secret_in_evidence(self):
        store, worker, tracker = self.setup_tracker()
        def operation():
            raise RuntimeError('private-token')
        with self.assertLogs('certlord.services.cycle_progress', level='INFO') as logs:
            with self.assertRaisesRegex(RuntimeError, 'private-token'):
                tracker.run(worker, operation)
        record = tracker.snapshot()['local'][worker.name]
        self.assertEqual(record['state'], 'raised')
        self.assertNotIn('private-token', json.dumps(record) + ''.join(logs.output))

    def test_storage_failure_does_not_cancel_work_or_retry_uncertain_write(self):
        store, worker, tracker = self.setup_tracker()
        store.start.side_effect = RuntimeError('private-redis-uri')
        callback = Mock(return_value=42)
        with self.assertLogs('certlord.services.cycle_progress', level='INFO') as logs:
            self.assertEqual(tracker.run(worker, callback), 42)
        callback.assert_called_once_with()
        store.finish.assert_not_called()
        self.assertFalse(tracker.snapshot()['local'][worker.name]['persisted'])
        self.assertNotIn('private-redis-uri', ''.join(logs.output))

    def test_finish_rejection_is_not_reported_as_persisted(self):
        store, worker, tracker = self.setup_tracker()
        store.finish.return_value = False
        tracker.run(worker, lambda: None)
        self.assertFalse(tracker.snapshot()['local'][worker.name]['persisted'])

    def test_stop_during_start_prevents_callback_and_records_stop(self):
        store, worker, tracker = self.setup_tracker()
        def stop(*args):
            worker.killed = True
            return True
        store.start.side_effect = stop
        callback = Mock()
        tracker.run(worker, callback)
        callback.assert_not_called()
        self.assertEqual(tracker.snapshot()['local'][worker.name]['state'], 'stopped')

    def test_new_instance_and_each_cycle_have_distinct_server_ids(self):
        store, worker, tracker = self.setup_tracker()
        tracker.run(worker, lambda: None)
        first = dict(tracker.snapshot()['local'][worker.name])
        tracker.run(worker, lambda: None)
        second = tracker.snapshot()['local'][worker.name]
        self.assertNotEqual(first['cycle_id'], second['cycle_id'])
        self.assertEqual(first['instance_id'], second['instance_id'])
        self.assertNotEqual(CycleProgress(store).instance_id, tracker.instance_id)

    def test_missing_records_are_unknown_and_corruption_is_not_projected(self):
        redis = Mock(servers={'fixture': {'conn': Mock()}})
        connection = redis.servers['fixture']['conn']
        connection.hmget.return_value = (None, None)
        store = CycleProgressStore(redis, 'fixture')
        self.assertTrue(all(value['current'] is None for value in store.read().values()))
        connection.hmget.return_value = (json.dumps({'private-key': 'secret'}), None)
        with self.assertRaises(ValueError):
            store.read()

    def test_record_validation_rejects_invented_completion_and_nonfinite_dates(self):
        store, worker, tracker = self.setup_tracker()
        tracker.run(worker, lambda: None)
        value = dict(tracker.snapshot()['local'][worker.name])
        value.pop('persisted')
        self.assertEqual(record_value(json.dumps(value)), value)
        for patch in ({'duration_seconds':float('nan')}, {'state':'success'},
                      {'state':'running'}, {'cycle_id':'client-string'}, {'extra':'secret'}):
            with self.assertRaises(ValueError):
                record_value(json.dumps(dict(value, **patch)))

    def test_scheduler_helper_preserves_arguments_and_unobserved_direct_cycles(self):
        store, worker, tracker = self.setup_tracker()
        worker._run = Mock(return_value=7)
        self.assertEqual(run_cycle(worker, True), 7)
        worker._cycle_tracker = tracker
        self.assertEqual(run_cycle(worker, True), 7)
        self.assertEqual(worker._run.call_count, 2)
        self.assertEqual(tracker.snapshot()['local'][worker.name]['state'], 'returned')

    def test_read_failure_stays_a_failure(self):
        store, _, tracker = self.setup_tracker()
        store.read.side_effect = RuntimeError('unavailable')
        with self.assertRaises(RuntimeError):
            tracker.snapshot()

    def test_finish_failure_preserves_callback_result_and_uncertain_persistence(self):
        store, worker, tracker = self.setup_tracker()
        store.finish.side_effect = RuntimeError('private-redis-uri')
        with self.assertLogs('certlord.services.cycle_progress', level='INFO') as logs:
            self.assertEqual(tracker.run(worker, lambda: 42), 42)
        record = tracker.snapshot()['local'][worker.name]
        self.assertEqual(record['state'], 'returned')
        self.assertFalse(record['persisted'])
        self.assertNotIn('private-redis-uri', ''.join(logs.output))
