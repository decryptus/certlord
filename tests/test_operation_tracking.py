"""Non-secret correlation remains separate from identities and authorization."""
from concurrent.futures import ThreadPoolExecutor
import json
import threading
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from certlord.services.operation_tracking import current_id, emit, record_id, tracked, valid_id
from certlord.services.runtime import CertificateRuntime
from certlord.ports.certificates import StorageConflict
import test_deployer

CERTIFICATE = '6ff9418a-a4d7-5964-b0a3-78f920426989'
DOMAIN = 'example.test'


class OperationTrackingTests(unittest.TestCase):
    def runtime(self):
        runtime = CertificateRuntime.__new__(CertificateRuntime)
        runtime._store = Mock()
        return runtime

    def test_concurrent_nested_contexts_are_isolated_and_reset_after_exception(self):
        barrier = threading.Barrier(2)
        @tracked('nested')
        def nested():
            return current_id()
        @tracked('create')
        def execute(fail):
            outer = current_id()
            barrier.wait(timeout=3)
            self.assertEqual(nested(), outer)
            if fail:
                raise RuntimeError(outer)
            return outer
        def run(fail):
            try:
                value = execute(fail)
            except RuntimeError as error:
                value = str(error)
            self.assertIsNone(current_id())
            return value
        with ThreadPoolExecutor(max_workers=2) as executor:
            ids = list(executor.map(run, (False, True)))
        self.assertTrue(all(map(valid_id, ids)))
        self.assertNotEqual(*ids)

    def test_creation_ignores_supplied_tracking_id_and_preserves_caller_data(self):
        runtime = self.runtime()
        supplied = str(uuid4())
        data = {'operation_id': supplied, 'cert': 'secret'}
        @tracked('create')
        def create():
            value = current_id()
            runtime._create_certificate(CERTIFICATE, DOMAIN, data=data)
            return value
        generated = create()
        stored = runtime._store.put.call_args.args[2]
        self.assertEqual(stored['operation_id'], generated)
        self.assertNotEqual(generated, supplied)
        self.assertEqual(data, {'operation_id': supplied, 'cert': 'secret'})

    def test_callback_and_deployment_preserve_stored_operation_not_payload(self):
        runtime = self.runtime()
        operation = str(uuid4())
        current = {'operation_id': operation, 'status': 'processing'}
        data = {'cert': 'new', 'key': 'secret', 'status': 'generated', 'operation_id': str(uuid4())}
        runtime.save_certificate(CERTIFICATE, DOMAIN, data, (current, 7))
        saved = runtime._store.replace_if_version.call_args.args[3]
        self.assertEqual(saved['operation_id'], operation)
        fresh = self.runtime()
        fresh.mark_deployed(CERTIFICATE, DOMAIN, (saved, 8))
        self.assertEqual(fresh._store.replace_if_version.call_args.args[3]['operation_id'], operation)
        self.assertEqual(current, {'operation_id': operation, 'status': 'processing'})

    def test_replacement_gets_new_operation_and_failed_cas_does_not_claim_storage(self):
        runtime = self.runtime()
        previous = str(uuid4())
        @tracked('replace_import')
        def replace():
            runtime.replace_import(CERTIFICATE, DOMAIN, {'cert': 'new'}, ({'operation_id': previous}, 9))
        with self.assertLogs('certlord.services.operation_tracking') as logs:
            replace()
        payload = runtime._store.replace_if_version.call_args.args[3]
        self.assertTrue(valid_id(payload['operation_id']))
        self.assertNotEqual(payload['operation_id'], previous)
        runtime._store.replace_if_version.side_effect = StorageConflict()
        with self.assertLogs('certlord.services.operation_tracking') as logs:
            with self.assertRaises(StorageConflict):
                replace()
        self.assertNotIn('replacement_stored', '\n'.join(logs.output))
        self.assertIn('replace_import_raised', '\n'.join(logs.output))

    def test_invalid_metadata_is_omitted_and_logging_failure_does_not_fail_work(self):
        self.assertIsNone(record_id({'operation_id': 'secret\nFORGED'}))
        with self.assertLogs('certlord.services.operation_tracking') as logs:
            emit('deployment_command_started', str(uuid4()), 'secret\nFORGED', 'secret-token')
        self.assertNotIn('secret', '\n'.join(logs.output))
        with patch('certlord.services.operation_tracking.LOG.info', side_effect=RuntimeError('sink failed')):
            @tracked('create')
            def create():
                return 42
            self.assertEqual(create(), 42)
        self.assertIsNone(current_id())

    def test_deployment_links_stored_operation_to_attempt_without_child_output(self):
        fixture = test_deployer.DeployerTests()
        fixture.setUp()
        operation = str(uuid4())
        fixture.snapshot[0]['operation_id'] = operation
        with patch.object(fixture.deployer._runner, 'run', return_value=(0, b'secret', b'secret')), \
             self.assertLogs('certlord.services.operation_tracking') as logs:
            fixture.deployer._run()
        records = [json.loads(item.getMessage().split(' ', 1)[1]) for item in logs.records]
        self.assertEqual([item['event'] for item in records],
                         ['deployment_command_started', 'deployment_command_returned', 'deployment_acknowledged'])
        self.assertEqual({item['operation_id'] for item in records}, {operation})
        self.assertEqual(len({item['attempt_id'] for item in records}), 1)
        self.assertTrue(valid_id(records[0]['attempt_id']))
        self.assertNotIn('secret', '\n'.join(logs.output))

    def test_failed_command_does_not_emit_acknowledgement(self):
        fixture = test_deployer.DeployerTests()
        fixture.setUp()
        fixture.snapshot[0]['operation_id'] = str(uuid4())
        with patch.object(fixture.deployer._runner, 'run', return_value=(1, b'', b'')), \
             self.assertLogs('certlord.services.operation_tracking') as logs:
            fixture.deployer._run()
        self.assertIn('deployment_command_unacknowledged', '\n'.join(logs.output))
        self.assertNotIn('deployment_acknowledged', '\n'.join(logs.output))
        fixture.assert_pending()
