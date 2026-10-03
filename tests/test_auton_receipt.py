"""Confirmed remote identities, uncertain outcomes and bounded polling."""
import json
import threading
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4
from certlord.adapters.auton_receipt import receipt_target, run_receipted, InvalidReceipt
from certlord.adapters.processes import CommandInterrupted, CommandTimeout
from certlord.adapters.commands import CommandBuilder


class AutonReceiptTests(unittest.TestCase):
    def setUp(self):
        self.identity = str(uuid4())
        self.target = {'origin': 'https://auton.example.test', 'endpoint': 'deploy'}
        self.command = {'args': ['auton'], 'env': {}, 'receipt_target': self.target}
        self.runner = Mock(timeout=10, grace=0.1)
        self.runner.stop_event = Mock()
        self.runner.stop_event.wait.return_value = False

    def response(self, status='complete', **changes):
        result = {'uid': 'deploy:' + self.identity, 'code': 200,
                  'status': status, 'return_code': 0 if status == 'complete' else None,
                  'stream': ['synthetic-secret'], 'errors': []}
        result.update(changes)
        return 0 if result['code'] == 200 else 1, json.dumps(result).encode(), b'synthetic-secret'

    def test_submit_once_poll_same_uid_and_return_only_receipt_metadata(self):
        with patch('certlord.adapters.auton_receipt.CommandRunner') as factory:
            factory.return_value.run.side_effect = [self.response('new'), self.response('processing'), self.response()]
            notify = Mock()
            code, receipt = run_receipted(self.runner, self.command, self.identity, notify)
        calls = factory.return_value.run.call_args_list
        self.assertEqual([call.args[0][-3] for call in calls], ['run', 'status', 'status'])
        self.assertTrue(all(call.args[0][-1] == self.identity for call in calls))
        self.assertEqual(code, 0)
        self.assertEqual(receipt, dict(self.target, uid='deploy:' + self.identity, status='complete', return_code=0))
        self.assertNotIn('synthetic-secret', repr(notify.call_args_list))

    def test_mismatched_or_malformed_receipts_never_resubmit(self):
        for response in [(0, b'not json', b''), self.response(uid='other:' + self.identity),
                         self.response(return_code=False), self.response(code=201),
                         (0, b'x' * (4*1024*1024+1), b'')]:
            with self.subTest(response_type=type(response[1])), \
                 patch('certlord.adapters.auton_receipt.CommandRunner') as factory:
                factory.return_value.run.return_value = response
                notify = Mock()
                with self.assertRaises(InvalidReceipt):
                    run_receipted(self.runner, self.command, self.identity, notify)
                self.assertEqual(factory.return_value.run.call_count, 1)
                notify.assert_not_called()

    def test_remote_failure_or_uncertain_completion_is_not_success(self):
        for change in ({'return_code': 1}, {'code': 400, 'return_code': 1},
                       {'execution_uncertain': True}, {'outcome': 'job.cancelled'}):
            with self.subTest(change=change), patch('certlord.adapters.auton_receipt.CommandRunner') as factory:
                factory.return_value.run.return_value = self.response(**change)
                code, receipt = run_receipted(self.runner, self.command, self.identity, Mock())
                self.assertNotEqual(code, 0)
                self.assertEqual(receipt['uid'], 'deploy:' + self.identity)

    def test_poll_failure_keeps_confirmed_identity_without_second_submission(self):
        with patch('certlord.adapters.auton_receipt.CommandRunner') as factory:
            factory.return_value.run.side_effect = [self.response('new'), OSError('lost reply')]
            notify = Mock()
            with self.assertRaises(OSError):
                run_receipted(self.runner, self.command, self.identity, notify)
            self.assertEqual(factory.return_value.run.call_count, 2)
            self.assertEqual(factory.return_value.run.call_args.args[0][-3], 'status')
            self.assertEqual(notify.call_args.args[0]['uid'], 'deploy:' + self.identity)

    def test_stop_and_total_deadline_bound_polling(self):
        with patch('certlord.adapters.auton_receipt.CommandRunner') as factory:
            factory.return_value.run.return_value = self.response('new')
            self.runner.stop_event.wait.return_value = True
            with self.assertRaises(CommandInterrupted):
                run_receipted(self.runner, self.command, self.identity, Mock())
        with patch('certlord.adapters.auton_receipt.time.monotonic', side_effect=[0, 11]), \
             patch('certlord.adapters.auton_receipt.CommandRunner') as factory:
            with self.assertRaises(CommandTimeout):
                run_receipted(self.runner, self.command, self.identity, Mock())
            factory.assert_not_called()

    def test_target_and_command_overrides_are_restricted(self):
        for uri in ('https://user:secret@example.test', 'https://example.test?secret=x', 'https://example.test/path'):
            with self.assertRaises(ValueError):
                receipt_target(uri, 'deploy', [])
        for args in (['--uid', 'arbitrary'], ['--uri', 'https://other.test'], ['--target', 'other'], ['--mode=status']):
            with self.assertRaises(ValueError):
                receipt_target(self.target['origin'], 'deploy', args)
        builder = CommandBuilder({'credentials': {'auton': {'uri':self.target['origin'], 'endpoint':'deploy'}}},
                                 {'auton': {'receipt_mode':True, 'args':['--http-timeout','5']}})
        self.assertEqual(builder.auton_cmd()['receipt_target'], self.target)

    def test_receipt_is_stored_with_deployed_snapshot_and_cleared_on_replacement(self):
        from certlord.services.runtime import CertificateRuntime
        runtime = CertificateRuntime.__new__(CertificateRuntime)
        runtime._store = Mock()
        receipt = dict(self.target, uid='deploy:' + self.identity, status='complete', return_code=0)
        snapshot = ({'cert':'pem', 'key':'secret'}, 7)
        runtime.mark_deployed(self.identity, 'example.test', snapshot, receipt=receipt)
        args = runtime._store.replace_if_version.call_args.args
        self.assertEqual(args[2], 7)
        self.assertEqual(args[3]['deployment_receipt'], receipt)
        self.assertEqual(args[3]['status'], 'deployed')
        runtime.replace_import(self.identity, 'example.test', {'cert':'new'}, (args[3],8))
        self.assertNotIn('deployment_receipt', runtime._store.replace_if_version.call_args.args[3])

    def test_invalid_receipt_keeps_lease_and_pending_work(self):
        import test_deployer
        fixture = test_deployer.DeployerTests()
        fixture.setUp()
        fixture.deployer._cmd['receipt_target'] = self.target
        with patch('certlord.classes.deployer.run_receipted', side_effect=InvalidReceipt()), \
             self.assertLogs('certlord.classes.deployer', level='ERROR'):
            fixture.deployer._run()
        fixture.assert_pending()
        fixture.deployer._lease.release.assert_not_called()
