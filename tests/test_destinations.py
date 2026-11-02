"""Per-destination effects, persisted recovery and exact-version TLS evidence."""
from contextlib import ExitStack
import copy
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from certlord.adapters.destinations import DestinationPlan
from certlord.adapters.processes import CommandRunner, CommandTimeout
from certlord.ports.certificates import StorageConflict, StorageError
from certlord.services.certificates import CertificateService, CertificateConflict
from certlord.services.deployment import DestinationDeployment, destination_state, deployment_metadata
from certlord.services.runtime import CertificateRuntime
from certlord.adapters.tls_verification import TlsVerifier
from destination_fixture import FileStore, runtime, IDENTITY, DOMAIN
from import_fixture import material
from test_tls_probe_transport import listener
from certlord.adapters.auton_receipt import InvalidReceipt

TARGETS = {'west': 'a' * 64, 'east': 'b' * 64, 'north': 'c' * 64}


class DestinationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.material = material()
        self.store = FileStore(Path(self.temp.name) / 'store.json', dict(self.material, status='generated'))
        self.runtime = runtime(self.store, TARGETS)
        self.command = Mock(return_value=True)
        self.verify = Mock(return_value={'status': 'verified', 'checked_at': '2026-11-02T00:00:00+00:00',
                                         'expected_fingerprint_sha256': 'd' * 64,
                                         'observed_fingerprint_sha256': 'd' * 64})

    def run_cycle(self, worker=None, targets=None, guard=None):
        worker = worker or self.runtime
        engine = DestinationDeployment(worker.certificate_snapshot, worker.write_deployment,
                                       self.command, self.verify, guard or (lambda: None))
        return engine.run(IDENTITY, DOMAIN, worker.certificate_snapshot(IDENTITY, DOMAIN), targets or TARGETS)

    def record(self):
        return self.store.get_versioned(IDENTITY, DOMAIN)[0]

    def retry(self, name, acknowledge=False, version=None):
        if version is None:
            version = self.store.get_versioned(IDENTITY, DOMAIN)[1]
        return CertificateService(self.runtime).retry_destination(IDENTITY, name,
                   {'expected_version': version, 'acknowledge_uncertain': acknowledge})

    def test_partial_failure_retry_only_failed_target_after_restart(self):
        self.command.side_effect = lambda _id, _domain, name, *_: name != 'east'
        self.assertFalse(self.run_cycle())
        record = self.record()
        self.assertEqual(record['status'], 'generated')
        self.assertEqual(deployment_metadata(record, TARGETS)['verified'], 2)
        restarted = runtime(FileStore(self.store.path), TARGETS)
        self.assertFalse(self.run_cycle(restarted))
        self.assertEqual(self.command.call_count, 3)
        self.runtime = restarted
        self.retry('east')
        self.command.side_effect = None
        self.assertTrue(self.run_cycle(restarted))
        self.assertEqual([c.args[2] for c in self.command.call_args_list], ['west', 'east', 'north', 'east'])
        self.assertEqual(self.record()['status'], 'deployed')

    def test_submission_intent_is_durable_before_external_call(self):
        def command(identity, domain, name, generation, attempt, submit):
            state = FileStore(self.store.path).get_versioned(identity, domain)[0]['deployment']
            self.assertEqual(state['generation'], generation)
            self.assertEqual(state['destinations'][name]['attempt_id'], attempt)
            self.assertEqual(state['destinations'][name]['status'], 'submitting')
            self.assertTrue(submit)
            return True
        self.command.side_effect = command
        self.assertTrue(self.run_cycle())

    def test_uncertain_submission_reconciles_same_job_without_resubmission(self):
        self.command.side_effect = [CommandTimeout(), True, True]
        self.assertFalse(self.run_cycle())
        first = self.command.call_args_list[0].args
        self.command.side_effect = None
        self.assertTrue(self.run_cycle(runtime(FileStore(self.store.path), TARGETS)))
        last = self.command.call_args.args
        self.assertEqual(last[4], first[4])
        self.assertFalse(last[5])
        self.assertEqual(self.command.call_count, 4)

    def test_unknown_job_requires_explicit_acknowledgement_for_fresh_attempt(self):
        self.command.side_effect = CommandTimeout()
        self.run_cycle()
        attempt = self.record()['deployment']['destinations']['west']['attempt_id']
        with self.assertRaises(CertificateConflict):
            self.retry('west')
        self.retry('west', acknowledge=True)
        self.command.side_effect = None
        self.run_cycle()
        self.assertNotEqual(self.record()['deployment']['destinations']['west']['attempt_id'], attempt)

    def test_successful_destination_and_stale_retry_version_are_rejected(self):
        self.command.side_effect = [True, False, True]
        self.run_cycle()
        before = self.store.path.read_bytes()
        for name, version in [('west', None), ('east', 1)]:
            with self.assertRaises(CertificateConflict):
                self.retry(name, version=version)
        self.assertEqual(self.store.path.read_bytes(), before)

    def test_tls_failure_is_rechecked_without_redeploying_command(self):
        self.verify.side_effect = [self.verify.return_value, {'status': 'failed', 'error_code': 'timeout'}, self.verify.return_value]
        self.assertFalse(self.run_cycle())
        self.verify.side_effect = None
        self.assertTrue(self.run_cycle())
        self.assertEqual(self.command.call_count, 3)
        self.assertEqual(self.verify.call_count, 4)

    def test_new_material_invalidates_every_previous_destination(self):
        self.run_cycle()
        self.runtime.replace_import(IDENTITY, DOMAIN, material(), self.store.get_versioned(IDENTITY, DOMAIN))
        self.assertNotIn('deployment', self.record())
        self.assertTrue(self.run_cycle())
        self.assertEqual(self.command.call_count, 6)

    def test_stale_command_result_cannot_acknowledge_replacement(self):
        def replace(*_):
            self.runtime.replace_import(IDENTITY, DOMAIN, material(), self.store.get_versioned(IDENTITY, DOMAIN))
            return True
        self.command.side_effect = replace
        with self.assertRaises(StorageConflict):
            self.run_cycle()
        self.assertEqual(self.record()['status'], 'generated')
        self.assertNotIn('deployment', self.record())
        self.verify.assert_not_called()

    def test_stale_tls_result_cannot_acknowledge_replacement(self):
        def replace(*_):
            self.runtime.replace_import(IDENTITY, DOMAIN, material(), self.store.get_versioned(IDENTITY, DOMAIN))
            return {'status': 'verified'}
        self.verify.side_effect = replace
        with self.assertRaises(StorageConflict):
            self.run_cycle()
        self.assertEqual(self.record()['status'], 'generated')
        self.assertNotIn('deployment', self.record())

    def test_ambiguous_storage_reply_does_not_launch_or_repeat_job(self):
        original = self.runtime.write_deployment
        def write(*args):
            original(*args)
            raise StorageError('lost acknowledgement')
        self.runtime.write_deployment = write
        with self.assertRaises(StorageError):
            self.run_cycle()
        self.command.assert_not_called()
        self.runtime.write_deployment = original
        self.run_cycle()
        self.assertFalse(self.command.call_args_list[0].args[5])

    def test_lease_loss_prevents_external_effect(self):
        with self.assertRaises(StorageConflict):
            self.run_cycle(guard=Mock(side_effect=StorageConflict()))
        self.command.assert_not_called()

    def test_target_configuration_change_only_invalidates_that_destination(self):
        self.run_cycle()
        changed = dict(TARGETS, east='e' * 64)
        self.assertTrue(self.run_cycle(targets=changed))
        self.assertEqual([c.args[2] for c in self.command.call_args_list], ['west', 'east', 'north', 'east'])

    def test_metadata_never_exposes_credentials_material_or_raw_errors(self):
        self.run_cycle()
        record = self.record()
        record['deployment']['destinations']['west'].update(key='private-key', error_code='private-error', uri='private-uri')
        metadata = deployment_metadata(record, TARGETS)
        self.assertNotIn('private-', json.dumps(metadata))
        self.assertEqual(len(metadata['expected_fingerprint_sha256']), 64)
        self.assertNotIn(self.material['key'], json.dumps(metadata))

    def test_three_actual_tls_endpoints_with_partial_failure_and_targeted_recovery(self):
        with ExitStack() as stack:
            endpoints = [stack.enter_context(listener(self.material)) for _ in range(3)]
            verifiers = {name: TlsVerifier({'timeout': 3, 'targets': {IDENTITY: {
                'host': '127.0.0.1', 'port': port, 'ca_file': ca}}}, threading.Event(), 0.2)
                for name, (port, ca) in zip(TARGETS, endpoints)}
            self.verify.side_effect = lambda identity, domain, name, record: verifiers[name].verify(identity, domain, record)
            self.command.side_effect = lambda _id, _domain, name, *_: name != 'east'
            self.assertFalse(self.run_cycle())
            self.runtime = runtime(FileStore(self.store.path), TARGETS)
            self.retry('east')
            self.command.side_effect = None
            self.assertTrue(self.run_cycle())
            metadata = deployment_metadata(self.record(), TARGETS)
            self.assertEqual(metadata['verified'], 3)
            self.assertTrue(all(t['verification']['observed_fingerprint_sha256'] == metadata['expected_fingerprint_sha256']
                                for t in metadata['destinations']))
            self.assertEqual(self.command.call_count, 4)


class DestinationConfigTests(unittest.TestCase):
    def config(self):
        return {'credentials': {'west-profile': {'uri': 'http://127.0.0.1:8999', 'endpoint': 'deploy',
                                                'auth-user': 'fixture', 'auth-passwd': 'fixture-secret'}}}

    def module(self):
        return {'deployment_destinations': {IDENTITY: {'west': {
            'credentials': 'west-profile', 'tls': {'host': '127.0.0.1'}}}}}

    def plan(self, config=None, module=None):
        event = threading.Event()
        return DestinationPlan(config or self.config(), module or self.module(), event, CommandRunner(event, 3, .2))

    def test_reject_invalid_names_empty_oversized_and_ambiguous_configuration(self):
        good = self.module()['deployment_destinations'][IDENTITY]['west']
        for targets in ({}, {'bad/name': good}, {'x'*65: good}, {str(n): good for n in range(33)}):
            with self.subTest(targets=list(targets)), self.assertRaises(ValueError):
                self.plan(module={'deployment_destinations': {IDENTITY: targets}})
        module = self.module()
        module['tls_verification'] = {'targets': {IDENTITY: {'host': '127.0.0.1'}}}
        with self.assertRaises(ValueError):
            self.plan(module=module)

    def test_reject_ambient_credentials_insecure_remote_origins_and_override_flags(self):
        for change in ({'uri': 'http://remote.example.test'}, {'auth-passwd': ''},
                       {'uri': 'https://name:secret@example.test'}, {'endpoint': 'bad/endpoint'}):
            conf = self.config()
            conf['credentials']['west-profile'].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.plan(config=conf)
        module = self.module()
        module['auton'] = {'args': ['--uri', 'https://override.example.test']}
        with self.assertRaises(ValueError):
            self.plan(module=module)

    def test_target_digest_excludes_secret_and_command_carries_only_selectors(self):
        plan = self.plan()
        conf = self.config()
        conf['credentials']['west-profile']['auth-passwd'] = 'rotated-secret'
        self.assertEqual(self.plan(conf).targets, plan.targets)
        with patch('certlord.adapters.destinations.run_receipted', return_value=(0, {})) as run:
            self.assertTrue(plan.command(IDENTITY, DOMAIN, 'west', 'f'*64, 'attempt', False))
        command = run.call_args.args[1]
        self.assertEqual(command['args'][-8:], ['-a', IDENTITY, '-a', DOMAIN, '-a', 'f'*64, '-a', 'west'])
        self.assertNotIn('fixture-secret', repr(command['args']))
        self.assertEqual(run.call_args.kwargs['initial_mode'], 'status')

    def test_uncertain_remote_completion_cannot_become_an_ordinary_failure(self):
        plan = self.plan()
        with patch('certlord.adapters.destinations.run_receipted', return_value=(1, {'execution_uncertain': True})):
            with self.assertRaises(InvalidReceipt):
                plan.command(IDENTITY, DOMAIN, 'west', 'f'*64, 'attempt', False)

    def test_http_retry_requires_deploy_permission_before_reading_payload(self):
        from certlord.modules.ssl_certs import SslCertsModule
        from certlord.services.api_access import AccessDenied
        from httpdis.ext.httpdis_json import HttpReqErrJson
        module = SslCertsModule()
        module._api_access = Mock()
        module._api_access.require.side_effect = AccessDenied()
        module._service = Mock()
        request = Mock()
        with self.assertRaises(HttpReqErrJson):
            module.retry_destination(request)
        module._api_access.require.assert_called_once_with(request, 'deploy')
        request.payload_params.assert_not_called()
        module._service.retry_destination.assert_not_called()

    def test_cli_retry_has_explicit_target_version_and_uncertainty_acknowledgement(self):
        from certlord.client.cli import main
        import contextlib
        import io
        with patch('certlord.client.cli.CertificateClient') as factory:
            client = factory.return_value
            client.inventory.return_value = [{'certificate_id': IDENTITY, 'domains': [DOMAIN], 'status': 'generated'}]
            client.retry_destination.return_value = {'certificate_id': IDENTITY, 'domains': [DOMAIN], 'status': 'generated'}
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(['retry-destination', DOMAIN, 'west', '--expected-version', '7',
                                       '--acknowledge-uncertain', '--json']), 0)
            client.retry_destination.assert_called_once_with(IDENTITY, 'west', 7, True)
