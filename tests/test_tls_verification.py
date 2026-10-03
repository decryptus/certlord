"""TLS verification failures must never acknowledge a deployment."""
import json
import threading
import unittest
from unittest.mock import Mock, patch
from certlord.adapters.tls_verification import TlsVerifier
from certlord.adapters.processes import CommandInterrupted, CommandTimeout
from certlord.services.runtime import CertificateRuntime
from certlord.services.verification import verification_metadata
from certlord.ports.certificates import StorageConflict
from import_fixture import material
import test_deployment_coordination as coordination

IDENTITY = '6ff9418a-a4d7-5964-b0a3-78f920426989'


class VerificationTests(unittest.TestCase):
    def verifier(self):
        return TlsVerifier({'targets':{IDENTITY:{'host':'127.0.0.1'}}}, threading.Event())

    def test_explicit_configuration_rejects_urls_unknown_options_and_bad_bounds(self):
        for config in ({'targets':{IDENTITY:{'host':'https://example.org'}}},
                       {'targets':{IDENTITY:{'host':'example.org','insecure':True}}},
                       {'targets':{'wrong':{'host':'example.org'}}},
                       {'targets':{IDENTITY:{'host':'example.org','port':True}}},
                       {'targets':{IDENTITY:{'host':'example.org','ca_file':'relative.pem'}}},
                       {'timeout':0}, {'timeout':True}, {'timeout':float('inf')}, {'timeout':301}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                TlsVerifier(config, threading.Event())
        self.assertFalse(TlsVerifier(None, threading.Event()).configured(IDENTITY))

    def test_success_requires_exact_expected_fingerprint_and_does_not_send_material(self):
        verifier = self.verifier()
        payload = material()
        def run(args, env):
            self.assertNotIn(payload['key'], args)
            self.assertNotIn(payload['cert'], args)
            self.assertEqual(args[5], payload['domain'])
            return 0, json.dumps({'status':'verified','error_code':None,
                                 'observed_fingerprint_sha256':args[7]}).encode(), b''
        verifier.runner.run = Mock(side_effect=run)
        result = verifier.verify(IDENTITY,payload['domain'],payload)
        self.assertEqual(result['status'],'verified')
        self.assertEqual(result['expected_fingerprint_sha256'],result['observed_fingerprint_sha256'])

    def test_malformed_or_inconsistent_probe_output_is_not_success(self):
        verifier = self.verifier()
        for output in (b'private error', b'[]', b'{"status":"verified"}',
                       json.dumps({'status':'verified','observed_fingerprint_sha256':'0'*64}).encode()):
            verifier.runner.run = Mock(return_value=(0,output,b'private-stderr'))
            value = verifier.verify(IDENTITY,'import.example.test',material())
            self.assertEqual(value['status'],'failed')
            self.assertEqual(value['error_code'],'probe_failed')
            self.assertNotIn('private',json.dumps(value))

    def test_timeout_is_recordable_but_interruption_is_not_a_false_result(self):
        verifier = self.verifier()
        verifier.runner.run = Mock(side_effect=CommandTimeout())
        self.assertEqual(verifier.verify(IDENTITY,'import.example.test',material())['error_code'],'timeout')
        verifier.runner.run.side_effect = CommandInterrupted()
        with self.assertRaises(CommandInterrupted):
            verifier.verify(IDENTITY,'import.example.test',material())

    def test_invalid_stored_material_does_not_open_connection(self):
        verifier = self.verifier()
        verifier.runner.run = Mock()
        self.assertEqual(verifier.verify(IDENTITY,'import.example.test',{'cert':'bad'})['error_code'],
                         'invalid_stored_certificate')
        verifier.runner.run.assert_not_called()

    def worker(self):
        worker, module = coordination.CoordinationTests().worker()
        worker._verifier = Mock()
        worker._verifier.configured.return_value = True
        return worker,module

    def test_failed_verification_keeps_queue_and_persists_failure(self):
        worker,module = self.worker()
        failure = {'status':'failed','error_code':'fingerprint_mismatch'}
        worker._verifier.verify.return_value = failure
        with self.assertLogs(level='WARNING'):
            worker._run()
        module.record_verification.assert_called_once_with(IDENTITY,'example.org',
                                                          module.certificate_snapshot.return_value,failure)
        module.mark_deployed.assert_not_called()
        worker._lease.acknowledge.assert_not_called()

    def test_success_and_version_conflict_cannot_ack_stale_verification(self):
        worker,module = self.worker()
        success = {'status':'verified'}
        worker._verifier.verify.return_value = success
        module.mark_deployed.side_effect = StorageConflict()
        with self.assertLogs(level='WARNING'):
            worker._run()
        module.mark_deployed.assert_called_once_with(IDENTITY,'example.org',
                                                    module.certificate_snapshot.return_value,success)
        worker._lease.acknowledge.assert_not_called()

    def test_shutdown_during_verification_does_not_acknowledge(self):
        worker,module = self.worker()
        worker._verifier.verify.side_effect = CommandInterrupted()
        worker._run()
        module.mark_deployed.assert_not_called()
        module.record_verification.assert_not_called()
        worker._lease.acknowledge.assert_not_called()

    def test_runtime_uses_same_cas_for_result_and_deployed_state(self):
        runtime = object.__new__(CertificateRuntime)
        runtime._store = Mock()
        snapshot = ({'cert':'material','status':'generated'},7)
        verification = {'status':'verified'}
        runtime.mark_deployed(IDENTITY,'example.org',snapshot,verification)
        args = runtime._store.replace_if_version.call_args.args
        self.assertEqual(args[:3],(IDENTITY,'example.org',7))
        self.assertEqual(args[3]['status'],'deployed')
        self.assertEqual(args[3]['verification'],verification)
        self.assertNotIn('verification',snapshot[0])
        runtime.record_verification(IDENTITY,'example.org',snapshot,{'status':'failed'})
        self.assertEqual(runtime._store.replace_if_version.call_args.args[3]['status'],'generated')

    def test_replacement_clears_old_verification_and_metadata_does_not_leak(self):
        runtime = object.__new__(CertificateRuntime)
        runtime._store = Mock()
        runtime.replace_import(IDENTITY,'example.org',{'cert':'new'},
                               ({'verification':{'status':'verified'}},7))
        self.assertNotIn('verification',runtime._store.replace_if_version.call_args.args[3])
        value = verification_metadata({'verification':{'status':'failed',
                    'checked_at':'2026-10-02T19:00:00+00:00','error_code':'secret-text','key':'secret-key'}})
        self.assertNotIn('secret',json.dumps(value))
