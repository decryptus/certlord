"""Independent TLS checks use real transport and fail closed on missing evidence."""
import contextlib
import io
import json
import threading
import unittest
from unittest.mock import Mock, patch

from certlord.adapters.tls_endpoints import EndpointPlan, EndpointProbe
from certlord.adapters.processes import CommandRunner
from certlord.classes.tls_monitor import TlsMonitor
from certlord.services.tls_endpoints import EndpointObservations, digest, endpoint_metrics
from certlord.modules.ssl_certs import SslCertsModule
from certlord.client.cli import main
from import_fixture import material
from test_tls_probe_transport import listener


class MemoryEvidence:
    def __init__(self):
        self.records = {}

    def read(self, name, signature):
        return self.records.get((name, signature))

    def write(self, name, signature, record):
        self.records[name, signature] = record


def targets(**overrides):
    spec = dict(host='127.0.0.1', server_name='import.example.test', **overrides)
    return EndpointPlan({'endpoints': {'web': spec}}).targets


class IndependentTlsTests(unittest.TestCase):
    def test_real_handshake_without_pin_still_checks_trust_and_sni(self):
        payload = material()
        with listener(payload) as (port, ca):
            plan = EndpointPlan({'endpoints': {'web': {'host': '127.0.0.1', 'port': port,
                'server_name': payload['domain'], 'ca_file': ca}}})
            probe = EndpointProbe(CommandRunner(threading.Event(), 3, .2))
            target = plan.targets['web']
            result = probe(target)
            self.assertEqual(result['status'], 'verified')
            self.assertEqual(len(result['observed_fingerprint_sha256']), 64)
            self.assertEqual(probe(dict(target, server_name='wrong.example.test'))['error_code'], 'tls_validation_failed')
            self.assertEqual(probe(dict(target, ca_file=None))['error_code'], 'tls_validation_failed')
            self.assertEqual(probe(dict(target, expected='0'*64))['error_code'], 'fingerprint_mismatch')
            self.assertEqual(probe(dict(target, expected=result['observed_fingerprint_sha256']))['status'], 'verified')
            self.assertEqual(probe(dict(target, ca_sha256='0'*64))['status'], 'failed')

    def test_expired_certificate_without_pin_is_rejected(self):
        payload = material(offset=-3)
        with listener(payload) as (port, ca):
            target = EndpointPlan({'endpoints': {'web': {'host': '127.0.0.1', 'port': port,
                'server_name': payload['domain'], 'ca_file': ca}}}).targets['web']
            self.assertEqual(EndpointProbe(CommandRunner(threading.Event(), 3, .2))(target)['error_code'], 'tls_validation_failed')

    def test_unknown_fresh_stale_and_future_evidence_never_invent_success(self):
        clock = Mock(return_value=100.)
        probe = Mock(return_value={'status': 'verified', 'observed_fingerprint_sha256': 'a'*64})
        store = MemoryEvidence()
        service = EndpointObservations(targets(), store, probe, 30, clock)
        self.assertEqual(service.snapshot()['status'], 'unknown')
        probe.assert_not_called()
        service.check()
        self.assertEqual(service.snapshot()['verified'], 1)
        # Restart retains evidence only for identical endpoint configuration.
        restarted = EndpointObservations(targets(), store, probe, 30, clock)
        self.assertEqual(restarted.snapshot()['verified'], 1)
        changed = EndpointObservations(targets(port=8443), store, probe, 30, clock)
        self.assertEqual(changed.snapshot()['status'], 'unknown')
        for now in (131., 99.):
            clock.return_value = now
            result = service.snapshot()
            self.assertEqual(result['verified'], 0)
            self.assertEqual(result['endpoints'][0]['status'], 'stale')
            self.assertIn('certlord_tls_endpoint_verified{endpoint="web"} 0', endpoint_metrics(result))
        self.assertEqual(probe.call_count, 1)

    def test_failure_replaces_success_and_partial_is_explicit(self):
        plan = targets()
        plan['other'] = dict(plan['web'], port=8443)
        probe = Mock(side_effect=[{'status': 'verified', 'observed_fingerprint_sha256': 'a'*64},
                                  {'status': 'failed', 'error_code': 'timeout'}])
        service = EndpointObservations(plan, MemoryEvidence(), probe, 30)
        service.check()
        self.assertEqual(service.snapshot()['status'], 'partial')
        probe.side_effect = None
        probe.return_value = {'status': 'failed', 'error_code': 'tls_validation_failed'}
        service.check()
        self.assertEqual(service.snapshot()['verified'], 0)
        self.assertEqual(service.snapshot()['status'], 'failed')

    def test_corrupt_or_wrong_pin_evidence_fails_closed(self):
        plan = targets(expected_fingerprint_sha256='b'*64)
        store = MemoryEvidence()
        service = EndpointObservations(plan, store, Mock(), 30)
        for record in ({'status': 'verified'}, {'status': 'verified', 'checked_at': 100,
                       'observed_fingerprint_sha256': 'a'*64},
                       {'status': 'failed', 'checked_at': 100, 'error_code': 'private-token'}):
            store.write('web', digest(plan['web']), record)
            with self.assertRaises(ValueError):
                service.snapshot()

    def test_interrupt_never_persists_and_idle_worker_stops(self):
        stop, wake = threading.Event(), threading.Event()
        store = MemoryEvidence()
        def probe(target):
            stop.set()
            return {'status': 'verified', 'observed_fingerprint_sha256': 'a'*64}
        service = EndpointObservations(targets(), store, probe, 30)
        service.check(stop.is_set)
        self.assertEqual(store.records, {})
        stop.clear()
        entered = threading.Event()
        service = Mock()
        service.check.side_effect = lambda stopped: entered.set()
        worker = TlsMonitor(service, 300, stop, wake)
        worker.start()
        try:
            self.assertTrue(entered.wait(2))
        finally:
            worker.terminate()
            worker.join(2)
        self.assertFalse(worker.is_alive())

    def test_invalid_configuration_is_rejected(self):
        for config in ({'interval': True}, {'timeout': float('nan')}, {'interval': 1},
                       {'stale_after': 1}, {'endpoints': []}, {'unknown': 1},
                       {'endpoints': {'bad/name': {}}},
                       {'endpoints': {'web': {'host': 'https://example.org', 'server_name': 'example.org'}}},
                       {'endpoints': {'web': {'host': 'example.org', 'server_name': 'example.org', 'verify': False}}}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                EndpointPlan(config)

    def test_authorization_precedes_reads_and_trigger_payload(self):
        module = object.__new__(SslCertsModule)
        module._authorize, module._runtime = Mock(), Mock()
        request = Mock()
        module._authorize.side_effect = RuntimeError('denied')
        for method in (module.tls_endpoints, module.tls_endpoint_metrics, module.check_tls_endpoints):
            with self.assertRaises(RuntimeError):
                method(request)
        request.payload_params.assert_not_called()
        self.assertEqual(module._runtime.mock_calls, [])
        module._authorize.side_effect = None
        request.payload_params.return_value = {'host': 'unconfigured.example.org'}
        with self.assertRaises(Exception):
            module.check_tls_endpoints(request)
        module._runtime.request_tls_check.assert_not_called()
        request.payload_params.return_value = {}
        module.check_tls_endpoints(request)
        module._authorize.assert_called_with(request, 'write')

    def test_read_failure_is_unavailable_not_empty_success(self):
        module = object.__new__(SslCertsModule)
        module._authorize, module._runtime = Mock(), Mock()
        module._runtime.tls_observations.snapshot.side_effect = RuntimeError('private redis password')
        for method in (module.tls_endpoints, module.tls_endpoint_metrics):
            with self.assertRaises(Exception) as caught:
                method(Mock())
            self.assertNotIn('private redis password', str(caught.exception))
        module._runtime.request_tls_check.assert_not_called()

    @patch('certlord.client.cli.CertificateClient')
    def test_cli_reads_and_trigger_are_separate(self, factory):
        client = factory.return_value
        client.tls_endpoints.return_value = EndpointObservations(targets(), MemoryEvidence(), Mock(), 30).snapshot()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(['tls-endpoints', '--json']), 0)
        self.assertEqual(json.loads(output.getvalue())['status'], 'unknown')
        client.check_tls.assert_not_called()
        client.check_tls.return_value = {'accepted': True}
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['check-tls']), 0)
        client.check_tls.assert_called_once_with()
