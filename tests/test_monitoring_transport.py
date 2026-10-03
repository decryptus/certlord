"""Real SDK transport faults must not duplicate provider mutations."""
import threading
import time
import unittest
from unittest.mock import Mock, patch

from requests.exceptions import ConnectionError

from certlord.classes.ssl_checker import SslCertsCheckerUpdown, SslCertsCheckerStatuscake
from certlord.services.monitoring import CertificateMonitoring
from integration.network_faults import MonitoringFaultServer


class MonitoringTransportTests(unittest.TestCase):
    def setUp(self):
        self.fault = MonitoringFaultServer()
        self.server = self.fault.server()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = patch.dict('os.environ', {
            'UPDOWN_ENDPOINT': 'http://127.0.0.1:%d' % self.server.server_port})
        self.endpoint.start()
        self.checker = SslCertsCheckerUpdown().init(
            {'enabled': True, 'recipients': ['email:123'], 'timeout': 0.2},
            {'api-key': 'disposable-fixture-key'})
        self.monitoring = CertificateMonitoring({'updown': self.checker})

    def tearDown(self):
        self.fault.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.endpoint.stop()

    def test_silent_listing_is_bounded_and_recovers_before_creation(self):
        self.fault.blocked.set()
        started = time.monotonic()
        with self.assertLogs(level='ERROR'):
            self.monitoring.create_ssl_check('example.test')
        self.assertTrue(self.fault.observed.is_set())
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(self.fault.snapshot()['creates'], 0)
        self.fault.blocked.clear()
        self.fault.release.set()
        self.monitoring.create_ssl_check('example.test')
        self.assertEqual(self.fault.snapshot()['creates'], 1)

    def test_applied_create_with_lost_reply_is_not_replayed_and_is_rediscovered(self):
        self.fault.drop_create_reply.set()
        with self.assertLogs(level='ERROR'):
            self.monitoring.create_ssl_check('example.test')
        self.assertEqual(self.fault.snapshot()['creates'], 1)
        self.assertEqual(self.fault.snapshot()['controls'], 1)
        self.assertNotIn('updown', self.monitoring._ready)
        self.monitoring.create_ssl_check('example.test')
        self.assertEqual(self.fault.snapshot()['creates'], 1)
        self.assertEqual(self.checker.collector, {'https://example.test': '1'})

    def test_provider_mutations_never_reconnect_and_replay_on_connection_error(self):
        for kind, create_method, delete_method in (
                (SslCertsCheckerUpdown, 'add', 'delete'),
                (SslCertsCheckerStatuscake, 'insert_ssl', 'delete_ssl')):
            with self.subTest(provider=kind.CHECKER_NAME):
                checker = kind()
                checker.config = {'params': {'enabled': True}}
                checker.conn = Mock()
                checker.connect = Mock()
                getattr(checker.conn, create_method).side_effect = ConnectionError('private detail')
                getattr(checker.conn, delete_method).side_effect = ConnectionError('private detail')
                with self.assertLogs(level='ERROR') as logs:
                    self.assertFalse(checker.create('example.test'))
                    self.assertFalse(checker.delete('1'))
                checker.connect.assert_not_called()
                self.assertEqual(getattr(checker.conn, create_method).call_count, 1)
                self.assertEqual(getattr(checker.conn, delete_method).call_count, 1)
                self.assertNotIn('private detail', '\n'.join(logs.output))
