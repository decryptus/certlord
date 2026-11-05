"""Issuance-cycle enumeration on a changing Redis keyspace."""
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, call

from certlord.adapters.pending import PENDING_SCAN_COUNT
from certlord.classes.certbot_handler import SslCertsCertbotHandler
from certlord.classes.ssl_cert_auto_object import SslCertAutoObject


FIRST = '6ff9418a-a4d7-5964-b0a3-78f920426989'
SECOND = '556feec6-6ffb-40a9-81c2-b8954669dc32'


def record(certificate_id):
    pending = SslCertAutoObject(certificate_id, date='2020-01-01 00:00:00')
    pending.add_dom('example.test')
    return pending.dumps('2020-01-01 00:00:00')


class PendingScanTests(unittest.TestCase):
    def setUp(self):
        self.connection = Mock(spec=['scan', 'get', 'eval'])
        self.module = Mock()
        self.module.modconf = {}
        redis = SimpleNamespace(servers={'ssl_certs_primary': {'conn': self.connection}})
        self.worker = SslCertsCertbotHandler(self.module, redis)
        self.worker._create_certs = Mock()
        self.worker._renew_certs = Mock()
        self.worker._delete_certs = Mock()

    def test_duplicate_and_disappearing_keys_and_empty_nonfinal_page(self):
        a, b = (('cert:' + value).encode() for value in (FIRST, SECOND))
        gone = b'cert:gone'
        def pages(cursor, match, count):
            self.assertEqual((match, count), ('cert:*', PENDING_SCAN_COUNT))
            if cursor == 0:
                return 17, [a, a]
            self.assertTrue(self.worker._create_certs.called)
            if cursor == 17:
                return 4, []
            self.assertEqual(cursor, 4)
            return 0, [gone, a, b]
        self.connection.scan.side_effect = pages
        self.connection.get.side_effect = {a: record(FIRST), b: record(SECOND), gone: None}.get
        self.worker._run()
        self.assertEqual(self.connection.get.call_args_list, [call(a), call(gone), call(b)])
        self.assertEqual(self.module.CERTIFICATES_LOCK.release.call_args_list, [call(FIRST), call(SECOND)])
        self.connection.eval.assert_not_called()
        self.worker._run()
        self.assertEqual(self.worker._create_certs.call_count, 4)

    def test_stop_during_processing_avoids_next_key_and_page(self):
        self.connection.scan.side_effect = [(31, [b'cert:first', b'cert:next'])]
        self.connection.get.return_value = record(FIRST)
        self.worker._create_certs.side_effect = lambda *args: self.worker.terminate()
        self.worker._run()
        self.connection.scan.assert_called_once()
        self.connection.get.assert_called_once_with(b'cert:first')

    def test_stop_during_empty_page_does_not_advance_cursor(self):
        def stop(**kwargs):
            self.worker.terminate()
            return 13, []
        self.connection.scan.side_effect = stop
        self.worker._run()
        self.connection.scan.assert_called_once()
        self.connection.get.assert_not_called()
