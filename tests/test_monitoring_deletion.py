"""Deletion failure must retain provider state for a later attempt."""
import unittest
from unittest.mock import Mock
from certlord.classes.ssl_checker import SslCertsCheckerStatuscake, SslCertsCheckerUpdown


class MonitoringDeletionTests(unittest.TestCase):
    def checker(self, kind):
        checker = kind()
        checker.config = {'params': {'enabled': True}}
        checker.conn = Mock(spec=['delete'] if kind is SslCertsCheckerUpdown else ['delete_ssl'])
        checker.collector = {'https://example.org': '123'}
        return checker

    def test_updown_boolean_success_removes_cached_control(self):
        checker = self.checker(SslCertsCheckerUpdown)
        checker.conn.delete.return_value = True
        self.assertTrue(checker.delete('123'))
        checker.conn.delete.assert_called_once_with('123')
        self.assertEqual(checker.collector, {})

    def test_statuscake_success_removes_cached_control(self):
        checker = self.checker(SslCertsCheckerStatuscake)
        checker.conn.delete_ssl.return_value = {'Success': True}
        self.assertTrue(checker.delete('123'))
        self.assertEqual(checker.collector, {})

    def test_rejected_deletion_keeps_cache(self):
        for kind, method, result in [(SslCertsCheckerUpdown, 'delete', False),
                (SslCertsCheckerStatuscake, 'delete_ssl', {'Success': False})]:
            checker = self.checker(kind)
            getattr(checker.conn, method).return_value = result
            self.assertFalse(checker.delete('123'))
            self.assertEqual(checker.collector, {'https://example.org': '123'})

    def test_exception_keeps_cache_without_leaking_error(self):
        for kind, method in [(SslCertsCheckerUpdown, 'delete'),
                (SslCertsCheckerStatuscake, 'delete_ssl')]:
            checker = self.checker(kind)
            getattr(checker.conn, method).side_effect = RuntimeError('secret-value')
            with self.assertLogs(level='ERROR') as logs:
                self.assertFalse(checker.delete('123'))
            self.assertNotIn('secret-value', '\n'.join(logs.output))
            self.assertEqual(checker.collector, {'https://example.org': '123'})
