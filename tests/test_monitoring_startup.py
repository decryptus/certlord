"""Monitoring initialization must not require provider availability."""
import copy
import unittest
from unittest.mock import Mock, patch
from certlord.classes.ssl_checker import SslCertsCheckerUpdown, SslCertsCheckerStatuscake
from certlord.classes.exceptions import CertLordConfigError
from certlord.services.monitoring import CertificateMonitoring


class MonitoringStartupTests(unittest.TestCase):
    def test_updown_initialization_validates_without_connecting(self):
        config = {'enabled': True, 'recipients': ['email:123'], 'timeout': 3}
        original = copy.deepcopy(config)
        with patch('certlord.classes.ssl_checker.updownio.service') as service:
            checker = SslCertsCheckerUpdown().init(config, {'api-key': 'fixture-key'})
            service.assert_not_called()
            checker.connect()
            service.assert_called_once_with('checks', api_key='fixture-key', timeout=3)
        self.assertEqual(config, original)
        self.assertNotIn('timeout', checker.config['params'])

    def test_statuscake_initialization_does_not_query_contact_groups(self):
        with patch('certlord.classes.ssl_checker.StatusCake') as client:
            checker = SslCertsCheckerStatuscake().init(
                {'enabled': True, 'contact_groups': ['123'], 'timeout': 4},
                {'api-key': 'fixture-key', 'api-user': 'fixture-user'})
            client.assert_not_called()
            client.return_value.get_contact_groups.return_value = [{'ContactID': 123}]
            checker.connect()
            client.assert_called_once_with(api_key='fixture-key', api_user='fixture-user', timeout=4)

    def test_invalid_configuration_still_rejected(self):
        for timeout in (0, -1, True, float('inf'), float('nan'), '10'):
            with self.assertRaises(CertLordConfigError):
                SslCertsCheckerUpdown().init(
                    {'enabled': True, 'recipients': ['email:123'], 'timeout': timeout},
                    {'api-key': 'fixture-key'})

    def test_unavailable_provider_can_recover_next_cycle(self):
        unavailable, healthy = Mock(), Mock()
        unavailable.connect.side_effect = [RuntimeError('secret'), None]
        monitoring = CertificateMonitoring({'unavailable': unavailable, 'healthy': healthy})
        with self.assertLogs(level='ERROR'):
            monitoring.create_ssl_check('example.org')
        unavailable.create.assert_not_called()
        healthy.create.assert_called_once()
        monitoring.create_ssl_check('example.org')
        unavailable.list.assert_called_once_with(True, True)
        unavailable.create.assert_called_once_with('example.org', True, True)

    def test_failed_initial_listing_prevents_duplicate_creation(self):
        checker = Mock()
        checker.list.side_effect = RuntimeError('listing failed')
        monitoring = CertificateMonitoring({'provider': checker})
        with self.assertLogs(level='ERROR'):
            monitoring.create_ssl_check('example.org')
        checker.create.assert_not_called()
        checker.list.side_effect = None
        monitoring.create_ssl_check('example.org')
        self.assertEqual(checker.list.call_count, 2)
        checker.create.assert_called_once()
