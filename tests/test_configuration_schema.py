"""Configuration contracts use XYS without coercing values or initializing services."""
import copy
import unittest
try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

from certlord.configuration_schema import validate_configuration, CertLordConfigError


class ConfigurationSchemaTests(unittest.TestCase):
    def test_extensions_and_values_are_preserved_without_mutation(self):
        conf = {'general': {}, 'api_authentication': {'backend': 'httpdis', 'permissions': {'reader': ['read']}}, 'certificate_storage': {'backend': 'vault'}, 'ssl_checkers': {'custom': {'enabled': False, 'extension': 'PRIVATE'}}}
        original = copy.deepcopy(conf)
        self.assertIs(validate_configuration(conf), conf)
        self.assertEqual(conf, original)

    def test_invalid_known_fields_cannot_hide_behind_extensions(self):
        cases = [None,
                 {'general': []},
                 {'general': {}, 'api_authentication': []},
                 {'general': {}, 'api_authentication': {'permissions': {'a': 'read'}}},
                 {'general': {}, 'api_authentication': {'permissions': {'a': ['root']}}},
                 {'general': {}, 'ssl_checkers': {'updown': {'enabled': 'false'}}},
                 {'general': {}, 'certificate_storage': {'backend': 'other'}}]
        for conf in cases:
            with self.assertRaises(CertLordConfigError) as caught:
                validate_configuration(conf)
            self.assertNotIn('PRIVATE', str(caught.exception))

    def test_invalid_values_are_not_in_validation_logs(self):
        with patch('certlord.configuration_schema.xys.LOG') as logger:
            with self.assertRaises(CertLordConfigError) as caught:
                validate_configuration({'general': 'PRIVATE-CONFIGURATION-VALUE'})
        self.assertNotIn('PRIVATE-CONFIGURATION-VALUE', str(caught.exception))
        self.assertNotIn('PRIVATE-CONFIGURATION-VALUE', str(logger.mock_calls))

    def test_parser_preserves_credential_resolution_and_defaults(self):
        from certlord.configuration_schema import parse_configuration
        conf = {'general': {'server_id': 'localhost'}, 'credentials': 'credentials.yml'}
        with patch('dwho.config.load_credentials', return_value={'vault': {'token': 'PRIVATE'}}) as credentials:
            result = parse_configuration(conf)
        credentials.assert_called_once_with('credentials.yml', None)
        self.assertEqual(result['credentials']['vault']['token'], 'PRIVATE')
        self.assertGreater(result['general']['max_workers'], 0)

    def test_imported_module_configuration_checked_before_routes(self):
        from certlord.modules.ssl_certs import SslCertsModule
        conf = {'general': {}, 'modules': {'ssl_certs': {'certbot': []}}}
        with patch('certlord.modules.ssl_certs.authenticated_routes') as routes:
            with self.assertRaises(CertLordConfigError):
                SslCertsModule().init(conf)
            routes.assert_not_called()

    def test_valid_permissions_remain_authorized_by_the_service(self):
        from certlord.services.api_access import AccessDenied
        conf = {'general': {}, 'api_authentication': {'permissions': {'reader': ['read']}}}
        validate_configuration(conf)
        from certlord.services.api_access import ApiAccess
        access = ApiAccess(conf['api_authentication']['permissions'])
        self.assertEqual(access.require('reader', 'read'), 'reader')
        with self.assertRaises(AccessDenied):
            access.require('reader', 'deploy')
