"""Failure and isolation contracts for certificate infrastructure boundaries."""
import ast
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
import hvac
import certlord
from certlord.adapters.api_auth import ApiRequestAccess, HttpdisApiAuth
from certlord.adapters.pending import PendingCertificates
from certlord.adapters.vault_auth import VaultSession, VaultAppRoleAuth
from certlord.adapters.vault_store import VaultCertificateStore
from certlord.composition import api_access, vault_settings
from certlord.services.api_access import ApiAccess, AccessDenied
from certlord.services.monitoring import CertificateMonitoring
from certlord.ports.certificates import StorageError, StorageNotFound


class BoundaryTests(unittest.TestCase):
    def test_http_module_has_no_infrastructure_imports(self):
        source = Path(certlord.__file__).parent / 'modules/ssl_certs.py'
        tree = ast.parse(source.read_text())
        imports = [n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        self.assertTrue(imports)
        self.assertFalse(any(n.startswith(('certlord.classes', 'certlord.adapters', 'dwho.adapters')) for n in imports))
        methods = [n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
        self.assertNotIn('get_certificate', methods)
        self.assertNotIn('create_ssl_check', methods)

    def test_monitoring_failure_does_not_prevent_other_provider(self):
        failed, healthy = Mock(), Mock()
        failed.create.side_effect = RuntimeError('private credentials')
        monitoring = CertificateMonitoring({'failed': failed, 'healthy': healthy})
        with self.assertLogs('certlord.services.monitoring', level='ERROR') as log:
            monitoring.create_ssl_check('example.org')
        healthy.create.assert_called_once_with('example.org', True, True)
        self.assertNotIn('private credentials', '\n'.join(log.output))

    def test_monitoring_delete_uses_normalized_collector_key(self):
        checker = Mock()
        checker.collector = {'https://example.org': '6ff9418a-a4d7-5964-b0a3-78f920426989'}
        CertificateMonitoring({'test': checker}).delete_ssl_check('example.org')
        checker.delete.assert_called_once_with('6ff9418a-a4d7-5964-b0a3-78f920426989', True)

    def test_disabled_monitoring_does_nothing(self):
        monitoring = CertificateMonitoring({})
        monitoring.create_ssl_check('example.org')
        monitoring.delete_ssl_check('example.org')
        monitoring.fetch_ssl_checks()

    def test_storage_copy_and_explicit_kv2_mount(self):
        session = Mock()
        store = VaultCertificateStore(session, 'certs', 'custom')
        payload = {'cert': 'fixture', 'nested': []}
        store.put('6ff9418a-a4d7-5964-b0a3-78f920426989', 'example.org', payload)
        method = session.client.return_value.secrets.kv.v2.create_or_update_secret
        method.assert_called_once_with(path='certs/6ff9418a-a4d7-5964-b0a3-78f920426989/example.org', mount_point='custom', secret=payload)
        method.call_args.kwargs['secret']['nested'].append('mutated')
        self.assertEqual(payload['nested'], [])

    def test_missing_update_is_not_acknowledged(self):
        session = Mock()
        session.client.return_value.secrets.kv.v2.patch.side_effect = hvac.exceptions.InvalidPath()
        with self.assertRaises(StorageNotFound):
            VaultCertificateStore(session, 'certs').update('6ff9418a-a4d7-5964-b0a3-78f920426989', 'example.org', {})

    def test_storage_errors_do_not_expose_credentials(self):
        session = Mock()
        session.client.side_effect = RuntimeError('secret-token')
        with self.assertRaises(StorageError) as caught:
            VaultCertificateStore(session, 'certs').get('6ff9418a-a4d7-5964-b0a3-78f920426989', 'example.org')
        self.assertNotIn('secret-token', str(caught.exception))

    def test_approle_authenticates_after_expiration(self):
        client = Mock()
        client.is_authenticated.side_effect = [False, True, True, False, True]
        session = VaultSession('https://vault.example.org', VaultAppRoleAuth('role', 'secret'), Mock(return_value=client))
        self.assertIs(session.client(), client)
        self.assertIs(session.client(), client)
        self.assertIs(session.client(), client)
        self.assertEqual(client.auth.approle.login.call_count, 2)

    def test_api_authenticates_before_reading_identity(self):
        request = Mock()
        variables = {'HTTP_AUTH_USER': 'forged'}
        request.get_server_vars.return_value = variables
        request.authenticate.side_effect = lambda: variables.update(HTTP_AUTH_USER='reader')
        access = ApiRequestAccess(HttpdisApiAuth(), ApiAccess({'reader': ['read'], 'forged': ['write']}))
        self.assertEqual(access.require(request, 'read'), 'reader')
        with self.assertRaises(AccessDenied):
            access.require(request, 'write')

    def test_unknown_principal_is_denied(self):
        with self.assertRaises(AccessDenied):
            ApiAccess({'reader': ['read']}).require('unknown', 'read')

    def test_local_api_mode_rejects_network_listener(self):
        with self.assertRaises(Exception):
            api_access({'general': {'listen_addr': '0.0.0.0'}, 'api_authentication': {'backend': 'local'}})

    @patch.dict('os.environ', {'VAULT_ADDR': 'https://vault.example.org', 'VAULT_TOKEN': 'canonical'}, clear=True)
    def test_vault_configuration_reads_environment(self):
        result = vault_settings({'credentials': {'vault': {'key_name': 'certs'}}})
        self.assertEqual(result['token'], 'canonical')
        self.assertEqual(result['url'], 'https://vault.example.org')

    def test_redis_write_failure_releases_lock_and_propagates(self):
        redis = Mock()
        redis.set_key.side_effect = RuntimeError('unavailable')
        pending = PendingCertificates(redis)
        pending.DOMAIN_LOCK = Mock()
        with self.assertRaises(RuntimeError):
            pending.set_certificate_ids_for_domain('example.org', ['6ff9418a-a4d7-5964-b0a3-78f920426989'])
        pending.DOMAIN_LOCK.release.assert_called_once_with('example.org')
