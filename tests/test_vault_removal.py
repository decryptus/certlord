import unittest
from unittest.mock import Mock

from certlord.adapters.vault_store import VaultCertificateStore
from certlord.ports.certificates import StorageConflict, StorageNotFound


class VaultRemovalTests(unittest.TestCase):
    def setUp(self):
        self.session = Mock()
        self.api = self.session.client.return_value.secrets.kv.v2
        self.api.read_secret_version.return_value = {
            'data': {'data': {'status': 'delete', 'cert': 'private'}, 'metadata': {'version': 3}}}
        self.api.read_secret_metadata.return_value = {
            'data': {'versions': {'1': {}, '2': {}, '3': {}, '4': {}}}}
        self.store = VaultCertificateStore(self.session, 'certs')

    def test_removal_advances_version_and_destroys_material_without_resetting_metadata(self):
        self.store.delete('6ff9418a-a4d7-5964-b0a3-78f920426989', 'one.example.test')
        self.api.delete_metadata_and_all_versions.assert_not_called()
        writes = self.api.create_or_update_secret.call_args_list
        self.assertEqual([call.kwargs['cas'] for call in writes], [3, 4])
        self.assertEqual(writes[0].kwargs['secret'], {'status': 'delete'})
        self.assertEqual(writes[1].kwargs['secret'], {'status': 'removed'})
        self.api.destroy_secret_versions.assert_called_once_with(
            path='certs/6ff9418a-a4d7-5964-b0a3-78f920426989/one.example.test', mount_point='secret', versions=[1, 2, 3])

    def test_failed_marker_cannot_destroy_newer_material(self):
        import hvac
        self.api.create_or_update_secret.side_effect = hvac.exceptions.InvalidRequest()
        with self.assertRaises(StorageConflict):
            self.store.delete('6ff9418a-a4d7-5964-b0a3-78f920426989', 'one.example.test')
        self.api.destroy_secret_versions.assert_not_called()

    def test_removed_marker_is_not_a_managed_certificate(self):
        self.api.read_secret_version.return_value['data']['data'] = {'status': 'removed'}
        self.assertEqual(self.store.get('6ff9418a-a4d7-5964-b0a3-78f920426989', 'one.example.test'), {})
        with self.assertRaises(StorageNotFound):
            self.store.get_versioned('6ff9418a-a4d7-5964-b0a3-78f920426989', 'one.example.test')

    def test_inventory_excludes_removed_marker(self):
        self.api.list_secrets.return_value = {'data': {'keys': ['one.example.test']}}
        self.api.read_secret_version.return_value['data']['data'] = {'status': 'removed'}
        self.assertEqual(self.store.list_domains('6ff9418a-a4d7-5964-b0a3-78f920426989'), [])

    def test_destroy_failure_keeps_retryable_marker(self):
        import hvac
        from certlord.ports.certificates import StorageError
        self.api.destroy_secret_versions.side_effect = hvac.exceptions.Forbidden()
        with self.assertRaises(StorageError):
            self.store.delete('6ff9418a-a4d7-5964-b0a3-78f920426989', 'one.example.test')
        self.assertEqual(self.api.create_or_update_secret.call_count, 1)
