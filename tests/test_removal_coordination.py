import unittest
from unittest.mock import Mock, patch
from certlord.services.runtime import CertificateRuntime
from certlord.services.certificates import CertificateService
from certlord.classes.ssl_cert_auto_object import SslCertAutoObject
from certlord.ports.certificates import StorageNotFound
import test_deployer


class RemovalCoordinationTests(unittest.TestCase):
    def backend(self):
        backend = Mock()
        backend.lock_timeout = 1
        backend.bound_domains.return_value = []
        backend.fetch_acerts.return_value = SslCertAutoObject('6ff9418a-a4d7-5964-b0a3-78f920426989')
        backend.list_certificates.return_value = ['one.example.test']
        backend.get_certificate_ids_for_domain.return_value = {'certificate_ids': ['6ff9418a-a4d7-5964-b0a3-78f920426989', '153e7019-20d1-563c-bbfd-0ce49b1f14f5']}
        return backend

    def test_removal_marks_vault_before_persisting_pending_work(self):
        backend = self.backend()
        CertificateService(backend).upsert('6ff9418a-a4d7-5964-b0a3-78f920426989', [])
        backend.update_certificate.assert_called_once_with('6ff9418a-a4d7-5964-b0a3-78f920426989', 'one.example.test', {'status': 'delete', 'issuance_id': None})
        names = [call[0] for call in backend.mock_calls]
        self.assertLess(names.index('update_certificate'), names.index('save_acerts'))

    def test_failed_tombstone_does_not_accept_removal(self):
        backend = self.backend()
        backend.update_certificate.side_effect = RuntimeError('Unavailable')
        with self.assertRaises(RuntimeError):
            CertificateService(backend).upsert('6ff9418a-a4d7-5964-b0a3-78f920426989', [])
        backend.save_acerts.assert_not_called()
        backend.change_certificate_id.assert_not_called()

    def test_readding_pending_removal_restores_generated_state(self):
        backend = self.backend()
        backend.get_certificate.return_value = {'status': 'delete', 'cert': 'pem', 'key': 'key'}
        CertificateService(backend).upsert('6ff9418a-a4d7-5964-b0a3-78f920426989', ['one.example.test'])
        backend.update_certificate.assert_called_once_with('6ff9418a-a4d7-5964-b0a3-78f920426989', 'one.example.test', {'status': 'generated'})

    def test_shared_domain_keeps_monitoring_for_remaining_site(self):
        runtime = CertificateRuntime.__new__(CertificateRuntime)
        runtime._store = Mock()
        runtime.get_certificate_ids_for_domain = Mock(return_value={'certificate_ids': ['153e7019-20d1-563c-bbfd-0ce49b1f14f5']})
        runtime.delete_ssl_check = Mock()
        runtime.delete_certificate('6ff9418a-a4d7-5964-b0a3-78f920426989', 'one.example.test')
        runtime.delete_ssl_check.assert_not_called()
        runtime._store.delete.assert_called_once_with('6ff9418a-a4d7-5964-b0a3-78f920426989', 'one.example.test')

    def test_last_site_removal_deletes_monitoring(self):
        runtime = CertificateRuntime.__new__(CertificateRuntime)
        runtime._store = Mock()
        runtime.get_certificate_ids_for_domain = Mock(return_value={'certificate_ids': []})
        runtime.delete_ssl_check = Mock()
        runtime.delete_certificate('6ff9418a-a4d7-5964-b0a3-78f920426989', 'one.example.test')
        runtime.delete_ssl_check.assert_called_once_with('one.example.test')

    def test_missing_certificate_cleans_obsolete_deployment_without_launch(self):
        fixture = test_deployer.DeployerTests()
        fixture.setUp()
        fixture.module.certificate_snapshot.side_effect = StorageNotFound('gone')
        with patch.object(fixture.deployer._runner, 'run') as command:
            fixture.deployer._run()
        command.assert_not_called()
        fixture.module.mark_deployed.assert_not_called()
        fixture.deployer._lease.acknowledge.assert_called_once_with('server-1', 'pending-1')

    def test_removal_repairs_stale_reverse_association(self):
        runtime = CertificateRuntime.__new__(CertificateRuntime)
        runtime._store = Mock()
        runtime.get_certificate_ids_for_domain = Mock(return_value={'certificate_ids': ['6ff9418a-a4d7-5964-b0a3-78f920426989', '153e7019-20d1-563c-bbfd-0ce49b1f14f5']})
        runtime.change_certificate_id = Mock()
        runtime.delete_ssl_check = Mock()
        runtime.delete_certificate('6ff9418a-a4d7-5964-b0a3-78f920426989', 'one.example.test')
        runtime.change_certificate_id.assert_called_once_with('one.example.test', '6ff9418a-a4d7-5964-b0a3-78f920426989', False)
        runtime.delete_ssl_check.assert_not_called()

    def test_deletion_worker_delegates_shared_monitoring_decision(self):
        from certlord.classes.certbot_handler import SslCertsCertbotHandler
        module = Mock()
        module.modconf = {}
        module.certbot_cmd.return_value = {'args': ['certbot'], 'env': None}
        pending = SslCertAutoObject('6ff9418a-a4d7-5964-b0a3-78f920426989')
        pending.add_dom('one.example.test', 'delete')
        worker = SslCertsCertbotHandler(module, Mock())
        worker._delete_certs({'certificate_id': '6ff9418a-a4d7-5964-b0a3-78f920426989', 'delete': ['one.example.test']}, pending)
        module.delete_certificate.assert_called_once_with('6ff9418a-a4d7-5964-b0a3-78f920426989', 'one.example.test')
        module.delete_ssl_check.assert_not_called()
