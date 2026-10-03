"""A busy certificate_id must be revisited without waiting for the periodic scan."""
import threading
import unittest
from unittest.mock import Mock, patch

from certlord.classes.vault_crawler import SslCertsVaultCrawler


class CrawlerRetryTests(unittest.TestCase):
    def test_busy_site_is_revisited_without_another_notification(self):
        busy, retried = threading.Event(), threading.Event()
        module = Mock()
        module.modconf = {'vault_check_interval': 3600}
        module.config = {'general': {'server_id': 'test'}}
        module.evt_tcrawler = threading.Event()
        module.evt_deployer = threading.Event()
        module.get_certificate_ids.return_value = ['6ff9418a-a4d7-5964-b0a3-78f920426989']
        module.list_certificates.return_value = []

        def acquire(certificate_id):
            if not busy.is_set():
                busy.set()
                return False
            retried.set()
            return True

        module.CERTIFICATES_LOCK.try_acquire.side_effect = acquire
        worker = SslCertsVaultCrawler(module, Mock(), None)
        with patch('certlord.classes.vault_crawler.DEFAULT_VAULT_BUSY_RETRY_INTERVAL', 0.01):
            worker.start()
            try:
                self.assertTrue(busy.wait(1), 'Initial busy scan did not run')
                self.assertTrue(retried.wait(1), 'Busy certificate_id was abandoned until next hourly scan')
            finally:
                worker.terminate()
                worker.join(1)
        self.assertFalse(worker.is_alive())

    def test_crawler_preserves_pending_deletion_before_worker_runs(self):
        from certlord.classes.ssl_cert_auto_object import SslCertAutoObject
        from certlord.classes.config import STATUS_DELETE
        pending = SslCertAutoObject('6ff9418a-a4d7-5964-b0a3-78f920426989')
        pending.add_dom('one.example.test', STATUS_DELETE)
        module = Mock()
        module.modconf = {}
        module.config = {'general': {'server_id': 'test'}}
        module.get_certificate_ids.return_value = ['6ff9418a-a4d7-5964-b0a3-78f920426989']
        module.list_certificates.return_value = ['one.example.test']
        module.fetch_acerts.return_value = pending
        module.get_certificate.return_value = {
            'cert': 'certificate', 'key': 'key', 'vendor': 'letsencrypt', 'status': 'deployed'}
        module.get_certificate_ids_for_domain.return_value = {'certificate_ids': []}
        certificate = Mock()
        certificate.get_notAfter.return_value = b'20990101000000Z'
        worker = SslCertsVaultCrawler(module, Mock(), None)
        with patch('certlord.classes.vault_crawler.crypto.load_certificate', return_value=certificate):
            worker._run()
        self.assertEqual(pending.get_dom_status('one.example.test'), STATUS_DELETE)
        module.change_certificate_id.assert_not_called()
        module.create_ssl_check.assert_not_called()
