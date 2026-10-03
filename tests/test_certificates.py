import unittest
from unittest.mock import Mock
from certlord.classes.config import STATUS_DELETE, STATUS_EXISTS, STATUS_PROCESSING
from certlord.classes.ssl_cert_auto_object import SslCertAutoObject
from certlord.services.certificates import (CertificateService, CertificateBusy,
                                           CertificateConflict, CertificateNotFound)


class CertificateServiceTests(unittest.TestCase):
    def setUp(self):
        self.backend = Mock()
        self.backend.lock_timeout = 10
        self.backend.certificate_snapshot.return_value = ({'status': 'processing', 'issuance_id': 'a' * 64}, 1)
        self.backend.fetch_acerts.return_value = SslCertAutoObject('6ff9418a-a4d7-5964-b0a3-78f920426989')
        self.backend.bound_domains.return_value = []
        self.backend.list_certificates.return_value = []
        self.backend.get_certificate_ids_for_domain.side_effect = lambda d: {'certificate_ids': [], 'domain': d}
        self.backend.duplicate_certificate.return_value = False
        self.service = CertificateService(self.backend)

    def test_duplicate_receives_site_before_domain(self):
        self.backend.duplicate_certificate.return_value = True
        self.assertEqual(self.service.upsert('6ff9418a-a4d7-5964-b0a3-78f920426989', ['Example.ORG']), ['example.org'])
        self.backend.duplicate_certificate.assert_called_once_with('6ff9418a-a4d7-5964-b0a3-78f920426989', 'example.org')
        self.backend._create_certificate.assert_not_called()
        self.assertEqual(self.backend.fetch_acerts.return_value.get_dom_status('example.org'), STATUS_EXISTS)
        self.backend.CERTIFICATES_LOCK.release.assert_called_once_with('6ff9418a-a4d7-5964-b0a3-78f920426989')

    def test_case_difference_does_not_delete_certificate(self):
        self.backend.list_certificates.return_value = ['example.org']
        self.service.upsert('6ff9418a-a4d7-5964-b0a3-78f920426989', ['EXAMPLE.ORG'])
        self.assertEqual(self.backend.fetch_acerts.return_value.get_dom_status('example.org'), STATUS_EXISTS)
        self.backend._create_certificate.assert_not_called()

    def test_removed_domain_is_queued_for_deletion(self):
        self.backend.list_certificates.return_value = ['example.org']
        self.service.upsert('6ff9418a-a4d7-5964-b0a3-78f920426989', [])
        self.assertEqual(self.backend.fetch_acerts.return_value.get_dom_status('example.org'), STATUS_DELETE)
        self.backend.delete_certificate.assert_not_called()

    def test_invalid_domain_prevents_all_writes_and_unlocks(self):
        self.backend.check_dns_resolv.return_value = False
        with self.assertRaises(CertificateConflict):
            self.service.upsert('6ff9418a-a4d7-5964-b0a3-78f920426989', ['a.example.org'])
        self.backend._create_certificate.assert_not_called()
        self.backend.save_acerts.assert_not_called()
        self.backend.CERTIFICATES_LOCK.release.assert_called_once_with('6ff9418a-a4d7-5964-b0a3-78f920426989')

    def test_save_missing_domain_reports_not_found(self):
        payload = {'domain': 'Example.org', 'cert': 'cert', 'key': 'key'}
        with self.assertRaises(CertificateNotFound) as caught:
            self.service.save(payload, 'a' * 64)
        self.assertIn('example.org', str(caught.exception))
        self.assertEqual(payload['domain'], 'Example.org')
        self.backend.LOCK.release.assert_called_once_with()

    def test_save_preserves_input_and_notifies_crawler(self):
        self.backend.get_certificate_ids_for_domain.side_effect = None
        self.backend.get_certificate_ids_for_domain.return_value = {'certificate_ids': ['6ff9418a-a4d7-5964-b0a3-78f920426989']}
        payload = {'domain': 'Example.org', 'cert': 'cert', 'key': 'key'}
        self.service.save(payload, 'a' * 64)
        self.assertNotIn('status', payload)
        self.assertNotIn('chain', payload)
        self.backend.evt_tcrawler.set.assert_called_once_with()

    def test_failed_lock_is_not_released(self):
        self.backend.LOCK.acquire_read.return_value = False
        with self.assertRaises(CertificateBusy):
            self.service.index('6ff9418a-a4d7-5964-b0a3-78f920426989')
        self.backend.LOCK.release.assert_not_called()

    def test_storage_failure_still_releases_lock(self):
        self.backend.list_certificates.side_effect = RuntimeError('unavailable')
        with self.assertRaises(RuntimeError):
            self.service.index('6ff9418a-a4d7-5964-b0a3-78f920426989')
        self.backend.LOCK.release.assert_called_once_with()

    def test_index_preserves_processing_status(self):
        self.backend.list_certificates.return_value = ['example.org']
        self.backend.get_certificate.return_value = {'cert': '', 'key': ''}
        self.assertEqual(self.service.index('6ff9418a-a4d7-5964-b0a3-78f920426989'), {'example.org': STATUS_PROCESSING})

    def test_validate_caa_conflict(self):
        self.backend.check_caa_records.return_value = False
        with self.assertRaises(CertificateConflict):
            self.service.validate('Example.org')
        self.backend.check_dns_resolv.assert_called_once_with('example.org')
        self.backend.LOCK.release.assert_called_once_with()

    def test_deploy_wakes_crawler(self):
        self.service.deploy()
        self.backend.evt_tcrawler.set.assert_called_once_with()

