import copy
import unittest
from unittest.mock import Mock

from certlord.ports.certificates import StorageConflict, StorageError, StorageNotFound
from certlord.services.certificates import CertificateService, CertificateConflict, CertificateNotFound
from certlord.services.runtime import CertificateRuntime


class SaveCoordinationTests(unittest.TestCase):
    def setUp(self):
        self.backend = Mock()
        self.backend.lock_timeout = 1
        self.backend.get_certificate_ids_for_domain.return_value = {'certificate_ids': ['6ff9418a-a4d7-5964-b0a3-78f920426989', '153e7019-20d1-563c-bbfd-0ce49b1f14f5']}
        self.backend.certificate_snapshot.return_value = ({'status': 'processing', 'issuance_id': 'a' * 64}, 3)
        self.service = CertificateService(self.backend)
        self.payload = {'domain': 'one.example.test', 'cert': 'new', 'key': 'key'}

    def test_missing_target_preflight_prevents_all_writes(self):
        self.backend.certificate_snapshot.side_effect = [({'status': 'processing', 'issuance_id': 'a' * 64}, 3), StorageNotFound()]
        with self.assertRaises(CertificateNotFound):
            self.service.save(self.payload, 'a' * 64)
        self.backend.save_certificate.assert_not_called()
        self.backend._create_certificate.assert_not_called()

    def test_pending_removal_rejects_save_before_any_write(self):
        self.backend.certificate_snapshot.side_effect = [({'status': 'processing', 'issuance_id': 'a' * 64}, 3), ({'status': 'delete'}, 4)]
        with self.assertRaises(CertificateConflict):
            self.service.save(self.payload, 'a' * 64)
        self.backend.save_certificate.assert_not_called()

    def test_removal_after_snapshot_rejects_stale_save(self):
        self.backend.save_certificate.side_effect = StorageConflict()
        with self.assertRaises(CertificateConflict):
            self.service.save(self.payload, 'a' * 64)
        self.backend.evt_tcrawler.set.assert_called_once_with()
        self.backend._create_certificate.assert_not_called()

    def test_partial_failure_notifies_crawler_and_releases_lock(self):
        self.backend.save_certificate.side_effect = [True, StorageError()]
        with self.assertRaises(StorageError):
            self.service.save(self.payload, 'a' * 64)
        self.assertEqual(self.backend.save_certificate.call_count, 2)
        self.backend.evt_tcrawler.set.assert_called_once_with()
        self.backend.LOCK.release.assert_called_once_with()

    def test_uncertain_first_write_still_notifies_crawler(self):
        self.backend.save_certificate.side_effect = StorageError()
        with self.assertRaises(StorageError):
            self.service.save(self.payload, 'a' * 64)
        self.backend.evt_tcrawler.set.assert_called_once_with()

    def test_runtime_save_uses_snapshot_version_and_preserves_input(self):
        runtime = CertificateRuntime.__new__(CertificateRuntime)
        runtime._store = Mock()
        data = {'cert': 'new', 'key': 'key', 'chain': '', 'status': 'generated'}
        before = copy.deepcopy(data)
        runtime.save_certificate('6ff9418a-a4d7-5964-b0a3-78f920426989', 'one.example.test', data, ({'status': 'processing', 'issuance_id': 'a' * 64}, 7))
        args = runtime._store.replace_if_version.call_args.args
        self.assertEqual(args[:3], ('6ff9418a-a4d7-5964-b0a3-78f920426989', 'one.example.test', 7))
        self.assertEqual(args[3]['cert'], 'new')
        self.assertEqual(data, before)
        runtime._store.put.assert_not_called()

    def test_replayed_material_does_not_reset_deployed_state(self):
        from certlord.classes.config import DEFAULT_CERT_VENDOR
        runtime = CertificateRuntime.__new__(CertificateRuntime)
        runtime._store = Mock()
        data = {'cert': 'new', 'key': 'key', 'chain': '', 'status': 'generated'}
        current = dict(data, status='deployed', vendor=DEFAULT_CERT_VENDOR)
        runtime.save_certificate('6ff9418a-a4d7-5964-b0a3-78f920426989', 'one.example.test', data, (current, 8))
        runtime._store.replace_if_version.assert_not_called()
