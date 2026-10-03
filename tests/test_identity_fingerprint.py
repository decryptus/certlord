"""Canonical definitions, reservation conflict handling and replay semantics."""
import unittest
from unittest.mock import Mock

from certlord.adapters.vault_store import VaultCertificateStore
from certlord.ports.certificates import StorageNotFound, StorageConflict
from certlord.services.identity_definition import identity_definition, identity_fingerprint
from certlord.services.certificates import CertificateService, CertificateConflict, CertificateNotFound

FIRST = '12345678-1111-4111-8111-111111111111'
SECOND = '12345678-2222-4222-8222-222222222222'


class IdentityFingerprintTests(unittest.TestCase):
    def test_normalization_san_order_duplicates_and_case(self):
        definition = identity_definition(['B.EXAMPLE.test.', 'a.example.test', 'b.example.test'])
        self.assertEqual(definition, {'version': 1, 'domains': ['a.example.test', 'b.example.test']})
        self.assertEqual(identity_fingerprint(definition), identity_fingerprint(identity_definition(['a.example.test', 'b.example.test'])))
        self.assertNotEqual(identity_fingerprint(definition), identity_fingerprint(identity_definition(['a.example.test'])))
        self.assertEqual(identity_definition(['é.example.test']), identity_definition(['xn--9ca.example.test']))

    def test_invalid_definition_rejected(self):
        for domains in ([], ['../bad'], ['a..test'], ['a.test\n'], [None], ['*.example.test']):
            with self.subTest(domains=domains), self.assertRaises((ValueError, UnicodeError)):
                identity_definition(domains)
        with self.assertRaises(ValueError):
            identity_fingerprint({'version': 2, 'domains': ['a.test']})

    def store(self):
        store = VaultCertificateStore(Mock(), 'certs')
        store.list_certificate_ids = Mock(return_value=[])
        store._call = Mock()
        return store

    def test_reservation_persists_sources_without_secret_and_uses_cas_zero(self):
        store = self.store()
        store._call.side_effect = [StorageNotFound(), {}]
        definition = identity_definition(['a.test'])
        self.assertEqual(store.reserve_identity(definition, FIRST), FIRST)
        call = store._call.call_args
        self.assertEqual(call.kwargs['cas'], 0)
        self.assertEqual(call.kwargs['secret'], {'certificate_id': FIRST,
            'definition': definition, 'sha256': identity_fingerprint(definition)})
        self.assertTrue(call.args[1].endswith(identity_fingerprint(definition)))

    def test_concurrent_reservation_loser_reads_winner(self):
        store = self.store()
        definition = identity_definition(['a.test'])
        record = {'definition': definition, 'sha256': identity_fingerprint(definition), 'certificate_id': FIRST}
        store._call.side_effect = [StorageNotFound(), StorageConflict(), {'data': {'data': record}}]
        self.assertEqual(store.reserve_identity(definition, SECOND), FIRST)

    def test_fast_lookup_verifies_definition_without_inventory_scan(self):
        store = self.store()
        definition = identity_definition(['a.test'])
        record = {'definition': definition, 'sha256': identity_fingerprint(definition), 'certificate_id': FIRST}
        store._call.return_value = {'data': {'data': record}}
        self.assertEqual(store.reserve_identity(definition, SECOND), FIRST)
        store.list_certificate_ids.assert_not_called()
        record['definition'] = identity_definition(['different.test'])
        with self.assertRaises(StorageConflict):
            store.reserve_identity(definition, SECOND)

    def test_preindex_duplicates_require_reconciliation(self):
        store = self.store()
        store._call.side_effect = StorageNotFound()
        store.list_certificate_ids.return_value = [FIRST, SECOND]
        store.bound_domains = Mock(return_value=['a.test'])
        with self.assertRaises(StorageConflict):
            store.reserve_identity(identity_definition(['a.test']), FIRST)
        self.assertEqual(store._call.call_count, 1)

    def test_identical_create_returns_existing_without_replacement(self):
        backend = Mock()
        backend.reserve_identity.return_value = FIRST
        backend.get_certificate.return_value = {'status': 'deployed', 'cert': 'existing'}
        service = CertificateService(backend)
        service.upsert, service.detail = Mock(), Mock(return_value={'certificate_id': FIRST})
        self.assertEqual(service.create(['A.TEST', 'a.test']), {'certificate_id': FIRST})
        service.upsert.assert_not_called()
        self.assertEqual(backend.reserve_identity.call_args.args[0], identity_definition(['a.test']))

    def test_retry_after_partial_creation_reuses_reservation(self):
        backend = Mock()
        backend.reserve_identity.return_value = FIRST
        backend.get_certificate.return_value = {}
        backend.bound_domains.return_value = []
        service = CertificateService(backend)
        service.upsert = Mock(side_effect=[RuntimeError('unavailable'), None])
        service.detail = Mock(return_value={'certificate_id': FIRST})
        with self.assertRaises(RuntimeError):
            service.create(['a.test'])
        self.assertEqual(service.create(['a.test']), {'certificate_id': FIRST})
        self.assertEqual([c.args[0] for c in service.upsert.call_args_list], [FIRST, FIRST])

    def test_create_never_restores_deleted_identity_implicitly(self):
        backend = Mock()
        backend.reserve_identity.return_value = FIRST
        service = CertificateService(backend)
        service.upsert = Mock()
        for record, bound in (({'status': 'delete'}, ['a.test']), ({}, ['a.test'])):
            backend.get_certificate.return_value = record
            backend.bound_domains.return_value = bound
            with self.assertRaises(CertificateConflict):
                service.create(['a.test'])
        service.upsert.assert_not_called()

    def test_retry_reconciles_record_created_before_pending_write_failed(self):
        backend = Mock()
        backend.reserve_identity.return_value = FIRST
        backend.get_certificate.return_value = {'status': 'create'}
        service = CertificateService(backend)
        service.upsert = Mock()
        service.detail = Mock(return_value={'certificate_id': FIRST})
        self.assertEqual(service.create(['a.test']), {'certificate_id': FIRST})
        service.upsert.assert_called_once_with(FIRST, ['a.test'])

    def test_update_cannot_create_client_selected_uuid(self):
        backend = Mock()
        backend.bound_domains.return_value = []
        service = CertificateService(backend)
        service.upsert = Mock()
        with self.assertRaises(CertificateNotFound):
            service.update_existing(FIRST, ['a.test'])
        service.upsert.assert_not_called()

    def test_update_preserves_existing_identity_path(self):
        backend = Mock()
        backend.bound_domains.return_value = ['a.test']
        service = CertificateService(backend)
        service.upsert = Mock()
        service.update_existing(FIRST, ['a.test'])
        service.upsert.assert_called_once_with(FIRST, ['a.test'])
