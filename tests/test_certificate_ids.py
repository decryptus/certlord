"""Identity invariants and unambiguous human-facing selection."""
import json
import unittest
from unittest.mock import Mock
from uuid import UUID
from certlord.services.certificate_ids import (valid_certificate_id, require_certificate_id,
                                              resolve_certificate, short_ids)
from certlord.services.certificates import CertificateService, CertificateConflict
from certlord.adapters.vault_store import VaultCertificateStore
from certlord.classes.ssl_cert_auto_object import SslCertAutoObject
from certlord.adapters.deployment_queue import DeploymentQueue

FIRST = '12345678-1111-4111-8111-111111111111'
SECOND = '12345678-2222-4222-8222-222222222222'


class CertificateIdentityTests(unittest.TestCase):
    def test_only_canonical_uuid_identity_is_accepted(self):
        self.assertTrue(valid_certificate_id(FIRST))
        for value in ('42', '../other', FIRST.replace('-', ''), FIRST + '\n',
                      '00000000-0000-0000-0000-000000000000', 42, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                require_certificate_id(value)

    def test_vault_rejects_path_injection_and_filters_legacy_groups(self):
        session = Mock()
        store = VaultCertificateStore(session, 'certs')
        with self.assertRaises(ValueError):
            store.get('../other', 'one.example.test')
        session.client.assert_not_called()
        session.client.return_value.secrets.kv.v2.list_secrets.return_value = {
            'data': {'keys': [FIRST + '/', '42/', 'business-name/', '../']}}
        self.assertEqual(store.list_certificate_ids(), [FIRST])

    def test_multiple_domains_are_rejected_before_backend_access(self):
        backend = Mock()
        with self.assertRaises(CertificateConflict):
            CertificateService(backend).upsert(FIRST, ['one.example.test', 'two.example.test'])
        self.assertEqual(backend.mock_calls, [])

    def test_uuid_cannot_change_domain_even_after_removal(self):
        backend = Mock()
        backend.bound_domains.return_value = ['old.example.test']
        backend.list_certificates.return_value = []  # Removed, but identity metadata remains.
        with self.assertRaises(CertificateConflict):
            CertificateService(backend).upsert(FIRST, ['new.example.test'])
        backend.fetch_acerts.assert_not_called()
        backend._create_certificate.assert_not_called()
        backend.CERTIFICATES_LOCK.release.assert_called_once_with(FIRST)

    def test_creation_generates_uuid4_and_reuses_it_for_inventory(self):
        service = CertificateService(Mock())
        service.backend.reserve_identity.side_effect = lambda definition, candidate: candidate
        service.backend.get_certificate.return_value = {}
        service.backend.bound_domains.return_value = []
        service.upsert, service.detail = Mock(), Mock()
        service.create(['one.example.test'])
        identity = service.upsert.call_args.args[0]
        self.assertEqual(UUID(identity).version, 4)
        service.detail.assert_called_once_with(identity)

    def test_inventory_contains_no_private_material_and_omits_removed_records(self):
        backend = Mock()
        backend.get_certificate_ids.return_value = [FIRST, SECOND]
        backend.list_certificates.side_effect = [['one.example.test'], []]
        backend.get_certificate.return_value = {'cert': 'pem', 'key': 'PRIVATE', 'status': 'deployed'}
        value = CertificateService(backend).inventory()
        self.assertEqual(value, [{'certificate_id': FIRST, 'domains': ['one.example.test'],
                                 'status': 'deployed', 'verification': None}])
        self.assertNotIn('PRIVATE', json.dumps(value))

    def test_pending_and_queue_serialize_uuid_field(self):
        record = json.loads(SslCertAutoObject(FIRST).dumps())
        self.assertEqual(record['certificate_id'], FIRST)
        self.assertNotIn('site_id', record)
        redis, pipe = Mock(), Mock()
        redis.servers = {'one': {'conn': Mock()}}
        redis.servers['one']['conn'].pipeline.return_value.__enter__ = Mock(return_value=pipe)
        redis.servers['one']['conn'].pipeline.return_value.__exit__ = Mock(return_value=False)
        DeploymentQueue(redis).enqueue('server', FIRST, 'one.example.test', {'cert': 'fixture'})
        self.assertEqual(json.loads(pipe.hset.call_args.args[2])['certificate_id'], FIRST)

    def test_domain_full_id_and_unique_prefix_resolve_same_certificate(self):
        records = [{'certificate_id': FIRST, 'domains': ['one.example.test']},
                   {'certificate_id': SECOND, 'domains': ['two.example.test']}]
        for selector in (FIRST, 'ONE.EXAMPLE.TEST', '12345678-1'):
            self.assertEqual(resolve_certificate(selector, records), FIRST)
        for selector in ('12345678', '123', 'unknown.example.test'):
            with self.assertRaises(ValueError):
                resolve_certificate(selector, records)
        self.assertEqual(short_ids(records)[FIRST], '12345678-1')

    def test_shared_domain_is_ambiguous(self):
        records = [{'certificate_id': identity, 'domains': ['one.example.test']} for identity in (FIRST, SECOND)]
        with self.assertRaisesRegex(ValueError, 'Ambiguous'):
            resolve_certificate('one.example.test', records)
