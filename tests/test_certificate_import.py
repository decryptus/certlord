"""External import validation, no replacement, and replay after partial persistence."""
import contextlib
import io
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
from import_fixture import material
from certlord.services.import_material import validate_import, InvalidMaterial
from certlord.services.certificates import CertificateService, CertificateConflict
from certlord.services.runtime import CertificateRuntime
from certlord.ports.certificates import StorageConflict
from certlord.client.cli import main

IDENTITY = '12345678-1111-4111-8111-111111111111'


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.payload = material()

    def test_valid_material_normalizes_and_exposes_only_public_metadata(self):
        definition, data = validate_import(self.payload)
        self.assertEqual(definition['domains'], ['import.example.test'])
        self.assertEqual(len(data['fingerprint_sha256']), 64)
        self.assertIn('BEGIN PRIVATE KEY', data['key'])
        self.assertIn('not_after', data)

    def test_dns_san_matching_is_case_insensitive(self):
        definition, _ = validate_import(material(names=('IMPORT.EXAMPLE.TEST',)))
        self.assertEqual(definition['domains'], ['import.example.test'])

    def test_invalid_material_is_rejected_without_echoing_input(self):
        other = material()
        variants = [dict(self.payload, key=other['key']), dict(self.payload, chain=other['chain']),
                    dict(self.payload, domain='other.example.test'), dict(self.payload, cert='PRIVATE INPUT'),
                    dict(self.payload, cert=self.payload['cert']*2),
                    dict(self.payload, key=self.payload['key']*2),
                    dict(self.payload, chain=self.payload['chain']*2),
                    dict(self.payload, chain=self.payload['chain']+'garbage'),
                    dict(self.payload, certificate_id=IDENTITY), dict(self.payload, key='x'*65537),
                    material(offset=-3), material(offset=3), material(ca=True),
                    material(names=('one.example.test', 'two.example.test'))]
        for payload in variants:
            with self.subTest(fields=list(payload)), self.assertRaises(InvalidMaterial) as error:
                validate_import(payload)
            self.assertNotIn('PRIVATE INPUT', str(error.exception))
            self.assertNotIn('BEGIN ', str(error.exception))

    def backend(self, current=None, bound=None):
        backend = Mock()
        backend.reserve_identity.return_value = IDENTITY
        backend.get_certificate.return_value = current or {}
        backend.bound_domains.return_value = bound or []
        service = CertificateService(backend)
        service.detail = Mock(return_value={'certificate_id': IDENTITY})
        return backend, service

    def test_invalid_import_does_not_touch_storage(self):
        backend, service = self.backend()
        with self.assertRaises(InvalidMaterial):
            service.import_certificate(dict(self.payload, key='secret'))
        self.assertEqual(backend.mock_calls, [])

    def test_new_import_marks_external_and_never_schedules_acme(self):
        backend, service = self.backend()
        self.assertEqual(service.import_certificate(self.payload)['certificate_id'], IDENTITY)
        data = backend.create_import.call_args.args[2]
        self.assertEqual((data['origin'], data['renewal_owner'], data['vendor']), ('external',)*3)
        self.assertEqual(data['status'], 'generated')
        backend.save_acerts.assert_not_called()
        backend.check_dns_resolv.assert_not_called()
        backend.change_certificate_id.assert_called_once_with('import.example.test', IDENTITY, True)
        backend.evt_tcrawler.set.assert_called_once_with()

    def test_import_never_overwrites_acme_different_material_or_removed_identity(self):
        _, normalized = validate_import(self.payload)
        for current, bound in [({'status':'create'}, []),
                (dict(normalized, status='delete', origin='external'), []),
                (dict(normalized, key='different', origin='external'), []), ({}, ['import.example.test'])]:
            backend, service = self.backend(current, bound)
            with self.assertRaises(CertificateConflict):
                service.import_certificate(self.payload)
            backend.create_import.assert_not_called()
            backend.change_certificate_id.assert_not_called()

    def test_replay_reconciles_partial_redis_failure_without_rewriting_vault(self):
        _, normalized = validate_import(self.payload)
        backend, service = self.backend(dict(normalized, origin='external', status='deployed'))
        backend.change_certificate_id.side_effect = [RuntimeError('redis unavailable'), None]
        with self.assertRaises(RuntimeError):
            service.import_certificate(self.payload)
        service.import_certificate(self.payload)
        backend.create_import.assert_not_called()
        self.assertEqual(backend.change_certificate_id.call_count, 2)

    def test_concurrent_storage_conflict_cannot_reach_redis(self):
        backend, service = self.backend()
        backend.create_import.side_effect = StorageConflict()
        with self.assertRaises(CertificateConflict):
            service.import_certificate(self.payload)
        backend.change_certificate_id.assert_not_called()

    def test_runtime_creation_uses_cas_zero(self):
        runtime = object.__new__(CertificateRuntime)
        runtime._store = Mock()
        runtime.create_import(IDENTITY, 'import.example.test', {'origin':'external'})
        self.assertEqual(runtime._store.replace_if_version.call_args.args[:3],
                         (IDENTITY, 'import.example.test', 0))

    def test_external_record_cannot_start_issuance(self):
        backend, service = self.backend()
        backend.get_certificate_ids_for_domain.return_value = {'certificate_ids':[IDENTITY]}
        backend.certificate_snapshot.return_value = ({'origin':'external'}, 1)
        with self.assertRaises(CertificateConflict):
            service.begin_issuance('import.example.test')
        backend.bind_issuance.assert_not_called()

    @patch('certlord.client.cli.CertificateClient')
    def test_cli_reads_files_and_never_prints_material(self, factory):
        factory.return_value.import_certificate.return_value = {
            'certificate_id':IDENTITY,'domains':['import.example.test'],'status':'generated'}
        with tempfile.TemporaryDirectory() as directory:
            paths = {}
            for name in ('cert','key','chain'):
                paths[name] = str(Path(directory)/name)
                Path(paths[name]).write_text(self.payload[name])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(['import','import.example.test','--cert-file',paths['cert'],
                             '--key-file',paths['key'],'--chain-file',paths['chain'],'--json'])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.getvalue())['certificate_id'], IDENTITY)
            self.assertNotIn('PRIVATE KEY', output.getvalue())
            factory.return_value.import_certificate.assert_called_once_with('import.example.test',
                self.payload['cert'],self.payload['key'],self.payload['chain'])
