"""Explicit imported-material replacement has mandatory storage preconditions."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from import_fixture import material
from certlord.services.certificates import CertificateService, CertificateConflict, CertificateNotFound
from certlord.services.import_material import InvalidMaterial
from certlord.services.runtime import CertificateRuntime
from certlord.ports.certificates import StorageConflict, StorageNotFound, StorageError
from certlord.client.cli import main

IDENTITY = '12345678-1111-4111-8111-111111111111'
DOMAIN = 'import.example.test'


class ReplacementTests(unittest.TestCase):
    def setUp(self):
        self.backend = Mock()
        self.backend.bound_domains.return_value = [DOMAIN]
        self.current = {'origin':'external', 'renewal_owner':'external', 'status':'deployed',
                        'identity_definition':{'version':1,'domains':[DOMAIN]}, 'identity_sha256':'identity'}
        self.backend.certificate_snapshot.return_value = (self.current, 7)
        self.service = CertificateService(self.backend)
        self.service.detail = Mock(return_value={'certificate_id':IDENTITY, 'version':8})
        self.payload = material()
        self.payload.pop('domain')
        self.payload['expected_version'] = 7

    def test_version_required_and_no_client_domain_change(self):
        for version in (None, True, 0, -1, '7', 7.0):
            with self.subTest(version=version), self.assertRaises(InvalidMaterial):
                self.service.replace_import(IDENTITY, dict(self.payload, expected_version=version))
        with self.assertRaises(InvalidMaterial):
            self.service.replace_import(IDENTITY, dict(self.payload, domain='other.example.test'))
        self.assertEqual(self.backend.mock_calls, [])

    def test_stale_version_never_writes(self):
        with self.assertRaises(CertificateConflict):
            self.service.replace_import(IDENTITY, dict(self.payload, expected_version=6))
        self.backend.replace_import.assert_not_called()
        self.backend.evt_tcrawler.set.assert_not_called()

    def test_only_existing_external_identity_can_be_replaced(self):
        for record in ({'origin':'acme'}, {'origin':'external','status':'delete'}):
            self.backend.certificate_snapshot.return_value = (record, 7)
            with self.assertRaises(CertificateConflict):
                self.service.replace_import(IDENTITY, self.payload)
        self.backend.certificate_snapshot.side_effect = StorageNotFound()
        with self.assertRaises(CertificateNotFound):
            self.service.replace_import(IDENTITY, self.payload)
        self.backend.replace_import.assert_not_called()

    def test_invalid_material_keeps_current_record(self):
        for changes in ({'key':'not PEM'}, {'cert':material(names=('other.example.test',))['cert']}):
            with self.assertRaises(InvalidMaterial):
                self.service.replace_import(IDENTITY, dict(self.payload, **changes))
        self.backend.replace_import.assert_not_called()
        self.backend.evt_tcrawler.set.assert_not_called()

    def test_valid_replacement_keeps_identity_and_uses_snapshot(self):
        self.assertEqual(self.service.replace_import(IDENTITY, self.payload)['version'], 8)
        args = self.backend.replace_import.call_args.args
        self.assertEqual(args[:2], (IDENTITY, DOMAIN))
        self.assertEqual(args[3], (self.current, 7))
        self.backend.reserve_identity.assert_not_called()
        self.backend.evt_tcrawler.set.assert_called_once_with()

    def test_cas_conflict_or_ambiguous_reply_never_becomes_success(self):
        for error, expected in ((StorageConflict(), CertificateConflict), (StorageError(), StorageError)):
            self.backend.replace_import.side_effect = error
            with self.assertRaises(expected):
                self.service.replace_import(IDENTITY, self.payload)
        self.service.detail.assert_not_called()
        self.assertEqual(self.backend.evt_tcrawler.set.call_count, 2)

    def test_runtime_preserves_identity_and_external_policy_with_cas(self):
        runtime = object.__new__(CertificateRuntime)
        runtime._store = Mock()
        runtime.replace_import(IDENTITY, DOMAIN, {'cert':'new','key':'new-key','chain':'new-chain'}, (self.current,7))
        args = runtime._store.replace_if_version.call_args.args
        self.assertEqual(args[:3], (IDENTITY, DOMAIN, 7))
        self.assertEqual(args[3]['identity_sha256'], 'identity')
        self.assertEqual(args[3]['status'], 'generated')
        self.assertEqual(args[3]['renewal_owner'], 'external')
        self.assertEqual(self.current['status'], 'deployed')

    def test_detail_returns_version_from_same_snapshot_as_metadata(self):
        service = CertificateService(self.backend)
        self.backend.list_certificates.return_value = [DOMAIN]
        self.backend.get_certificate.return_value = {'origin':'external','status':'generated'}
        self.current.update(fingerprint_sha256='public-fingerprint', key='secret')
        value = service.detail(IDENTITY)
        self.assertEqual(value['version'], 7)
        self.assertEqual(value['status'], 'deployed')
        self.assertNotIn('secret', json.dumps(value))

    @patch('certlord.client.cli.CertificateClient')
    def test_cli_uses_explicit_version_and_file_contents(self, factory):
        record = {'certificate_id':IDENTITY,'domains':[DOMAIN],'status':'generated','version':8}
        factory.return_value.inventory.return_value = [record]
        factory.return_value.replace_import.return_value = record
        with tempfile.TemporaryDirectory() as directory:
            paths = {}
            for name in ('cert','key','chain'):
                paths[name] = str(Path(directory)/name)
                Path(paths[name]).write_text(self.payload[name])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(['replace', DOMAIN, '--expected-version','7','--json',
                    '--cert-file', paths['cert'], '--key-file',paths['key'],'--chain-file',paths['chain']]),0)
            self.assertNotIn('PRIVATE KEY', output.getvalue())
        factory.return_value.replace_import.assert_called_once_with(IDENTITY,7,
            self.payload['cert'],self.payload['key'],self.payload['chain'])
