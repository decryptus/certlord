import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

import yaml
from certlord.adapters.issuance_command import issuance_command
from certlord.classes.config import CERTBOT_INSTALLER_CONFIG_OPTION, ISSUANCE_HEADER
from certlord.services.certificates import CertificateService, CertificateConflict
from certlord.services.issuance import issuance_header


class IssuanceTests(unittest.TestCase):
    def setUp(self):
        self.backend = Mock()
        self.backend.lock_timeout = 1
        self.backend.get_certificate_ids_for_domain.return_value = {'certificate_ids': ['6ff9418a-a4d7-5964-b0a3-78f920426989', '153e7019-20d1-563c-bbfd-0ce49b1f14f5']}
        self.current = {'status': 'processing', 'issuance_id': 'a' * 64}
        self.backend.certificate_snapshot.side_effect = lambda *args: (dict(self.current), 3)
        self.service = CertificateService(self.backend)
        self.payload = {'domain': 'one.example.test', 'cert': 'cert', 'key': 'key', 'chain': ''}

    def test_missing_identity_fails_before_storage(self):
        with self.assertRaises(CertificateConflict):
            self.service.save(self.payload)
        self.backend.get_certificate_ids_for_domain.assert_not_called()

    def test_superseded_callback_cannot_write_any_site(self):
        with self.assertRaises(CertificateConflict):
            self.service.save(self.payload, 'b' * 64)
        self.backend.save_certificate.assert_not_called()

    def test_new_attempt_binds_all_sites_before_return(self):
        first = self.service.begin_issuance('one.example.test')
        second = self.service.begin_issuance('one.example.test')
        self.assertNotEqual(first, second)
        self.assertEqual(len(first), 64)
        self.assertEqual(self.backend.bind_issuance.call_count, 4)
        self.assertEqual(self.backend.bind_issuance.call_args.args[2], second)

    def test_partial_binding_failure_does_not_return_attempt(self):
        self.backend.bind_issuance.side_effect = [None, RuntimeError('unavailable')]
        with self.assertRaises(RuntimeError):
            self.service.begin_issuance('one.example.test')
        self.backend.LOCK.release.assert_called_once()

    def test_duplicate_callback_cannot_change_already_accepted_material(self):
        self.current.update(self.payload, issuance_complete=True)
        with self.assertRaises(CertificateConflict):
            self.service.save(dict(self.payload, cert='different'), 'a' * 64)
        self.backend.save_certificate.assert_not_called()

    def test_matching_identity_is_persisted_with_accepted_material(self):
        self.service.save(self.payload, 'a' * 64)
        saved = self.backend.save_certificate.call_args.args[2]
        self.assertEqual(saved['issuance_id'], 'a' * 64)
        self.assertTrue(saved['issuance_complete'])
        self.assertNotIn('issuance_id', self.payload)

    def test_header_case_and_duplicate_handling(self):
        self.assertEqual(issuance_header({'x-certlord-issuance': 'a'}), 'a')
        self.assertIsNone(issuance_header({'X-CertLord-Issuance': 'a', 'x-certlord-issuance': 'b'}))

    def test_installer_config_is_private_temporary_and_preserves_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source.yml'
            config = {'deploy': {'uri': 'http://localhost', 'headers': {
                'Authorization': 'fixture', 'x-certlord-issuance': 'obsolete'}}}
            source.write_text(yaml.safe_dump(config))
            command = {'args': ['certbot', CERTBOT_INSTALLER_CONFIG_OPTION + '=' + str(source)], 'env': None}
            before = copy.deepcopy(command)
            with issuance_command(command, 'a' * 64) as (args, env):
                target = Path(args[-1])
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
                headers = yaml.safe_load(target.read_text())['deploy']['headers']
                self.assertEqual(headers, {'Authorization': 'fixture', ISSUANCE_HEADER: 'a' * 64})
                self.assertIsNone(env)
            self.assertFalse(target.exists())
            self.assertEqual(command, before)
            self.assertEqual(yaml.safe_load(source.read_text()), config)
