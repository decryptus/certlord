"""Failure evidence includes Certbot without publishing fixture credentials."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    'lifecycle_diagnostics', Path(__file__).parent / 'integration/diagnostics.py')
diagnostics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostics)


class LifecycleDiagnosticsTests(unittest.TestCase):
    def test_nested_certbot_and_rotated_logs_are_sanitized(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            logs = root / 'certbot/logs'
            logs.mkdir(parents=True)
            (root / 'worker.log').write_text('Connection refused: secret-token\n')
            (logs / 'letsencrypt.log').write_text(
                'secret-key -----BEGIN PRIVATE KEY-----\n'
                'urn:ietf:params:acme:error:unauthorized secret-domain.invalid\n'
                '  File "/secret-home/client.py", line 12, in poll\n'
                'acme.errors.ValidationError: secret-details\n')
            (logs / 'letsencrypt.log.1').write_text('Performing the following challenges:\nsecret-domain.invalid')
            (root / 'private_key.json').write_text('secret-key')
            result = diagnostics.collect(root)
            self.assertEqual(set(result), {'worker.log', 'certbot/logs/letsencrypt.log',
                                          'certbot/logs/letsencrypt.log.1'})
            self.assertEqual(result['certbot/logs/letsencrypt.log']['locations'], [
                {'file': 'client.py', 'line': 12, 'function': 'poll'},
                {'exception': 'acme.errors.ValidationError'}])
            self.assertEqual(result['certbot/logs/letsencrypt.log']['categories'],
                             ['urn:ietf:params:acme:error:unauthorized'])
            self.assertNotIn('secret-', json.dumps(result))
            self.assertNotIn('PRIVATE KEY', json.dumps(result))

    def test_empty_and_unrecognized_logs_produce_no_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertEqual(diagnostics.collect(root), {})
            (root / 'worker.log').write_text('arbitrary secret text\n')
            self.assertEqual(diagnostics.collect(root), {})

    def test_traceback_locations_are_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'worker.log').write_text(''.join(
                '  File "/tmp/client.py", line %d, in poll\n' % n for n in range(30)))
            locations = diagnostics.collect(root)['worker.log']['locations']
            self.assertEqual([item['line'] for item in locations], list(range(15, 30)))

    def test_unreadable_or_rotated_log_does_not_mask_the_test_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'worker.log').touch()
            for error in (FileNotFoundError('secret-path'), PermissionError('secret-path')):
                with self.subTest(error=type(error).__name__), \
                        patch.object(Path, 'read_text', side_effect=error):
                    self.assertEqual(diagnostics.collect(root), {
                        'worker.log': {'locations': [], 'categories': ['Log unavailable']}})
