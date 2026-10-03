"""Cron-safe client dispatch, explicit TUI and HTTP failure boundaries."""
import contextlib
import io
import json
import os
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch
import requests
from certlord.client.api import CertificateClient, ClientError
from certlord.client.cli import main

IDENTITY = '12345678-1111-4111-8111-111111111111'
RECORD = {'certificate_id': IDENTITY, 'domains': ['one.example.test'], 'status': 'deployed'}


class CliTests(unittest.TestCase):
    @patch.dict(os.environ, {}, clear=True)
    @patch('certlord.client.cli.CertificateClient')
    def test_json_list_retains_full_uuid(self, factory):
        factory.return_value.inventory.return_value = [RECORD]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(['list', '--json']), 0)
        self.assertEqual(json.loads(output.getvalue()), [RECORD])
        factory.return_value.close.assert_called_once_with()

    @patch('certlord.client.cli.CertificateClient')
    def test_ambiguous_selector_never_mutates(self, factory):
        other = dict(RECORD, certificate_id='12345678-2222-4222-8222-222222222222')
        factory.return_value.inventory.return_value = [RECORD, other]
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            self.assertEqual(main(['remove', 'one.example.test']), 1)
        self.assertIn('Ambiguous', output.getvalue())
        factory.return_value.remove.assert_not_called()

    @patch('certlord.client.cli.CertificateClient')
    def test_unique_prefix_is_sent_as_full_uuid(self, factory):
        factory.return_value.inventory.return_value = [RECORD]
        factory.return_value.detail.return_value = RECORD
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['show', '12345678', '--json']), 0)
        factory.return_value.detail.assert_called_once_with(IDENTITY)

    def test_noninteractive_tui_fails_before_http_client_creation(self):
        with patch('certlord.client.cli.CertificateClient') as factory, \
                patch('sys.stdin.isatty', return_value=False), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['tui']), 1)
        factory.assert_not_called()

    def test_importing_cli_never_loads_curses_or_daemon_modules(self):
        result = subprocess.run([sys.executable, '-c',
            'import sys; import certlord.client.cli; '
            'assert "curses" not in sys.modules; '
            'assert "certlord.modules.ssl_certs" not in sys.modules'],
            capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_http_client_rejects_unsafe_endpoint_and_timeout(self):
        for url in ('http://remote.example.test', 'https://user:secret@example.test', 'file:///tmp/api'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                CertificateClient(url)
        with self.assertRaises(ValueError):
            CertificateClient('http://127.0.0.1', timeout=float('nan'))

    @patch('certlord.client.api.requests.Session')
    def test_http_transport_uses_verification_timeout_and_no_redirects(self, factory):
        response = factory.return_value.request.return_value
        response.status_code, response.json.return_value = 200, [RECORD]
        client = CertificateClient('https://certlord.example.test', 'user', 'secret', '/tmp/ca.pem', 3)
        self.assertEqual(client.inventory(), [RECORD])
        self.assertEqual(client.session.verify, '/tmp/ca.pem')
        factory.return_value.request.assert_called_once_with('GET', 'https://certlord.example.test/api/certificates',
                                                            json=None, timeout=3, allow_redirects=False)

    @patch('certlord.client.api.requests.Session')
    def test_http_errors_do_not_disclose_credentials_or_response_body(self, factory):
        client = CertificateClient('http://127.0.0.1')
        response = factory.return_value.request.return_value
        response.status_code, response.text = 403, 'private-token'
        with self.assertRaisesRegex(ClientError, 'HTTP 403') as caught:
            client.inventory()
        self.assertNotIn('private-token', str(caught.exception))
        factory.return_value.request.side_effect = requests.ConnectionError('private-token')
        with self.assertRaises(ClientError) as caught:
            client.inventory()
        self.assertNotIn('private-token', str(caught.exception))
