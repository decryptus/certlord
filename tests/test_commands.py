import unittest
from unittest.mock import patch
from certlord.adapters.commands import CommandBuilder
from certlord.classes.exceptions import CertLordConfigError


class CommandTests(unittest.TestCase):
    def builder(self, modconf=None):
        return CommandBuilder({'credentials': {'auton': {
            'uri': 'https://auton.example.org', 'endpoint': 'deploy',
            'auth-user': 'example-user', 'auth-passwd': 'example-password'}}}, modconf or {})

    def test_auton_contract_and_credentials_not_in_argv(self):
        command = self.builder().auton_cmd()
        self.assertEqual(command['args'], ['auton', '--uri', 'https://auton.example.org', '--endpoint', 'deploy'])
        self.assertEqual(command['env']['AUTON_AUTH_USER'], 'example-user')
        self.assertNotIn('example-password', command['args'])

    def test_path_override_does_not_mutate_cached_credentials(self):
        builder = self.builder({'auton': {'search_paths': ['/opt/bin']}})
        self.assertEqual(builder.auton_cmd()['env']['PATH'], '/opt/bin')
        builder.modconf = {}
        self.assertNotIn('PATH', builder.auton_cmd()['env'])
        self.assertNotIn('PATH', builder._get_auton_cred()['env'])

    def test_certbot_arguments_override_defaults(self):
        command = self.builder({'certbot': {'args': ['renew']}}).certbot_cmd()
        self.assertEqual(command['args'], ['certbot', 'renew'])

    def test_sudo_arguments_remain_explicit(self):
        command = self.builder({'certbot': {'become': {'enabled': True}}}).certbot_cmd()
        self.assertEqual(command['args'][:6], ['sudo', '-H', '-E', '-u', 'root', 'certbot'])

    def test_invalid_argument_type_rejected(self):
        with self.assertRaises(CertLordConfigError):
            self.builder({'auton': {'args': 'shell command'}}).auton_cmd()

    @patch.dict('os.environ', {}, clear=True)
    def test_missing_auton_credentials_rejected(self):
        with self.assertRaises(CertLordConfigError):
            CommandBuilder({'credentials': {'auton': {}}}, {}).auton_cmd()
