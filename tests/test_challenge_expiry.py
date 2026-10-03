"""Challenge retention remains bounded when client cleanup never arrives."""
import unittest
from unittest.mock import Mock, patch

from certlord.classes.exceptions import CertLordConfigError
from certlord.modules.letsencrypt import LetsEncryptModule


class ChallengeExpiryTests(unittest.TestCase):
    def initialize(self, options):
        module = LetsEncryptModule()
        module.modconf = options
        module.config = {'general': {'lock_timeout': 1}}
        with patch('certlord.modules.letsencrypt.api_access'), \
                patch('certlord.modules.letsencrypt.redis_adapter') as adapter:
            adapter.return_value.servers = {'letsencrypt': Mock()}
            module.safe_init(None)
        return module

    def test_default_retention_is_finite(self):
        self.assertEqual(self.initialize({}).challenge_ttl, 3600)

    def test_custom_retention_is_applied_atomically_with_publication(self):
        module = self.initialize({'challenge_ttl': 23})
        request = Mock()
        path = '/.well-known/acme-challenge/' + 'a' * 43
        request.query_params.return_value = {'challenge': 'a' * 43}
        request.get_path.return_value = path
        request.payload_params.return_value = 'a' * 43 + '.' + 'b' * 43
        module.well_known_put(request)
        module._redis.set_key.assert_called_once_with(path, request.payload_params.return_value, expire=23)

    def test_invalid_retention_fails_before_connecting(self):
        for value in (None, True, False, 0, -1, 1.5, float('inf'), '30', 2147483648):
            with self.subTest(value=value), \
                    patch('certlord.modules.letsencrypt.redis_adapter') as adapter, \
                    self.assertRaises(CertLordConfigError):
                module = LetsEncryptModule()
                module.modconf = {'challenge_ttl': value}
                module.safe_init(None)
            adapter.assert_not_called()
