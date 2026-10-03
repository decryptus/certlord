"""HTTP status contracts preserve absence, invalid input and backend failure."""
import unittest
from unittest.mock import Mock, patch
from httpdis.ext.httpdis_json import HttpReqErrJson
from certlord.modules.letsencrypt import LetsEncryptModule
from certlord.modules.ssl_certs import SslCertsModule


class HttpErrorTests(unittest.TestCase):
    def challenge(self):
        module = LetsEncryptModule()
        module._api_access = Mock()
        module._redis = Mock()
        module.LOCK = Mock()
        module.lock_timeout = 1
        module.challenge_ttl = 30
        request = Mock()
        request.query_params.return_value = {'challenge': 'a'*43}
        request.payload_params.return_value = 'fixture.proof'
        request.get_path.return_value = '/.well-known/acme-challenge/' + 'a'*43
        return module, request

    def test_absent_challenge_is_404_and_releases_lock(self):
        module, request = self.challenge()
        module._redis.get_key.return_value = None
        with self.assertRaises(HttpReqErrJson) as error:
            module.well_known_get(request)
        self.assertEqual(error.exception.code, 404)
        self.assertEqual(error.exception.headers.get("Cache-Control"), "no-store")
        module.LOCK.release.assert_called_once_with()

    def test_existing_challenge_returns_exact_bytes_without_caching(self):
        module, request = self.challenge()
        module._redis.get_key.return_value = b'fixture.proof'
        response = module.well_known_get(request)
        self.assertEqual(response.get_code(), 200)
        self.assertEqual(response.data, b'fixture.proof')
        self.assertEqual(response.get_header('Cache-control'), 'no-store')
        module.LOCK.release.assert_called_once_with()

    def test_backend_failure_is_503_not_missing_and_does_not_leak(self):
        module, request = self.challenge()
        module._redis.get_key.side_effect = RuntimeError('secret-redis-url')
        with self.assertRaises(HttpReqErrJson) as error:
            module.well_known_get(request)
        self.assertEqual(error.exception.code, 503)
        self.assertNotIn('secret-redis-url', str(error.exception))
        module.LOCK.release.assert_called_once_with()

    def test_invalid_challenge_and_newline_never_reach_storage(self):
        for token, payload in (('a'*43+'\n', 'fixture.proof'), ('a'*43, 'fixture.proof\n'),
                               ('a'*43, {}), ('short', 'fixture.proof')):
            with self.subTest(token=token, payload=payload):
                module, request = self.challenge()
                request.query_params.return_value = {'challenge': token}
                request.payload_params.return_value = payload
                with self.assertRaises(HttpReqErrJson) as error:
                    module.well_known_put(request)
                self.assertEqual(error.exception.code, 400)
                self.assertEqual(module._redis.mock_calls, [])
                self.assertEqual(module.LOCK.mock_calls, [])

    def test_invalid_certificate_routes_use_400_before_service(self):
        for method in ('save', 'validate', 'upsert', 'index', 'create', 'remove', 'replace_import'):
            with self.subTest(method=method):
                module = SslCertsModule()
                module._api_access, module._service = Mock(), Mock()
                request = Mock()
                request.query_params.return_value = {}
                request.payload_params.return_value = {}
                with self.assertRaises(HttpReqErrJson) as error:
                    getattr(module, method)(request)
                self.assertEqual(error.exception.code, 400)
                self.assertEqual(module._service.mock_calls, [])

    def test_metrics_formatting_failure_uses_safe_service_error(self):
        module = SslCertsModule()
        module._api_access, module._runtime = Mock(), Mock()
        with patch('certlord.modules.ssl_certs.operations_metrics', side_effect=ValueError('secret-value')):
            with self.assertRaises(HttpReqErrJson) as error:
                module.operation_metrics(Mock())
        self.assertEqual(error.exception.code, 503)
        self.assertNotIn('secret-value', str(error.exception))
