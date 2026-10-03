"""Real library contracts; install requirements.txt before running this suite."""
import inspect
import threading
import tempfile
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import yaml
import unittest
from unittest.mock import Mock, patch

from certlord.composition import vault_settings
from certlord.modules.ssl_certs import SslCertsModule
from certlord.modules.letsencrypt import LetsEncryptModule
from certlord.services.certificates import CertificateConflict, CertificateNotFound, CertificateBusy
from dwho.adapters.redis import DWhoAdapterRedis
from httpdis.ext.httpdis_json import HttpReqErrJson
from sonicprobe.libs.moresynchro import RWLock, ListLock
from certbot_httpreq.installer import Installer
from acme_http_connector import HTTPConnector
from certbot_httpreq.authenticator import Authenticator
import hvac


class ComponentContracts(unittest.TestCase):
    def setUp(self):
        self.module = SslCertsModule()
        self.module._service = Mock()
        self.module._api_access = Mock()

    def test_http_error_translation(self):
        for error, code in [(CertificateConflict, 409), (CertificateNotFound, 404), (CertificateBusy, 503)]:
            with self.assertRaises(HttpReqErrJson) as caught:
                self.module._call_service(Mock(side_effect=error('failure')))
            self.assertEqual(caught.exception.code, code)

    def test_invalid_http_payload_rejected_before_service(self):
        request = Mock()
        request.payload_params.return_value = ['invalid']
        with self.assertRaises(HttpReqErrJson) as caught:
            self.module.save(request)
        self.assertEqual(caught.exception.code, 400)
        self.module._service.save.assert_not_called()

    def test_upsert_route_delegates_validated_inputs(self):
        request = Mock()
        request.query_params.return_value = {'certificate_id': '6ff9418a-a4d7-5964-b0a3-78f920426989'}
        request.payload_params.return_value = {'domains': ['www.example.org']}
        self.module.upsert(request)
        self.module._service.update_existing.assert_called_once_with('6ff9418a-a4d7-5964-b0a3-78f920426989', ['www.example.org'])

    @patch.dict('os.environ', {}, clear=True)
    def test_vault_token_configuration(self):
        self.module.config = {'credentials': {'vault': {
            'uri': 'https://vault.example.org', 'key_name': 'certificates', 'token': 'example-token'}}}
        conf = vault_settings(self.module.config)
        self.assertIsNone(conf['role_id'])
        self.assertIsNone(conf['secret_id'])
        self.assertEqual(conf['token'], 'example-token')

    @patch.dict('os.environ', {}, clear=True)
    def test_vault_approle_configuration(self):
        self.module.config = {'credentials': {'vault': {
            'uri': 'https://vault.example.org', 'key_name': 'certificates',
            'role_id': 'example-role', 'secret_id': 'example-secret'}}}
        conf = vault_settings(self.module.config)
        self.assertIsNone(conf['token'])
        self.assertEqual(conf['role_id'], 'example-role')

    def test_hvac_kv2_signatures(self):
        client = hvac.Client(url='https://vault.example.org')
        for name, args in [('create_or_update_secret', ('key/6ff9418a-a4d7-5964-b0a3-78f920426989/example.org', {})),
                           ('patch', ('key/6ff9418a-a4d7-5964-b0a3-78f920426989/example.org', {})),
                           ('read_secret_version', ('key/6ff9418a-a4d7-5964-b0a3-78f920426989/example.org',)),
                           ('list_secrets', ('key/42',)),
                           ('read_secret_metadata', ('key/6ff9418a-a4d7-5964-b0a3-78f920426989/example.org',)),
                           ('destroy_secret_versions', ('key/6ff9418a-a4d7-5964-b0a3-78f920426989/example.org', [1]))]:
            inspect.signature(getattr(client.secrets.kv, name)).bind(*args)
        inspect.signature(client.auth.approle.login).bind('role', 'secret')

    def test_redis_adapter_signatures(self):
        for name, args in [('get_key', ('key',)), ('set_key', ('key', 'value')),
                           ('del_key', ('key',)), ('hget_key', ('key', 'obj')),
                           ('srem', ('server', 'key')), ('keys', ('cert:*',))]:
            inspect.signature(getattr(DWhoAdapterRedis, name)).bind(None, *args)
        inspect.signature(DWhoAdapterRedis.sort).bind(None, 'server', by='*->ts')

    def test_real_sonicprobe_locks(self):
        lock = RWLock()
        self.assertTrue(lock.acquire_read(1))
        lock.release()
        self.assertTrue(lock.acquire_write(1))
        lock.release()
        certificate_ids = ListLock()
        self.assertTrue(certificate_ids.try_acquire('6ff9418a-a4d7-5964-b0a3-78f920426989'))
        self.assertTrue(certificate_ids.try_acquire('6ff9418a-a4d7-5964-b0a3-78f920426989'))  # Same-thread reentrancy.
        result = []
        worker = threading.Thread(target=lambda: result.append(certificate_ids.try_acquire('6ff9418a-a4d7-5964-b0a3-78f920426989')))
        worker.start()
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result, [False])
        certificate_ids.release('6ff9418a-a4d7-5964-b0a3-78f920426989')
        certificate_ids.release('6ff9418a-a4d7-5964-b0a3-78f920426989')

    def connector_config(self):
        path = Path(__file__).resolve().parents[2] / 'etc/certlord/certbot-httpreq.yml.example'
        return yaml.safe_load(path.read_text())

    @patch('acme_http_connector.connector.requests.post')
    def test_certbot_plugin_payload_matches_save_api(self, post):
        post.return_value.status_code = 200
        # Exercise the installed adapter and core, not a private plugin constant.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / 'plugin.yml'
            config.write_text(yaml.safe_dump(self.connector_config()))
            cert, key = root / 'cert.pem', root / 'key.pem'
            # Schema-sized strings test the wire contract, not PEM validity.
            cert.write_text('C' * 1200)
            key.write_text('K' * 1200)
            installer = Installer(SimpleNamespace(test_config=str(config)), 'test')
            installer.prepare()
            installer.deploy_cert('www.example.org', str(cert), str(key), None, None)
        self.assertEqual(post.call_args.args, ('http://127.0.0.1:8666/api/ssl-certs/save',))
        payload = post.call_args.kwargs['json']
        self.assertEqual(payload, {'domain': 'www.example.org', 'cert': 'C' * 1200,
                                   'key': 'K' * 1200, 'chain': ''})
        request = Mock()
        request.payload_params.return_value = payload
        request.get_headers.return_value = {'X-CertLord-Issuance': 'a' * 64}
        self.module.save(request)
        self.module._service.save.assert_called_once_with(payload, 'a' * 64)
        post.return_value.raise_for_status.assert_called_once()

    @patch('acme_http_connector.connector.requests.put')
    @patch('acme_http_connector.connector.requests.delete')
    def test_connector_challenge_publication_and_cleanup_match_routes(self, delete, put):
        put.return_value.status_code = delete.return_value.status_code = 200
        connector = HTTPConnector(self.connector_config())
        token = 'a' * 43
        path = '/.well-known/acme-challenge/' + token
        validation = token + '.' + 'b' * 43
        connector.publish(path, validation)
        self.assertEqual(urlsplit(put.call_args.args[0]).path, path)
        self.assertEqual(put.call_args.kwargs['json'], validation)
        module = LetsEncryptModule()
        module._api_access = Mock()
        module.lock_timeout = 1
        module.challenge_ttl = 3600
        module._redis = Mock()
        request = Mock()
        request.query_params.return_value = {'challenge': token}
        request.get_path.return_value = path
        request.payload_params.return_value = put.call_args.kwargs['json']
        module.well_known_put(request)
        module._redis.set_key.assert_called_once_with(path, validation, expire=3600)
        connector.cleanup(path)
        self.assertEqual(delete.call_args.args, (put.call_args.args[0],))
        module.well_known_delete(request)
        module._redis.del_key.assert_called_once_with(path)
        put.return_value.raise_for_status.assert_called_once()
        delete.return_value.raise_for_status.assert_called_once()

    def test_acme_invalid_payload_has_http_error(self):
        request = Mock()
        request.query_params.return_value = {'challenge': 'a' * 43}
        request.payload_params.return_value = {'unexpected': 'json'}
        with self.assertRaises(HttpReqErrJson) as caught:
            module = LetsEncryptModule()
            module._api_access = Mock()
            module.well_known_put(request)
        self.assertEqual(caught.exception.code, 400)
