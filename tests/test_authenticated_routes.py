"""Registration authenticates protected bodies without changing local/public routes."""
import copy
import unittest
from unittest import mock
from certlord.modules.route_auth import authenticated_routes
from certlord.modules.ssl_certs import SslCertsModule
from certlord.modules.letsencrypt import LetsEncryptModule
from dwho.classes.modules import DWhoModuleBase


class AuthenticatedRoutesTests(unittest.TestCase):
    def test_default_backend_protects_routes_without_mutating_configuration(self):
        config = {'modules': {'example': {'routes': {'a': {'handler': 'create', 'auth': False},
                  'b': {'handler': 'read', 'auth': ['operator']}}}}}
        original = copy.deepcopy(config)
        result = authenticated_routes(config, 'example')
        self.assertEqual(config, original)
        self.assertIs(result['modules']['example']['routes']['a']['auth'], True)
        self.assertEqual(result['modules']['example']['routes']['b']['auth'], ['operator'])

    def test_local_backend_and_public_handler_keep_their_registration(self):
        config = {'api_authentication': {'backend': 'local'}, 'modules': {'example': {'routes': {
            'public': {'handler': 'well_known_get'}, 'write': {'handler': 'create'}}}}}
        self.assertIs(authenticated_routes(config, 'example'), config)
        config['api_authentication']['backend'] = 'httpdis'
        result = authenticated_routes(config, 'example', ('well_known_get',))
        self.assertNotIn('auth', result['modules']['example']['routes']['public'])
        self.assertIs(result['modules']['example']['routes']['write']['auth'], True)

    def test_both_modules_pass_protected_routes_to_framework_registration(self):
        for module in (SslCertsModule, LetsEncryptModule):
            config = {'modules': {module.MODULE_NAME: {'routes': {'write': {'handler': 'create'}}}}}
            with mock.patch.object(DWhoModuleBase, 'init') as initialize:
                module().init(config)
            routes = initialize.call_args.args[0]['modules'][module.MODULE_NAME]['routes']
            self.assertIs(routes['write']['auth'], True)
