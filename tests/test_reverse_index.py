import unittest
from unittest.mock import Mock

from certlord.adapters.pending import PendingCertificates
from certlord.services.certificates import CertificateService
from certlord.classes.ssl_cert_auto_object import SslCertAutoObject


class ReverseIndexTests(unittest.TestCase):
    def test_upsert_mutates_only_requested_site(self):
        backend = Mock()
        backend.lock_timeout = 1
        backend.bound_domains.return_value = []
        backend.fetch_acerts.return_value = SslCertAutoObject('6ff9418a-a4d7-5964-b0a3-78f920426989')
        backend.list_certificates.return_value = []
        backend.get_certificate_ids_for_domain.return_value = {'certificate_ids': ['153e7019-20d1-563c-bbfd-0ce49b1f14f5']}
        backend.duplicate_certificate.return_value = True
        CertificateService(backend).upsert('6ff9418a-a4d7-5964-b0a3-78f920426989', ['one.example.test'])
        backend.change_certificate_id.assert_called_once_with('one.example.test', '6ff9418a-a4d7-5964-b0a3-78f920426989', True)
        backend.set_certificate_ids_for_domain.assert_not_called()

    def test_mutation_requires_one_authoritative_redis(self):
        redis = Mock()
        redis.servers = {}
        with self.assertRaises(RuntimeError):
            PendingCertificates(redis).change_certificate_id('one.example.test', '6ff9418a-a4d7-5964-b0a3-78f920426989', True)
