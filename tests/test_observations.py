"""Supervision reports facts without leaking material or hiding collection failures."""
import copy
import json
import unittest
from unittest.mock import Mock
from cryptography import x509
from certlord.services.certificates import CertificateService
from certlord.services.observations import certificate_observation, prometheus_metrics
from certlord.ports.certificates import StorageError, StorageNotFound
from certlord.modules.ssl_certs import SslCertsModule
from import_fixture import material

IDENTITY = '12345678-1111-4111-8111-111111111111'
DOMAIN = 'import.example.test'


class ObservationTests(unittest.TestCase):
    def project(self, record, pending=None):
        return certificate_observation(IDENTITY, DOMAIN, record, 7, pending or {})

    def test_both_origins_use_actual_leaf_not_cached_metadata(self):
        record = material()
        expected = x509.load_pem_x509_certificate(record['cert'].encode()).not_valid_after_utc
        for fields, origin in (({'vendor':'letsencrypt'}, 'acme'),
                               ({'origin':'external', 'renewal_owner':'external'}, 'external')):
            with self.subTest(origin=origin):
                record.update(fields, not_after='wrong', fingerprint_sha256='wrong')
                value = self.project(record)
                self.assertEqual(value['origin'], origin)
                self.assertEqual(value['not_after_timestamp_seconds'], expected.timestamp())
                self.assertEqual(value['not_after'], expected.isoformat())
                self.assertEqual(value['material_state'], 'readable')
                self.assertNotEqual(value['fingerprint_sha256'], 'wrong')

    def test_expired_and_future_material_remain_observable(self):
        for offset in (-3, 3):
            value = self.project(material(offset=offset))
            self.assertEqual(value['material_state'], 'readable')
            self.assertIsNotNone(value['not_after_timestamp_seconds'])

    def test_missing_and_malformed_material_have_no_fake_expiry(self):
        for pem, state in ((None,'missing'), ('broken','invalid'), ('é','invalid'),
                           ('x'*65537,'invalid'), (123,'invalid')):
            value = self.project({'cert':pem})
            self.assertEqual(value['material_state'], state)
            self.assertIsNone(value['not_after_timestamp_seconds'])
            self.assertIsNone(value['fingerprint_sha256'])

    def test_projection_is_secret_free_and_does_not_mutate_record(self):
        record = dict(material(), status='secret-status', credentials='secret-token',
                      error='secret-error', renewal_owner='secret-owner')
        original = copy.deepcopy(record)
        value = self.project(record, {'status':'secret-action'})
        rendered = json.dumps(value)
        for forbidden in ('PRIVATE KEY', 'BEGIN CERTIFICATE', 'secret-'):
            self.assertNotIn(forbidden, rendered)
        self.assertEqual(record, original)
        self.assertEqual(value['version'], 7)

    def test_pending_retries_are_not_lifetime_failures(self):
        pending = {'status':'renew','retry':2,'last_retry':'2026-10-02 19:00:00'}
        value = self.project({'vendor':'letsencrypt'}, pending)
        self.assertEqual(value['issuance_retry_count'], 2)
        self.assertEqual(value['last_issuance_retry_at'], '2026-10-02T19:00:00+00:00')
        for record, state in (({'origin':'external'}, 'renew'), ({'vendor':'letsencrypt'}, 'delete'),
                              ({'vendor':'letsencrypt'}, 'exists')):
            value = self.project(record, dict(pending, status=state))
            self.assertIsNone(value['issuance_retry_count'])
            self.assertIsNone(value['last_issuance_retry_at'])

    def test_corrupt_retry_metadata_does_not_become_zero(self):
        for retry in (True, -1, '2', 1.5):
            with self.subTest(retry=retry), self.assertRaises(ValueError):
                self.project({'vendor':'letsencrypt'}, {'status':'renew','retry':retry})
        with self.assertRaises(ValueError):
            self.project({'vendor':'letsencrypt'}, {'status':'renew','last_retry':'bad-date'})

    def backend(self):
        backend = Mock()
        backend.get_certificate_ids.return_value = [IDENTITY]
        backend.list_certificates.return_value = [DOMAIN]
        backend.certificate_snapshot.return_value = ({'vendor':'letsencrypt'}, 7)
        backend.fetch_acerts.return_value.get_obj.return_value = {}
        return backend

    def test_reads_are_fresh_and_do_not_write(self):
        backend = self.backend()
        service = CertificateService(backend)
        first = service.observations()
        backend.certificate_snapshot.return_value = (dict(material(), origin='external'),8)
        second = service.observations()
        self.assertEqual(first['certificates'][0]['version'],7)
        self.assertEqual(second['certificates'][0]['version'],8)
        self.assertLessEqual(first['completed_timestamp_seconds'], second['completed_timestamp_seconds'])
        allowed = {'LOCK.acquire_read','LOCK.release','get_certificate_ids','list_certificates',
                   'certificate_snapshot','fetch_acerts','fetch_acerts().get_obj'}
        self.assertTrue(all(call[0] in allowed for call in backend.mock_calls))

    def test_outage_propagates_but_confirmed_removal_is_skipped(self):
        backend = self.backend()
        service = CertificateService(backend)
        backend.certificate_snapshot.side_effect = StorageError('unavailable')
        with self.assertRaises(StorageError):
            service.observations()
        backend.certificate_snapshot.side_effect = StorageNotFound()
        self.assertEqual(service.observations()['certificates'], [])
        backend.certificate_snapshot.side_effect = None
        backend.fetch_acerts.side_effect = RuntimeError('Redis unavailable')
        with self.assertRaises(RuntimeError):
            service.metrics()

    def test_prometheus_has_gauges_without_false_expiry_or_sensitive_labels(self):
        record = self.project({'origin':'external'})
        snapshot = {'completed_timestamp_seconds':1234.5,'certificates':[record]}
        output = prometheus_metrics(snapshot)
        self.assertIn('# TYPE certlord_certificates_observed gauge\n',output)
        self.assertIn('certlord_certificates_observed 1\n',output)
        self.assertNotIn('certlord_certificate_not_after_timestamp_seconds{',output)
        self.assertNotIn('certlord_certificate_issuance_retry_count{',output)
        self.assertNotIn(DOMAIN,output)
        record = self.project(dict(material(),vendor='letsencrypt'), {'status':'renew','retry':2})
        snapshot['certificates'] = [record]
        output = prometheus_metrics(snapshot)
        self.assertIn('certlord_certificate_not_after_timestamp_seconds{certificate_id="'+IDENTITY+'"}',output)
        self.assertIn('certlord_certificate_issuance_retry_count{certificate_id="'+IDENTITY+'"} 2\n',output)
        self.assertTrue(output.endswith('\n'))

    def test_http_authorizes_before_collecting_and_sets_uncacheable_formats(self):
        module = object.__new__(SslCertsModule)
        module._authorize = Mock()
        module._service = Mock()
        module._service.observations.return_value = {'certificates':[]}
        module._service.metrics.return_value = '# fixture\n'
        request = Mock()
        response = module.observations(request)
        module._authorize.assert_called_once_with(request, 'read')
        self.assertEqual(json.loads(response.data), {'certificates':[]})
        self.assertEqual(response.get_header('Cache-control'), 'no-store')
        response = module.metrics(request)
        self.assertEqual(response.data, '# fixture\n')
        self.assertEqual(response.get_header('Content-type'), 'text/plain; version=0.0.4; charset=utf-8')
        module._service.reset_mock()
        module._authorize.side_effect = RuntimeError('denied')
        for method in (module.observations, module.metrics):
            with self.assertRaises(RuntimeError):
                method(request)
        self.assertEqual(module._service.mock_calls, [])
