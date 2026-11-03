"""Offline qualification cases; no AWS account or provider calls are involved."""
from contextlib import redirect_stdout
from copy import deepcopy
from datetime import timedelta
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from import_fixture import material


from certlord.cloudfront import preflight


class CloudFrontPreflightTests(unittest.TestCase):
    def setUp(self):
        self.plan = {'account_id': '123456789012', 'distribution_id': 'E123EXAMPLE',
                     'certificate_arn': 'arn:aws:acm:us-east-1:123456789012:certificate/11111111-2222-3333-4444-555555555555',
                     'domain': 'import.example.test'}
        self.pem = material(offset=1)['cert']
        leaf = x509.load_pem_x509_certificate(self.pem.encode())
        self.now = leaf.not_valid_before_utc + timedelta(hours=1)
        self.expected_fingerprint = leaf.fingerprint(hashes.SHA256()).hex()
        self.sts = Mock(spec=['get_caller_identity'])
        self.sts.get_caller_identity.return_value = {'Account': self.plan['account_id']}
        self.acm = Mock(spec=['describe_certificate', 'get_certificate'])
        self.detail = {'CertificateArn': self.plan['certificate_arn'], 'Type': 'IMPORTED',
                       'Status': 'ISSUED', 'KeyAlgorithm': 'EC_prime256v1',
                       'SubjectAlternativeNames': [self.plan['domain']],
                       'InUseBy': [preflight.distribution_arn(self.plan)]}
        self.acm.describe_certificate.return_value = {'Certificate': self.detail}
        self.acm.get_certificate.return_value = {'Certificate': self.pem}
        self.cloudfront = Mock(spec=['get_distribution'])
        self.distribution = {'ARN': preflight.distribution_arn(self.plan),
            'Id': self.plan['distribution_id'], 'Status': 'Deployed', 'DistributionConfig': {
                'Enabled': True, 'Aliases': {'Quantity': 1, 'Items': [self.plan['domain']]},
                'ViewerCertificate': {'ACMCertificateArn': self.plan['certificate_arn'],
                                      'SSLSupportMethod': 'sni-only'}}}
        self.cloudfront.get_distribution.return_value = {'Distribution': self.distribution}

    def inspect(self):
        return preflight.inspect_target(self.plan, self.sts, self.acm, self.cloudfront, self.now)

    def test_valid_snapshot_reads_only_exact_resources_without_claiming_live_tls(self):
        result = self.inspect()
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(result['acm_fingerprint_sha256'], self.expected_fingerprint)
        self.assertEqual(result['domain'], self.plan['domain'])
        for field in ('tls_verified', 'write_permissions_verified', 'global_propagation_verified'):
            self.assertIs(result[field], False)
        self.cloudfront.get_distribution.assert_called_once_with(Id=self.plan['distribution_id'])
        self.acm.describe_certificate.assert_called_once_with(CertificateArn=self.plan['certificate_arn'])
        self.acm.get_certificate.assert_called_once_with(CertificateArn=self.plan['certificate_arn'])
        text = json.dumps(result)
        self.assertNotIn('BEGIN CERTIFICATE', text)
        self.assertNotIn(self.plan['account_id'], text)
        self.assertNotIn(self.plan['distribution_id'], text)

    def test_invalid_plan_is_rejected_before_any_provider_call(self):
        for key, value in (('account_id', 'bad'), ('distribution_id', '*'),
                           ('certificate_arn', self.plan['certificate_arn'].replace('us-east-1', 'eu-west-1')),
                           ('domain', '*.example.test'), ('domain', 'UPPER.example.test'),
                           ('private_key', 'do-not-accept-material')):
            with self.subTest(key=key, value=value):
                plan = dict(self.plan, **{key: value})
                with self.assertRaises(preflight.PreflightError):
                    preflight.inspect_target(plan, self.sts, self.acm, self.cloudfront, self.now)
        for client in (self.sts, self.acm, self.cloudfront):
            self.assertEqual(client.mock_calls, [])

    def test_wrong_caller_account_stops_before_reading_resources(self):
        self.sts.get_caller_identity.return_value['Account'] = '000000000000'
        with self.assertRaisesRegex(preflight.PreflightError, '^wrong_account$'):
            self.inspect()
        self.assertEqual(self.acm.mock_calls + self.cloudfront.mock_calls, [])

    def test_wrong_distribution_or_viewer_certificate_stops_before_acm(self):
        for kind in ('arn', 'id', 'viewer', 'iam', 'default', 'dedicated_ip'):
            with self.subTest(kind=kind):
                candidate = deepcopy(self.distribution)
                viewer = candidate['DistributionConfig']['ViewerCertificate']
                if kind == 'arn': candidate['ARN'] += '-wrong'
                if kind == 'id': candidate['Id'] += 'WRONG'
                if kind == 'viewer': viewer['ACMCertificateArn'] += '-wrong'
                if kind == 'iam': viewer['IAMCertificateId'] = 'legacy'
                if kind == 'default': viewer['CloudFrontDefaultCertificate'] = True
                if kind == 'dedicated_ip': viewer['SSLSupportMethod'] = 'vip'
                self.cloudfront.get_distribution.return_value = {'Distribution': candidate}
                with self.assertRaises(preflight.PreflightError): self.inspect()
        self.assertEqual(self.acm.mock_calls, [])

    def test_shared_and_unattached_certificates_are_refused(self):
        for usages in ([], [preflight.distribution_arn(self.plan), 'another-resource']):
            with self.subTest(usages=usages):
                self.detail['InUseBy'] = usages
                with self.assertRaisesRegex(preflight.PreflightError, '^shared_or_unattached_certificate$'):
                    self.inspect()
        self.acm.get_certificate.assert_not_called()

    def test_disabled_staging_or_propagating_distribution_is_not_qualified(self):
        for field, value in (('Enabled', False), ('Staging', True), ('Status', 'InProgress')):
            with self.subTest(field=field):
                candidate = deepcopy(self.distribution)
                (candidate if field == 'Status' else candidate['DistributionConfig'])[field] = value
                self.cloudfront.get_distribution.return_value = {'Distribution': candidate}
                with self.assertRaisesRegex(preflight.PreflightError, '^distribution_not_ready$'):
                    self.inspect()

    def test_multiple_aliases_and_managed_certificates_are_outside_initial_scope(self):
        self.distribution['DistributionConfig']['Aliases']['Items'].append('other.example.test')
        with self.assertRaisesRegex(preflight.PreflightError, '^unsupported_aliases$'):
            self.inspect()
        self.distribution['DistributionConfig']['Aliases']['Items'].pop()
        for field, value in (('Type', 'AMAZON_ISSUED'), ('Status', 'EXPIRED'),
                             ('CertificateKeyPairOrigin', 'AWS_MANAGED')):
            with self.subTest(field=field):
                saved = dict(self.detail)
                self.detail[field] = value
                with self.assertRaisesRegex(preflight.PreflightError, '^unsupported_certificate_type$'):
                    self.inspect()
                self.detail.clear()
                self.detail.update(saved)

    def test_returned_certificate_identity_and_real_leaf_names_must_match(self):
        for field, value in (('CertificateArn', 'unexpected'),
                             ('SubjectAlternativeNames', ['other.example.test'])):
            with self.subTest(field=field):
                saved = dict(self.detail)
                self.detail[field] = value
                with self.assertRaises(preflight.PreflightError): self.inspect()
                self.detail.clear()
                self.detail.update(saved)
        self.acm.get_certificate.return_value['Certificate'] = material(('other.example.test',), offset=1)['cert']
        with self.assertRaisesRegex(preflight.PreflightError, '^unsupported_certificate_names$'):
            self.inspect()

    def test_invalid_appended_or_ca_material_is_refused(self):
        for pem in ('invalid secret', self.pem + self.pem, self.pem + 'PRIVATE KEY',
                    material(offset=1, ca=True)['cert']):
            with self.subTest(length=len(pem)):
                self.acm.get_certificate.return_value['Certificate'] = pem
                with self.assertRaisesRegex(preflight.PreflightError, '^invalid_certificate$'):
                    self.inspect()

    def test_key_metadata_and_certificate_validity_are_checked(self):
        self.detail['KeyAlgorithm'] = 'RSA_2048'
        with self.assertRaisesRegex(preflight.PreflightError, '^key_algorithm_mismatch$'):
            self.inspect()
        self.detail['KeyAlgorithm'] = 'EC_prime256v1'
        leaf = x509.load_pem_x509_certificate(self.pem.encode())
        for now, code in ((leaf.not_valid_before_utc - timedelta(seconds=1), 'certificate_not_valid'),
                          (leaf.not_valid_after_utc, 'certificate_not_valid'),
                          (leaf.not_valid_after_utc - timedelta(hours=24), 'certificate_expires_too_soon')):
            with self.subTest(code=code):
                self.now = now
                with self.assertRaisesRegex(preflight.PreflightError, '^' + code + '$'):
                    self.inspect()

    def test_generated_policy_grants_only_scoped_reads(self):
        policy = preflight.read_policy(self.plan)
        statements = policy['Statement']
        self.assertEqual({action for item in statements for action in item['Action']},
                         {'acm:GetCertificate', 'acm:DescribeCertificate', 'cloudfront:GetDistribution'})
        self.assertEqual({item['Resource'] for item in statements},
                         {self.plan['certificate_arn'], preflight.distribution_arn(self.plan)})
        self.assertNotIn('*', json.dumps(policy))

    def test_cloudfront_key_boundaries_are_stricter_than_acm_storage(self):
        for key, algorithm in ((rsa.generate_private_key(public_exponent=65537, key_size=2048), 'RSA_2048'),
                               (ec.generate_private_key(ec.SECP384R1()), 'EC_secp384r1'),
                               (ec.generate_private_key(ec.SECP521R1()), 'EC_secp521r1')):
            with self.subTest(algorithm=algorithm):
                self.acm.get_certificate.return_value['Certificate'] = material(offset=1, key=key)['cert']
                self.detail['KeyAlgorithm'] = algorithm
                if algorithm == 'EC_secp521r1':
                    with self.assertRaisesRegex(preflight.PreflightError, '^unsupported_key_algorithm$'):
                        self.inspect()
                else:
                    self.assertEqual(self.inspect()['key_algorithm'], algorithm)

    def test_cli_offline_modes_and_redacted_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / 'plan.json'
            config.write_text(json.dumps(self.plan))
            for mode in ('check-config', 'policy'):
                output = io.StringIO()
                with redirect_stdout(output), patch.object(preflight.logging, 'disable'), \
                        patch.object(preflight, 'live_report', side_effect=AssertionError('AWS contacted')):
                    self.assertEqual(preflight.main([mode, '--config', str(config)]), 0)
                    self.assertIsInstance(json.loads(output.getvalue()), dict)
            for error in (RuntimeError('private provider token'), ValueError('private response')):
                output = io.StringIO()
                fake_sdk = Mock()
                with redirect_stdout(output), patch.object(preflight.logging, 'disable'), \
                        patch.dict('sys.modules', {'boto3': fake_sdk}), \
                        patch.object(preflight, 'live_report', side_effect=error):
                    self.assertEqual(preflight.main(['live', '--config', str(config)]), 1)
                    self.assertEqual(json.loads(output.getvalue())['status'], 'failed')
                    self.assertNotIn('private', output.getvalue())
