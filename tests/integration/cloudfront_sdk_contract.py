#!/usr/bin/env python3
"""Offline AWS SDK contract: signed service clients with all API calls stubbed.

No live provider acceptance, IAM enforcement or TLS propagation is implied.
"""
from contextlib import ExitStack, redirect_stdout
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

import boto3
from botocore.stub import Stubber

from certlord.cloudfront import preflight

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from import_fixture import material


def exercise(denied=False):
    plan = {'account_id': '123456789012', 'distribution_id': 'E123EXAMPLE',
            'certificate_arn': 'arn:aws:acm:us-east-1:123456789012:certificate/11111111-2222-3333-4444-555555555555',
            'domain': 'import.example.test'}
    pem = material(offset=1)['cert']
    expected_endpoints = {'sts': 'https://sts.us-east-1.amazonaws.com',
                          'acm': 'https://acm.us-east-1.amazonaws.com',
                          'cloudfront': 'https://cloudfront.amazonaws.com'}
    # Explicit synthetic credentials prevent SDK credential-provider/network access.
    session = boto3.Session(aws_access_key_id='synthetic', aws_secret_access_key='synthetic',
                            region_name='us-east-1')
    stubs = []
    services = []
    with ExitStack() as stack, tempfile.TemporaryDirectory() as directory:
        class StubbedSession:
            def client(self, service, **kwargs):
                assert service not in services and service in expected_endpoints
                services.append(service)
                assert kwargs['endpoint_url'] == expected_endpoints[service]
                assert kwargs['verify'] is True and kwargs['region_name'] == 'us-east-1'
                assert kwargs['config'].ignore_configured_endpoint_urls is True
                assert kwargs['config'].retries['total_max_attempts'] == 1
                client = session.client(service, **kwargs)
                assert client.meta.endpoint_url == expected_endpoints[service]
                stub = stack.enter_context(Stubber(client))
                stubs.append(stub)
                if service == 'sts':
                    stub.add_response('get_caller_identity', {'Account': plan['account_id'],
                        'Arn': 'arn:aws:iam::123456789012:role/synthetic', 'UserId': 'synthetic'}, {})
                elif service == 'cloudfront':
                    if denied:
                        stub.add_client_error('get_distribution', service_error_code='AccessDenied',
                            service_message='private provider detail', http_status_code=403,
                            expected_params={'Id': plan['distribution_id']})
                    else:
                        stub.add_response('get_distribution', {'Distribution': {
                            'Id': plan['distribution_id'], 'ARN': preflight.distribution_arn(plan),
                            'Status': 'Deployed', 'LastModifiedTime': datetime.now(timezone.utc),
                            'InProgressInvalidationBatches': 0, 'DomainName': 'synthetic.cloudfront.net',
                            'DistributionConfig': {'CallerReference': 'synthetic',
                                'Origins': {'Quantity': 1, 'Items': [{'Id': 'origin', 'DomainName': 'origin.example.test'}]},
                                'DefaultCacheBehavior': {'TargetOriginId': 'origin', 'ViewerProtocolPolicy': 'https-only'},
                                'Comment': 'synthetic', 'Enabled': True,
                                'Aliases': {'Quantity': 1, 'Items': [plan['domain']]},
                                'ViewerCertificate': {'ACMCertificateArn': plan['certificate_arn'],
                                                      'SSLSupportMethod': 'sni-only'}}}},
                            {'Id': plan['distribution_id']})
                elif not denied:
                    stub.add_response('describe_certificate', {'Certificate': {
                        'CertificateArn': plan['certificate_arn'], 'Type': 'IMPORTED', 'Status': 'ISSUED',
                        'KeyAlgorithm': 'EC_prime256v1', 'SubjectAlternativeNames': [plan['domain']],
                        'InUseBy': [preflight.distribution_arn(plan)]}}, {'CertificateArn': plan['certificate_arn']})
                    stub.add_response('get_certificate', {'Certificate': pem},
                                      {'CertificateArn': plan['certificate_arn']})
                return client

        config = Path(directory) / 'plan.json'
        config.write_text(json.dumps(plan))
        output = io.StringIO()
        with patch.object(boto3, 'Session', return_value=StubbedSession()), \
                patch.object(preflight.logging, 'disable'), redirect_stdout(output), \
                patch.dict('os.environ', {'AWS_ENDPOINT_URL': 'http://untrusted.invalid'}):
            code = preflight.main(['live', '--config', str(config), '--profile', 'synthetic'])
        result = json.loads(output.getvalue())
        assert services == ['sts', 'acm', 'cloudfront']
        for stub in stubs:
            stub.assert_no_pending_responses()
        assert 'private provider detail' not in output.getvalue()
        assert 'BEGIN CERTIFICATE' not in output.getvalue()
        assert code == int(denied)
        if denied:
            assert result == {'status': 'failed', 'error_code': 'provider_read_failed'}
        else:
            assert result['status'] == 'passed' and result['tls_verified'] is False
    print('PASS: offline-sdk-' + ('denied-and-redacted' if denied else 'scoped-read-snapshot'))


def exercise_import(outcome):
    from certlord.cloudfront.aws import AwsProvider
    from certlord.cloudfront.config import JobError
    from certlord.cloudfront.ledger import Ledger
    from certlord.cloudfront.material import current_material, material_digest
    from certlord.cloudfront.writer import Renewal
    from certlord.services.deployment import certificate_generation
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    import threading
    record = dict(material(offset=1), status='generated')
    old = dict(material(offset=1), status='generated')
    generation = certificate_generation(record)
    _, candidate, leaf = current_material(lambda: record, generation, record['domain'])
    arn = 'arn:aws:acm:us-east-1:123456789012:certificate/11111111-2222-3333-4444-555555555555'
    session = boto3.Session(aws_access_key_id='synthetic', aws_secret_access_key='synthetic', region_name='us-east-1')
    provider = AwsProvider({'certificate_arn': arn}, session)
    def snapshot(pem):
        value = x509.load_pem_x509_certificate(pem['cert'].encode())
        return {'leaf': value, 'fingerprint': value.fingerprint(hashes.SHA256()).hex(),
                'host': 'synthetic.cloudfront.net', 'material_sha256': material_digest(value, pem['chain'])}
    with tempfile.TemporaryDirectory() as directory, Stubber(provider.acm) as stub:
        # Strict exact expected params fail if ARN disappears, tags or any new
        # option is introduced. Every SDK network request is intercepted.
        expected = {'CertificateArn': arn, 'Certificate': candidate['cert'].encode(),
                    'PrivateKey': candidate['key'].encode()}
        if candidate['chain']: expected['CertificateChain'] = candidate['chain'].encode()
        if outcome == 'denied':
            stub.add_client_error('import_certificate', service_error_code='AccessDeniedException',
                service_message='private provider detail', http_status_code=403, expected_params=expected)
        else:
            stub.add_response('import_certificate', {'CertificateArn': arn if outcome == 'accepted' else arn + 'wrong'}, expected)
        ledger = Ledger(directory)
        try:
            with patch.object(provider, 'read', side_effect=[snapshot(old), snapshot(old), snapshot(record)]):
                engine = Renewal({'target': {'certificate_arn': arn, 'domain': record['domain']},
                    'poll_interval': 1, 'propagation_timeout': 5}, 'a' * 64, ledger, lambda: record,
                    provider, lambda _record, seen: {'status': 'verified',
                        'observed_fingerprint_sha256': seen['fingerprint']}, threading.Event())
                if outcome == 'accepted':
                    assert engine.run(generation)['status'] == 'verified'
                else:
                    try:
                        engine.run(generation)
                    except JobError as error:
                        assert str(error) == 'import_outcome_uncertain'
                    else:
                        raise AssertionError('Uncertain receipt was accepted')
                    assert ledger.read(arn)['state'] == 'quarantined'
            stub.assert_no_pending_responses()
        finally:
            ledger.close(); provider.close()
    print('PASS: offline-sdk-existing-arn-import-' + outcome)


if __name__ == '__main__':
    exercise()
    exercise(denied=True)
    for outcome in ('accepted', 'denied', 'wrong-receipt'):
        exercise_import(outcome)
