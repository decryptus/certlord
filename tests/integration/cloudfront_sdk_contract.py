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

import cloudfront_preflight as preflight

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


if __name__ == '__main__':
    exercise()
    exercise(denied=True)
