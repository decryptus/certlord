"""Standard AWS endpoints only; no automatic retry of an ambiguous write."""
from certlord.cloudfront.config import JobError, require
from certlord.cloudfront.preflight import inspect_target
from certlord.cloudfront.material import material_digest


class AwsProvider:
    def __init__(self, plan, session):
        from botocore.config import Config
        self.plan = plan
        config = Config(connect_timeout=3, read_timeout=5,
                        retries={'mode': 'standard', 'total_max_attempts': 1},
                        ignore_configured_endpoint_urls=True)
        self.clients = []
        try:
            for service, endpoint in (('sts', 'https://sts.us-east-1.amazonaws.com'),
                                      ('acm', 'https://acm.us-east-1.amazonaws.com'),
                                      ('cloudfront', 'https://cloudfront.amazonaws.com')):
                self.clients.append(session.client(service, region_name='us-east-1',
                    endpoint_url=endpoint, verify=True, config=config))
            self.sts, self.acm, self.cloudfront = self.clients
        except Exception:
            self.close()
            raise JobError('provider_initialization_failed') from None

    def close(self):
        for client in self.clients:
            client.close()

    def read(self):
        try:
            report, leaf, host, chain = inspect_target(self.plan, self.sts, self.acm,
                self.cloudfront, details=True, allow_propagating=True)
            return {'fingerprint': report['acm_fingerprint_sha256'], 'leaf': leaf, 'host': host,
                    'material_sha256': material_digest(leaf, chain)}
        except Exception:
            raise JobError('provider_preflight_failed') from None

    def reimport(self, material):
        # Existing ARN is mandatory. No tags, creation fallback or SDK retries.
        request = {'CertificateArn': self.plan['certificate_arn'],
                   'Certificate': material['cert'].encode(), 'PrivateKey': material['key'].encode()}
        if material['chain']:
            request['CertificateChain'] = material['chain'].encode()
        response = self.acm.import_certificate(**request)
        require(response.get('CertificateArn') == self.plan['certificate_arn'], 'unexpected_import_receipt')
