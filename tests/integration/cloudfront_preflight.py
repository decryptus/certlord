#!/usr/bin/env python3
"""Contributor qualification tool: read-only AWS snapshot, not a deployer."""
import argparse
from datetime import datetime, timedelta, timezone
import json
import logging
from pathlib import Path
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa


class PreflightError(Exception):
    """Only fixed error codes may enter reports."""


def require(condition, code):
    if not condition:
        raise PreflightError(code)


def validate_plan(plan):
    fields = {'account_id', 'certificate_arn', 'distribution_id', 'domain'}
    require(isinstance(plan, dict) and set(plan) == fields
            and all(isinstance(value, str) for value in plan.values()), 'invalid_config')
    require(re.fullmatch(r'[0-9]{12}', plan['account_id']), 'invalid_account')
    require(re.fullmatch(r'[A-Z0-9]{1,32}', plan['distribution_id']), 'invalid_distribution')
    arn = r'arn:aws:acm:us-east-1:' + plan['account_id'] + r':certificate/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
    require(re.fullmatch(arn, plan['certificate_arn']), 'invalid_certificate_arn')
    domain = plan['domain']
    require(len(domain) <= 253 and len(domain.split('.')) >= 2 and all(
        re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
        for label in domain.split('.')), 'invalid_domain')
    return plan


def distribution_arn(plan):
    return 'arn:aws:cloudfront::%s:distribution/%s' % (plan['account_id'], plan['distribution_id'])


def read_policy(plan):
    validate_plan(plan)
    return {'Version': '2012-10-17', 'Statement': [
        {'Effect': 'Allow', 'Action': ['acm:DescribeCertificate', 'acm:GetCertificate'],
         'Resource': plan['certificate_arn']},
        {'Effect': 'Allow', 'Action': ['cloudfront:GetDistribution'],
         'Resource': distribution_arn(plan)}]}


def inspect_target(plan, sts, acm, cloudfront, now=None):
    """Read exactly the selected resources; return no account/role IDs or PEM."""
    validate_plan(plan)
    now = now or datetime.now(timezone.utc)
    require(sts.get_caller_identity()['Account'] == plan['account_id'], 'wrong_account')
    response = cloudfront.get_distribution(Id=plan['distribution_id'])
    distribution = response['Distribution']
    require(distribution['ARN'] == distribution_arn(plan)
            and distribution['Id'] == plan['distribution_id'], 'wrong_distribution')
    config = distribution['DistributionConfig']
    require(distribution['Status'] == 'Deployed' and config['Enabled'] is True
            and not config.get('Staging', False), 'distribution_not_ready')
    require(config['Aliases'] == {'Quantity': 1, 'Items': [plan['domain']]}, 'unsupported_aliases')
    viewer = config['ViewerCertificate']
    require(viewer.get('ACMCertificateArn') == plan['certificate_arn']
            and not viewer.get('IAMCertificateId')
            and viewer.get('CloudFrontDefaultCertificate', False) is False
            and viewer.get('SSLSupportMethod') == 'sni-only', 'wrong_viewer_certificate')
    detail = acm.describe_certificate(CertificateArn=plan['certificate_arn'])['Certificate']
    require(detail['CertificateArn'] == plan['certificate_arn'], 'wrong_certificate')
    require(detail['Type'] == 'IMPORTED' and detail['Status'] == 'ISSUED'
            and detail.get('CertificateKeyPairOrigin', 'CUSTOMER_PROVIDED') == 'CUSTOMER_PROVIDED',
            'unsupported_certificate_type')
    require(detail['InUseBy'] == [distribution_arn(plan)], 'shared_or_unattached_certificate')
    require(detail['SubjectAlternativeNames'] == [plan['domain']], 'unsupported_certificate_names')
    pem = acm.get_certificate(CertificateArn=plan['certificate_arn'])['Certificate']
    require(isinstance(pem, str) and len(pem) <= 32768 and re.fullmatch(
        r'-----BEGIN CERTIFICATE-----[\sA-Za-z0-9+/=]+-----END CERTIFICATE-----\s*', pem),
        'invalid_certificate')
    try:
        leaf = x509.load_pem_x509_certificate(pem.encode('ascii'))
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        require(len(names) == 1 and names.get_values_for_type(x509.DNSName) == [plan['domain']],
                'unsupported_certificate_names')
        try:
            require(not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca,
                    'invalid_certificate')
        except x509.ExtensionNotFound:
            pass
        key = leaf.public_key()
        if isinstance(key, rsa.RSAPublicKey) and key.key_size in (2048, 3072, 4096):
            algorithm = 'RSA_%d' % key.key_size
        elif isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name in ('secp256r1', 'secp384r1'):
            algorithm = {'secp256r1': 'EC_prime256v1', 'secp384r1': 'EC_secp384r1'}[key.curve.name]
        else:
            raise PreflightError('unsupported_key_algorithm')
        require(detail['KeyAlgorithm'] == algorithm, 'key_algorithm_mismatch')
        require(leaf.not_valid_before_utc <= now < leaf.not_valid_after_utc, 'certificate_not_valid')
        require(leaf.not_valid_after_utc - now > timedelta(hours=24), 'certificate_expires_too_soon')
    except PreflightError:
        raise
    except Exception:
        raise PreflightError('invalid_certificate') from None
    return {'status': 'passed', 'scope': 'read_only_snapshot', 'domain': plan['domain'],
            'observed_at': now.isoformat(), 'key_algorithm': algorithm,
            'certificate_not_after': leaf.not_valid_after_utc.isoformat(),
            'acm_fingerprint_sha256': leaf.fingerprint(hashes.SHA256()).hex(),
            'tls_verified': False, 'write_permissions_verified': False,
            'global_propagation_verified': False}


def live_report(plan, session):
    """Use standard AWS HTTPS endpoints; main sanitizes SDK exceptions."""
    from botocore.config import Config
    validate_plan(plan)
    config = Config(connect_timeout=3, read_timeout=5,
                    retries={'mode': 'standard', 'total_max_attempts': 1},
                    ignore_configured_endpoint_urls=True)
    clients = []
    try:
        for service, endpoint in (
                ('sts', 'https://sts.us-east-1.amazonaws.com'),
                ('acm', 'https://acm.us-east-1.amazonaws.com'),
                ('cloudfront', 'https://cloudfront.amazonaws.com')):
            clients.append(session.client(service, region_name='us-east-1',
                           endpoint_url=endpoint, verify=True, config=config))
        return inspect_target(plan, *clients)
    finally:
        for client in clients:
            client.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('check-config', 'policy', 'live'))
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--profile', help='Named AWS SDK credential profile for live mode')
    args = parser.parse_args(argv)
    # SDK debug logs can contain response bodies. This process emits only its report.
    logging.disable(logging.CRITICAL)
    try:
        with args.config.open() as stream:
            raw = stream.read(65537)
        require(len(raw) <= 65536, 'invalid_config')
        plan = validate_plan(json.loads(raw))
        if args.mode == 'policy':
            result = read_policy(plan)
        elif args.mode == 'check-config':
            result = {'status': 'passed', 'scope': 'configuration_only', 'aws_contacted': False}
        else:
            try:
                import boto3
            except ImportError:
                raise PreflightError('aws_sdk_not_installed') from None
            result = live_report(plan, boto3.Session(profile_name=args.profile))
    except PreflightError as error:
        result = {'status': 'failed', 'error_code': str(error)}
    except (OSError, ValueError, UnicodeError):
        result = {'status': 'failed', 'error_code': 'invalid_input_or_response'}
    except Exception:
        result = {'status': 'failed', 'error_code': 'provider_read_failed'}
    print(json.dumps(result, sort_keys=True))
    return 1 if result.get('status') == 'failed' else 0


if __name__ == '__main__':
    raise SystemExit(main())
