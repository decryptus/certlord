"""Bounded HTTP client with sanitized errors and verified TLS."""
import ipaddress
import math
from urllib.parse import urlsplit
import requests


class ClientError(Exception):
    pass


class CertificateClient:
    def __init__(self, url, username=None, password=None, ca=True, timeout=10):
        parsed = urlsplit(url)
        try:
            local = parsed.hostname == 'localhost' or ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            local = False
        if (parsed.scheme not in ('http', 'https') or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment):
            raise ValueError('Use an HTTP(S) API URL without credentials, query or fragment')
        if parsed.scheme == 'http' and not local:
            raise ValueError('Use HTTPS for a remote API')
        if (username is None) != (password is None):
            raise ValueError('Set both CERTLORD_API_USER and CERTLORD_API_PASSWORD')
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError('Timeout must be finite and positive')
        self.url, self.timeout = url.rstrip('/'), timeout
        self.session = requests.Session()
        # Avoid implicit netrc credentials; proxy settings are not part of this client.
        self.session.trust_env = False
        self.session.verify = ca
        if username is not None:
            self.session.auth = (username, password)

    def close(self):
        self.session.close()

    def request(self, method, path, payload=None):
        try:
            response = self.session.request(method, self.url + path, json=payload,
                                            timeout=self.timeout, allow_redirects=False)
            if not 200 <= response.status_code < 300:
                raise ClientError('API request failed (HTTP %d)' % response.status_code)
            return response.json()
        except (requests.RequestException, ValueError):
            raise ClientError('API unreachable or invalid response; check endpoint, TLS and credentials') from None

    def inventory(self):
        records = self.request('GET', '/api/certificates')
        if not isinstance(records, list):
            raise ClientError('Invalid certificate inventory')
        return records

    def detail(self, certificate_id):
        return self.request('GET', '/api/certificates/' + certificate_id)

    def create(self, domain):
        return self.request('POST', '/api/certificates', {'domains': [domain]})

    def remove(self, certificate_id):
        return self.request('DELETE', '/api/certificates/' + certificate_id)

    def import_certificate(self, domain, cert, key, chain=''):
        return self.request('POST', '/api/certificates/import',
                            {'domain': domain, 'cert': cert, 'key': key, 'chain': chain})

    def replace_import(self, certificate_id, expected_version, cert, key, chain=''):
        return self.request('PUT', '/api/certificates/' + certificate_id + '/material',
                            {'expected_version': expected_version, 'cert': cert, 'key': key, 'chain': chain})
