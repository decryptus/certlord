"""Validate and normalize external TLS material without storage or HTTP access."""
from datetime import datetime, timezone
import re
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import ExtendedKeyUsageOID
from certlord.services.identity_definition import identity_definition

LIMITS = {'cert': 65536, 'key': 65536, 'chain': 262144}
CERT_BLOCK = re.compile(rb'-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----', re.S)


class InvalidMaterial(ValueError):
    pass


def validate_import(payload):
    if not isinstance(payload, dict) or set(payload) - {'domain', 'cert', 'key', 'chain'}:
        raise InvalidMaterial('Expected domain, cert, key and optional chain')
    try:
        definition = identity_definition([payload['domain']])
        encoded = {}
        for field, limit in LIMITS.items():
            value = payload.get(field, '' if field == 'chain' else None)
            if not isinstance(value, str) or len(value) > limit:
                raise ValueError()
            encoded[field] = value.encode('ascii')
        blocks = CERT_BLOCK.findall(encoded['cert'])
        if len(blocks) != 1 or CERT_BLOCK.sub(b'', encoded['cert']).strip():
            raise ValueError()
        leaf = x509.load_pem_x509_certificate(blocks[0])
        key = serialization.load_pem_private_key(encoded['key'], password=None)
        # Accept exactly one unencrypted private key, without appended material.
        key_blocks = re.findall(rb'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----.*?-----END (?:RSA |EC )?PRIVATE KEY-----', encoded['key'], re.S)
        if len(key_blocks) != 1 or encoded['key'].strip() != key_blocks[0]:
            raise ValueError()
        if not ((isinstance(key, rsa.RSAPrivateKey) and key.key_size >= 2048)
                or (isinstance(key, ec.EllipticCurvePrivateKey) and key.key_size >= 256)):
            raise ValueError()
        spki = lambda value: value.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if spki(key.public_key()) != spki(leaf.public_key()):
            raise ValueError()
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if len(names) != 1 or identity_definition(names.get_values_for_type(x509.DNSName)) != definition:
            raise ValueError()
        try:
            if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError()
        except x509.ExtensionNotFound:
            pass
        try:
            if ExtendedKeyUsageOID.SERVER_AUTH not in leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
                raise ValueError()
        except x509.ExtensionNotFound:
            pass
        chain_blocks = CERT_BLOCK.findall(encoded['chain'])
        if len(chain_blocks) > 8 or CERT_BLOCK.sub(b'', encoded['chain']).strip():
            raise ValueError()
        chain = [x509.load_pem_x509_certificate(block) for block in chain_blocks]
        now = datetime.now(timezone.utc)
        seen = set()
        for cert in [leaf, *chain]:
            if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
                raise ValueError()
            digest = cert.fingerprint(hashes.SHA256())
            if digest in seen:
                raise ValueError()
            seen.add(digest)
        for position, issuer in enumerate(chain):
            constraints = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
            if not constraints.ca or (constraints.path_length is not None and position > constraints.path_length):
                raise ValueError()
            try:
                if not issuer.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
                    raise ValueError()
            except x509.ExtensionNotFound:
                pass
        for child, issuer in zip([leaf, *chain], chain):
            child.verify_directly_issued_by(issuer)
        # Supplied chain consistency is not proof of trust in a public/private PKI.
        pem = lambda cert: cert.public_bytes(serialization.Encoding.PEM).decode('ascii')
        return definition, {'cert': pem(leaf), 'chain': ''.join(pem(cert) for cert in chain),
            'key': key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()).decode('ascii'),
            'fingerprint_sha256': leaf.fingerprint(hashes.SHA256()).hex(),
            'not_after': leaf.not_valid_after_utc.isoformat()}
    except Exception:
        raise InvalidMaterial('Invalid TLS material: check PEM, key match, single DNS SAN, validity and chain') from None
