"""Validate a generation without putting private material in the durable ledger."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from certlord.cloudfront.config import require, JobError
from certlord.services.deployment import certificate_generation
from certlord.services.import_material import validate_import


def current_material(read, generation, domain, minimum_life=0):
    record = read()
    require(record.get('status') in ('generated', 'deployed')
            and certificate_generation(record) == generation, 'superseded_generation')
    try:
        _definition, normalized = validate_import(dict(domain=domain,
            **{key: record.get(key, '') for key in ('cert', 'key', 'chain')}))
        leaf = x509.load_pem_x509_certificate(normalized['cert'].encode())
        require(leaf.not_valid_after_utc > datetime.now(timezone.utc) + timedelta(seconds=minimum_life),
                'candidate_expires_too_soon')
        chain = x509.load_pem_x509_certificates(normalized['chain'].encode())
        if chain and chain[-1].issuer == chain[-1].subject:
            chain[-1].verify_directly_issued_by(chain[-1])
            chain.pop()
        normalized['chain'] = ''.join(cert.public_bytes(serialization.Encoding.PEM).decode() for cert in chain)
        normalized['material_sha256'] = material_digest(leaf, normalized['chain'])
        require(len(normalized['key'].encode()) <= 5120 and len(normalized['cert'].encode()) <= 32768,
                'acm_material_limit')
        return record, normalized, leaf
    except JobError:
        raise
    except Exception:
        raise JobError('invalid_candidate_material') from None


def material_digest(leaf, chain_pem):
    chain = x509.load_pem_x509_certificates(chain_pem.encode()) if chain_pem else []
    if chain and chain[-1].issuer == chain[-1].subject:
        chain[-1].verify_directly_issued_by(chain[-1])
        chain.pop()
    hashes_ = [cert.fingerprint(hashes.SHA256()).hex() for cert in [leaf, *chain]]
    return hashlib.sha256(json.dumps(hashes_, separators=(',', ':')).encode()).hexdigest()


def key_kind(leaf):
    key = leaf.public_key()
    if isinstance(key, rsa.RSAPublicKey) and key.key_size in (2048, 3072, 4096):
        return ('RSA', key.key_size)
    if isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name in ('secp256r1', 'secp384r1'):
        return ('EC', key.curve.name)
    raise JobError('unsupported_key_algorithm')


def usages(leaf, kind):
    try:
        extension = leaf.extensions.get_extension_for_class(kind).value
    except x509.ExtensionNotFound:
        return set()
    if kind is x509.ExtendedKeyUsage:
        return {value.dotted_string for value in extension}
    names = ('digital_signature', 'content_commitment', 'key_encipherment', 'data_encipherment',
             'key_agreement', 'key_cert_sign', 'crl_sign')
    values = {name for name in names if getattr(extension, name)}
    if extension.key_agreement:
        values |= {name for name in ('encipher_only', 'decipher_only') if getattr(extension, name)}
    return values


def compatible(old, new):
    require(key_kind(old) == key_kind(new), 'reimport_key_type_changed')
    old_usage = usages(old, x509.KeyUsage)
    if key_kind(new)[0] == 'EC':
        old_usage.discard('key_encipherment')
    require(old_usage <= usages(new, x509.KeyUsage), 'reimport_key_usage_removed')
    old_extended = usages(old, x509.ExtendedKeyUsage)
    old_extended.discard(ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string)
    require(old_extended <= usages(new, x509.ExtendedKeyUsage), 'reimport_extended_usage_removed')
