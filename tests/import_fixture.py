"""Synthetic TLS material, never credentials from a deployment."""
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def material(names=('import.example.test',), offset=0, ca=False, key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Fixture CA')])
    issuer = (x509.CertificateBuilder().subject_name(issuer_name).issuer_name(issuer_name)
              .public_key(issuer_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now-timedelta(days=10)).not_valid_after(now+timedelta(days=100))
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
              .sign(issuer_key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
            .issuer_name(issuer_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now+timedelta(days=offset-1)).not_valid_after(now+timedelta(days=offset+1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .sign(issuer_key, hashes.SHA256()))
    pem = lambda cert: cert.public_bytes(serialization.Encoding.PEM).decode()
    return {'domain': names[0], 'cert': pem(leaf), 'chain': pem(issuer),
            'key': key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()).decode()}
