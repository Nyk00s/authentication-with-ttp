import os
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def save_key_and_cert(key, cert):
    with open('key.pem', 'wb') as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    with open('cert.pem', 'wb') as f:
        f.write(
            cert.public_bytes(serialization.Encoding.PEM)
        )


def get_ttp_keys():
    if not os.path.exists('cert.pem') or not os.path.exists('key.pem'):
        return generate_ttp_keys()
    else:
        with open('cert.pem', 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        with open('key.pem', 'rb') as f:
            key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        return key, cert


def generate_ttp_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
            x509.NameAttribute(NameOID.COMMON_NAME, "TTP-CA"),
        ]
    )

    cert = (x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(private_key, hashes.SHA256())
            )
    save_key_and_cert(private_key, cert)
    return private_key, cert
