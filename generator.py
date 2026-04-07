import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding


def encrypt_with_public_key(public_key_pem, data: bytes):
    public_key = get_public_key_from_pem(public_key_pem)
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_with_private_key(private_key, ciphertext_b64):
    return private_key.decrypt(
        ciphertext_b64,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def get_public_key_pem(public_key):
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def get_cert_pem(cert):
    return cert.public_bytes(
        serialization.Encoding.PEM
    ).decode()


def get_public_key_from_pem(public_key_pem: bytes):
    return serialization.load_pem_public_key(
        public_key_pem
    )


def save_private_key(key):
    with open('key.pem', 'wb') as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )


def save_cert(cert):
    with open('cert.pem', 'wb') as f:
        f.write(
            cert.public_bytes(serialization.Encoding.PEM)
        )


def get_keys():
    if not os.path.exists('key.pem'):
        return generate_keys()
    else:
        with open('key.pem', 'rb') as f:
            key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        return key, key.public_key()


def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    save_private_key(private_key)
    return private_key, private_key.public_key()


def get_cert(private_key, public_key, name_attr):
    if not os.path.exists('cert.pem'):
        return generate_cert(private_key, public_key, name_attr)
    else:
        with open('cert.pem', 'rb') as f:
            cert = x509.load_pem_x509_certificate(
                f.read(),
                default_backend()
            )
        return cert


def generate_cert(private_key, public_key, name_attr):
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
            x509.NameAttribute(NameOID.COMMON_NAME, name_attr),
        ]
    )

    cert = (x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(private_key, hashes.SHA256())
            )
    save_cert(cert)
    return cert
