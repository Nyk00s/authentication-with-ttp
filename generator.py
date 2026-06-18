"""
@file generator.py
@brief Cryptographic utility provider for symmetric and asymmetric primitive operations.
@details Implements core RSA-2048 key management, X.509 certificate generation, 
         and hybrid encryption mechanisms utilizing AES-CBC and RSA-OAEP.
@author Franciszek Kuczkowski, Nikodem Falkowski
@version 1.0
@date 2026-06-06
"""

import os
import base64
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def get_public_key_pem(public_key):
    """!
    @brief Serializes an RSA public key object into a PEM-encoded string format.
    @param public_key Valid RSA public key object instantiated from cryptography primitives.
    @return Standard SubjectPublicKeyInfo structural layout encoded in a PEM string.
    """
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def get_cert_pem(cert):
    """!
    @brief Serializes an X.509 certificate object into standard PEM encoded layout.
    @param cert Active X.509 certificate object instance.
    @return Decoded multi-line string encapsulation containing the certificate structures.
    """
    return cert.public_bytes(
        serialization.Encoding.PEM
    ).decode()


def get_public_key_from_pem(public_key_pem: bytes):
    """!
    @brief Deserializes raw PEM input buffers or strings back into active RSA public key entities.
    @param public_key_pem Binary byte array or string sequence holding valid PEM parameters.
    @return Loaded asymmetric RSA public key object operational context.
    """
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode()
    return serialization.load_pem_public_key(public_key_pem)


def aes_encrypt(session_key: bytes, message: bytes) -> str:
    """!
    @brief Encrypts input plaintext streams using symmetric AES-256 in CBC operational mode.
    @details Enforces automatic byte padding constraints up to standard 16-byte cryptographic block limits.
             Generates an unpredictable Cryptographically Strong Initialization Vector (IV) for every envelope.
    @param session_key Explicit secret symmetric byte array context key.
    @param message Raw input plaintext payload array.
    @return Base64 encoded payload holding concatenated Initialization Vector and block-aligned ciphertext bytes.
    """
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded = message + b' ' * (16 - len(message) % 16)
    ct = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(iv + ct).decode()


def aes_decrypt(session_key: bytes, ciphered_message: str) -> bytes:
    """!
    @brief Extracts and decrypts raw ciphertext blocks back into discrete application payloads.
    @details Isolates transmission variables by capturing the leading 16-byte chunk as the active IV context.
             Subsequently strips off trailing blank padding buffers before serialization dispatch.
    @param session_key Synchronized secret symmetric byte array context key.
    @param ciphered_message Complete base64 encoded transport layout packet containing IV and ciphertext block chains.
    @return Original plain binary byte stream data array stripped of block alignments.
    """
    ciphered_message = base64.b64decode(ciphered_message)
    iv = ciphered_message[:16]
    ct = ciphered_message[16:]
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return (decryptor.update(ct) + decryptor.finalize()).rstrip(b' ')


def encrypt_with_public_key(public_key_pem, data: bytes):
    """!
    @brief Encrypts discrete binary buffers using RSA-OAEP asymmetric primitives.
    @details Implements Optimal Asymmetric Encryption Padding (OAEP) backed by standard SHA-256 internal digests.
             Primarily utilized during secure registration phases to transmit initial verification payloads.
    @param public_key_pem Target target endpoint destination public key structure.
    @param data Sensitive short payload string requiring asymmetric encapsulation properties.
    @return Encrypted ciphertext byte representation sequence.
    """
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
    """!
    @brief Decrypts asymmetric envelopes using internal local RSA private keys.
    @details Leverages OAEP mathematical transformations alongside SHA-256 routing algorithms.
             Safely handles unpacking inbound elements such as symmetric network session key distributions.
    @param private_key Valid RSA local private key object.
    @param ciphertext_b64 Asymmetric ciphertext block container representation requiring resolution.
    @return Fully decrypted plain underlying payload byte array values.
    """
    return private_key.decrypt(
        ciphertext_b64,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def save_private_key(key):
    """!
    @brief Flushes private key objects directly to non-volatile local disk storage structures.
    @note Persists structures as unencrypted OpenSSL traditional block assets within the local execution directory.
    @param key Asymmetric RSA private engine key context targeting archival routines.
    """
    with open('key.pem', 'wb') as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )


def save_cert(cert):
    """!
    @brief Serializes and archives X.509 data models directly to persistent file interfaces.
    @param cert Active X.509 certificate structural instantiation targeting archival routines.
    """
    with open('cert.pem', 'wb') as f:
        f.write(
            cert.public_bytes(serialization.Encoding.PEM)
        )


def get_keys():
    """!
    @brief Evaluates execution directories to automatically restore or bootstrap required RSA parameters.
    @return A tuple sequence where entry [0] maps the private engine structure and entry [1] stores the companion public key.
    """
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
    """!
    @brief Core industrial-grade generator bootstrapping local RSA parameter contexts.
    @details Configures explicit, industry-standard mathematical defaults: public exponent set to 65537 
             alongside a robust key length restriction size totaling 2048 bits.
    @return Freshly initialized asymmetric keys tuple: (private_key, public_key).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    save_private_key(private_key)
    return private_key, private_key.public_key()


def get_cert(private_key, public_key, name_attr):
    """!
    @brief Fallback factory interface matching certificate files dynamically against file system indicators.
    @param private_key Signatory authority private parameters.
    @param public_key Subject identity target parameters.
    @param name_attr Identity descriptive identifier label maps (e.g., Common Name).
    @return Active validated X.509 digital certificate asset structures.
    """
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
    """!
    @brief Constructs, binds, and digitally signs standard compliance X.509 certificate formats.
    @details Synthesizes country variables and subject parameters, sets automated 365-day expiration spans, 
             injects cryptographically random serial structures, and seals parameters using internal SHA-256 signatures.
    @param private_key Signatory authority private parameters mapping issuer contexts.
    @param public_key Target public parameters bound securely into the issued token context.
    @param name_attr Context descriptive data binding (e.g., Common Name).
    @return Signed, fully authenticated digital validation x509 Certificate model.
    """
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