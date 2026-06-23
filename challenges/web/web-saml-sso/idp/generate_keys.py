#!/usr/bin/env python3
"""Generate RSA key pair for the SAML IDP."""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime
from pathlib import Path

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

Path("/app/keys/idp_private.pem").write_bytes(
    key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
)

# Self-signed cert
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "PE"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Corp SSO"),
    x509.NameAttribute(NameOID.COMMON_NAME, "idp.corp.local"),
])
cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
    .sign(key, hashes.SHA256())
)

Path("/app/keys/idp_cert.pem").write_bytes(
    cert.public_bytes(serialization.Encoding.PEM)
)
print("[+] Keys generated at /app/keys/")
