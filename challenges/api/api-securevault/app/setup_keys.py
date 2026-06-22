"""Genera el par de claves RSA y las guarda en /keys/ al arrancar."""
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

os.makedirs("/keys", exist_ok=True)

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Guardar clave privada (solo el servidor la usa internamente)
with open("/keys/current.key", "wb") as f:
    f.write(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))

# Guardar clave pública (usada para verificar tokens con kid="current")
with open("/keys/current.pub", "wb") as f:
    f.write(public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

print("[setup_keys] RSA key pair generated at /keys/current.{key,pub}")
