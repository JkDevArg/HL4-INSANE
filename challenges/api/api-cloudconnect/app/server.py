"""CloudConnect OAuth API — api-cloudconnect (JWT RS256→HS256 algorithm confusion).

Vulnerabilidad:
  El servidor valida JWTs aceptando AMBOS algoritmos: RS256 y HS256.
  La clave pública RSA está expuesta en /jwks.json (incluyendo el PEM completo).

  jwt.decode(token, public_key_pem, algorithms=["RS256", "HS256"])

  Cuando el atacante envía un JWT firmado con HS256 usando la clave pública
  como secreto HMAC, PyJWT lo valida exitosamente porque:
  1. El header dice alg=HS256
  2. PyJWT usa la misma 'key' (public_key_pem) como secreto HMAC
  3. La firma verifica correctamente

  Así se puede forjar un token con role="admin" sin conocer la clave privada.

Flujo de explotación:
  1. GET /jwks.json → obtener la clave pública RSA (en PEM y en JWK)
  2. POST /oauth/token con credenciales válidas → ver estructura del JWT
  3. Forjar JWT con alg=HS256, role=admin, firmado con la public_key como HMAC
  4. GET /api/admin/export con el token forjado → FLAG

Anti-AI twist:
  - /jwks.json expone tanto JWK como PEM (el PEM es la "comodidad" que habilita el ataque)
  - La descripción dice RS256 en todos lados pero el código acepta HS256 silenciosamente
  - El endpoint de admin no está documentado en /
"""
import base64
import json
import os
import time

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, request

from siem import emit
from reqlog import reqlog_http

app = Flask(__name__)

FLAG = os.environ.get("FLAG", "HL4{EJEMPLO_LOCAL}")

# ---------------------------------------------------------------------------
# Generación del par de claves RSA al arrancar (único por instancia/equipo)
# ---------------------------------------------------------------------------
_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_public_key = _private_key.public_key()

# PEM serializado (lo que se usará como 'key' en jwt.decode)
PUBLIC_KEY_PEM = _public_key.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("utf-8")

PRIVATE_KEY_PEM = _private_key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.TraditionalOpenSSL,
    serialization.NoEncryption(),
).decode("utf-8")

# JWK components para /jwks.json
pub_numbers = _public_key.public_numbers()


def _int_to_base64url(n: int) -> str:
    """Convierte un entero grande a base64url sin padding."""
    length = (n.bit_length() + 7) // 8
    b = n.to_bytes(length, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# Credenciales de usuarios (hardcodeadas para el CTF)
USERS = {
    "ctfuser": {"password": "ctfpass2024", "role": "viewer", "name": "CTF User"},
    "svcaccount": {"password": "svc!Internal#9", "role": "viewer", "name": "Service Account"},
}


def _make_token(username: str, role: str) -> str:
    """Genera un JWT RS256 con los claims del usuario."""
    payload = {
        "sub": username,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "iss": "cloudconnect-oauth",
        "aud": "cloudconnect-api",
    }
    return jwt.encode(payload, PRIVATE_KEY_PEM, algorithm="RS256")


def _verify_token(token: str) -> dict | None:
    """Verifica el JWT. VULNERABLE: acepta RS256 Y HS256.

    Cuando alg=HS256, PyJWT usa PUBLIC_KEY_PEM como secreto HMAC.
    Un atacante que conoce la clave pública puede forjar tokens HS256 válidos.
    """
    try:
        payload = jwt.decode(
            token,
            PUBLIC_KEY_PEM,                  # VULN: misma key para RS256 y HS256
            algorithms=["RS256", "HS256"],   # VULN: acepta ambos
            audience="cloudconnect-api",
            issuer="cloudconnect-oauth",
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# ---------------------------------------------------------------------------
# Middleware / helpers
# ---------------------------------------------------------------------------
@app.before_request
def _log_request():
    try:
        src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        if src_ip and "," in src_ip:
            src_ip = src_ip.split(",")[0].strip()
        body = request.get_data(cache=True, as_text=True)
        reqlog_http(
            src_ip=src_ip, method=request.method, path=request.path,
            query=request.query_string.decode("utf-8", "replace"),
            headers=dict(request.headers), body=body,
        )
    except Exception:
        pass


def _get_token_from_request():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/")
def index():
    return jsonify({
        "api": "CloudConnect OAuth API",
        "version": "1.8.3",
        "auth": "OAuth2/JWT (RS256)",
        "endpoints": {
            "token": "POST /oauth/token",
            "jwks": "GET /jwks.json",
            "data": "GET /api/data",
            "health": "GET /health",
        },
        "note": "Enterprise cloud integration platform with OAuth2 authentication.",
    })


@app.get("/health")
def health():
    return jsonify({"status": "ok", "algorithm": "RS256"})


@app.get("/jwks.json")
def jwks():
    """Expone la clave pública en formato JWKS + PEM completo.

    El PEM es la 'comodidad' para clientes que no soportan JWK nativo.
    Es también la pieza que habilita el ataque de algorithm confusion.
    """
    pub_nums = _public_key.public_numbers()
    return jsonify({
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": "cloudconnect-2024-01",
                "n": _int_to_base64url(pub_nums.n),
                "e": _int_to_base64url(pub_nums.e),
                # PEM incluido para "conveniencia" de clientes legacy
                "x5c": [PUBLIC_KEY_PEM],
            }
        ],
        # Campo extra: PEM directo para integración rápida
        "public_key_pem": PUBLIC_KEY_PEM,
    })


@app.post("/oauth/token")
def oauth_token():
    """Emite un JWT RS256 para credenciales válidas."""
    src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    user = USERS.get(username)
    if not user or user["password"] != password:
        emit("auth_failed", "warn", src_ip=src_ip, detail={"username": username})
        return jsonify({"error": "invalid_credentials", "message": "Invalid username or password"}), 401

    token = _make_token(username, user["role"])
    emit("auth_success", "info", src_ip=src_ip, detail={"username": username, "role": user["role"]})
    return jsonify({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "read",
    })


@app.get("/api/data")
def api_data():
    """Endpoint de datos para rol 'viewer'."""
    token = _get_token_from_request()
    if not token:
        return jsonify({"error": "unauthorized", "message": "Bearer token required"}), 401

    payload = _verify_token(token)
    if not payload:
        return jsonify({"error": "invalid_token", "message": "Token invalid or expired"}), 401

    return jsonify({
        "message": "Cloud connection data",
        "user": payload.get("sub"),
        "role": payload.get("role"),
        "connections": [
            {"id": "conn_001", "provider": "AWS", "region": "us-east-1", "status": "active"},
            {"id": "conn_002", "provider": "Azure", "region": "eastus", "status": "active"},
            {"id": "conn_003", "provider": "GCP", "region": "us-central1", "status": "degraded"},
        ],
    })


@app.get("/api/admin/export")
def api_admin_export():
    """Endpoint de exportación — solo para administradores.

    No documentado en /. Descubrible via fuzzing o análisis de tráfico.
    Requiere role=admin en el JWT.
    """
    src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    token = _get_token_from_request()
    if not token:
        return jsonify({"error": "unauthorized"}), 401

    payload = _verify_token(token)
    if not payload:
        return jsonify({"error": "invalid_token"}), 401

    if payload.get("role") != "admin":
        emit("priv_escalation_attempt", "warn", src_ip=src_ip,
             detail={"sub": payload.get("sub"), "role": payload.get("role")})
        return jsonify({"error": "forbidden", "message": "Admin role required"}), 403

    emit("admin_export_accessed", "alert", src_ip=src_ip,
         detail={"sub": payload.get("sub"), "alg": "check-headers"})
    return jsonify({
        "export": "full_system_export",
        "classification": "TOP_SECRET",
        "flag": FLAG,
        "connections_count": 1247,
        "data_exported_gb": 892.4,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=False)
