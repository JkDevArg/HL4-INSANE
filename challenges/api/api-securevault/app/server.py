"""SecureVault Secrets API — api-securevault (JWT kid path traversal).

Vulnerabilidad:
  El servidor usa el campo `kid` del header JWT para cargar la clave de
  verificación desde /keys/{kid}.pub. Si el `kid` contiene una secuencia
  de path traversal, puede leer archivos arbitrarios del sistema.

  Clave del ataque:
    kid = "../../../../dev/null"
    → abre /keys/../../../../dev/null = /dev/null
    → lee "" (cadena vacía)
    → usa "" como secreto HMAC (HS256)
    → el atacante puede firmar cualquier payload con "" como clave

  Para obtener la flag hay que forjar un token con:
    {"sub": "attacker", "role": "admin", "clearance": "TOP_SECRET"}
  firmado con HS256 y kid="../../../../dev/null", usando "" como secreto.

Flujo de explotación:
  1. POST /auth/token → JWT RS256 legítimo con kid="current", role="user"
  2. GET /vault/list → ver las entradas disponibles (no la flag)
  3. GET /vault/flag → 403 (requiere admin + TOP_SECRET)
  4. Inspeccionar JWT: ver que usa kid header
  5. Forjar JWT con kid="../../../../dev/null", alg=HS256, role=admin, clearance=TOP_SECRET
     usando secreto HMAC = "" (vacío)
  6. GET /vault/flag con token forjado → FLAG

Anti-AI twist:
  - El kid path traversal es una vuln real (CVE-class) pero poco conocida
  - /dev/null devuelve "" como contenido al ser leído
  - PyJWT acepta "" como secreto HMAC válido si el token está bien formado
  - Hay que entender que base64url("") = "" y que HMAC con clave vacía es válido
"""
import os
import time
import sqlite3
import base64

import jwt
from flask import Flask, jsonify, request

from siem import emit
from reqlog import reqlog_http

app = Flask(__name__)

FLAG = os.environ.get("FLAG", "HL4{EJEMPLO_LOCAL}")
KEYS_DIR = "/keys"

# ---------------------------------------------------------------------------
# Base de datos del vault (in-memory)
# ---------------------------------------------------------------------------
_db = None

def get_db():
    global _db
    if _db is None:
        _db = sqlite3.connect(":memory:", check_same_thread=False)
        _init_vault(_db)
    return _db

def _init_vault(conn):
    conn.executescript("""
        CREATE TABLE vault_entries (
            id       INTEGER PRIMARY KEY,
            key_name TEXT UNIQUE NOT NULL,
            value    TEXT NOT NULL,
            owner    TEXT NOT NULL,
            clearance TEXT NOT NULL DEFAULT 'PUBLIC'
        );
    """)
    conn.execute("INSERT INTO vault_entries VALUES (1, 'db_password', 'p4ssw0rd_prod_2024!', 'admin', 'CONFIDENTIAL')")
    conn.execute("INSERT INTO vault_entries VALUES (2, 'api_key_stripe', 'sk_live_XXXXXXXXXXXX', 'admin', 'CONFIDENTIAL')")
    conn.execute("INSERT INTO vault_entries VALUES (3, 'smtp_password', 'smtp_secret_v2', 'ops', 'INTERNAL')")
    conn.execute("INSERT INTO vault_entries VALUES (4, 'vpn_shared_key', 'vpn_pre_shared_2024', 'ops', 'INTERNAL')")
    conn.execute("INSERT INTO vault_entries VALUES (5, 'flag', ?, 'admin', 'TOP_SECRET')", (FLAG,))
    conn.commit()

# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------
def _load_verification_key(kid: str) -> bytes:
    """Carga la clave de verificación desde /keys/{kid}.pub.

    VULN: kid no está saneado → path traversal.
    Si kid = "../../../../dev/null", lee /dev/null → b""
    → secreto HMAC vacío → cualquier token HS256 con ese kid es válido.
    """
    key_path = os.path.join(KEYS_DIR, f"{kid}.pub")
    try:
        with open(key_path, "rb") as f:
            return f.read()
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        return b""


def _get_private_key() -> bytes:
    """Carga la clave privada para firmar tokens RS256."""
    with open(os.path.join(KEYS_DIR, "current.key"), "rb") as f:
        return f.read()


def _make_token(username: str, role: str) -> str:
    """Genera JWT RS256 legítimo con kid='current'."""
    payload = {
        "sub": username,
        "role": role,
        "clearance": "PUBLIC",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    private_key = _get_private_key()
    return jwt.encode(payload, private_key, algorithm="RS256",
                      headers={"kid": "current"})


def _verify_token(token: str) -> dict | None:
    """Verifica JWT usando el kid del header para cargar la clave.

    VULN: usa el kid sin sanear para cargar el archivo de clave.
    Si la clave cargada es b"", entonces el token HS256 con secreto ""
    (vacío) pasa la verificación.
    """
    try:
        # Decodificar header sin verificar para obtener kid y alg
        unverified = jwt.get_unverified_header(token)
        kid = unverified.get("kid", "current")
        alg = unverified.get("alg", "RS256")

        # Sanitización INSUFICIENTE: solo bloquea ".." directo, no codificado
        # (el path traversal usa "/" directamente en el kid)
        if kid == "..":
            return None

        # Cargar la clave según el kid — VULN de path traversal aquí
        key_bytes = _load_verification_key(kid)

        # Si alg es HS256, key_bytes se usa como secreto HMAC
        # Si key_bytes = b"" (de /dev/null), el secreto es la cadena vacía
        key = key_bytes.decode("utf-8", errors="replace") if alg == "HS256" else key_bytes

        payload = jwt.decode(
            token, key,
            algorithms=["RS256", "HS256"],
            options={"verify_exp": True},
        )
        return payload
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Middleware
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


def _require_auth():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, (jsonify({"error": "unauthorized"}), 401)
    token = auth[7:]
    payload = _verify_token(token)
    if not payload:
        return None, (jsonify({"error": "invalid_token"}), 401)
    return payload, None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/")
def index():
    return jsonify({
        "api": "SecureVault Secrets API",
        "version": "3.0.1",
        "auth": "POST /auth/token",
        "vault": {
            "list": "GET /vault/list",
            "get": "GET /vault/get/<key_name>",
            "flag": "GET /vault/flag",
        },
        "note": "Enterprise secrets management. JWT authentication with key rotation support (kid header).",
    })


@app.get("/health")
def health():
    return jsonify({"status": "ok", "entries": 5})


USERS = {
    "vaultuser": {"password": "v4ult!Secure99", "role": "user"},
    "vaultops": {"password": "0ps#Vault2024", "role": "operator"},
}


@app.post("/auth/token")
def auth_token():
    src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    user = USERS.get(username)
    if not user or user["password"] != password:
        emit("auth_failed", "warn", src_ip=src_ip, detail={"username": username})
        return jsonify({"error": "invalid_credentials"}), 401

    token = _make_token(username, user["role"])
    emit("auth_success", "info", src_ip=src_ip, detail={"username": username})
    return jsonify({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "note": "Token uses RS256 with key rotation. See kid header for active key ID.",
    })


@app.get("/vault/list")
def vault_list():
    payload, err = _require_auth()
    if err:
        return err

    db = get_db()
    cur = db.execute("SELECT id, key_name, owner, clearance FROM vault_entries")
    entries = [{"id": r[0], "key_name": r[1], "owner": r[2], "clearance": r[3]} for r in cur.fetchall()]
    return jsonify({"entries": entries, "total": len(entries)})


@app.get("/vault/get/<key_name>")
def vault_get(key_name):
    payload, err = _require_auth()
    if err:
        return err

    db = get_db()
    cur = db.execute("SELECT value, clearance FROM vault_entries WHERE key_name=?", (key_name,))
    row = cur.fetchone()
    if not row:
        return jsonify({"error": "not_found"}), 404

    value, clearance = row
    if clearance == "TOP_SECRET":
        return jsonify({"error": "forbidden", "message": "TOP_SECRET clearance required"}), 403

    return jsonify({"key_name": key_name, "value": value, "clearance": clearance})


@app.get("/vault/flag")
def vault_flag():
    """Acceso al secreto de máxima clasificación. Requiere admin + TOP_SECRET."""
    src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    payload, err = _require_auth()
    if err:
        return err

    role = payload.get("role", "user")
    clearance = payload.get("clearance", "PUBLIC")

    if role != "admin" or clearance != "TOP_SECRET":
        emit("priv_escalation_attempt", "warn", src_ip=src_ip,
             detail={"role": role, "clearance": clearance, "vuln": "jwt-kid-traversal"})
        return jsonify({
            "error": "forbidden",
            "message": "Requires role=admin AND clearance=TOP_SECRET",
            "your_role": role,
            "your_clearance": clearance,
        }), 403

    emit("vault_flag_accessed", "alert", src_ip=src_ip,
         detail={"role": role, "clearance": clearance})
    return jsonify({
        "key_name": "flag",
        "value": FLAG,
        "clearance": "TOP_SECRET",
        "classification": "EYES ONLY",
    })


if __name__ == "__main__":
    get_db()
    app.run(host="0.0.0.0", port=5004, debug=False)
