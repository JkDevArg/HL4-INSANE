"""Royal Console — web-jwt-04 (Web INSANE).

App de administracion del "Reino" con autenticacion por JWT (RS256). Cualquiera
puede registrarse / pedir un token de invitado (role=guest). El endpoint
`/admin/crown` entrega la corona (la FLAG) solo a un token con privilegios de
admin. La meta: FORJAR ese token.

================================ LA CADENA ================================

El servidor genera un par RSA al arrancar. La clave PUBLICA se expone en
`/jwks.json` (JWK) y en `/pubkey` -- es lo normal para que clientes verifiquen.
El token de invitado se firma con RS256 (kid=royal-2024).

El VERIFICADOR (verify_token) esta deliberadamente roto y ofrece DOS vias de
forja independientes:

  VULN #1 -- Confusion de algoritmos RS256 -> HS256
  ------------------------------------------------
  El verificador lee `alg` del header SIN verificar y lo usa para decidir como
  validar la firma (error clasico: confiar en el `alg` del propio token). Para
  HS256 reutiliza el MATERIAL de la clave PUBLICA como secreto HMAC: en concreto
  el SPKI de la clave publica en DER codificado en base64 (exactamente lo que
  /pubkey publica en el campo "key"). Como ese material es CONOCIDO, el atacante
  firma un token HS256 con ese mismo string base64-DER como secreto y el servidor
  lo valida -> forja total de claims.
  (Nota tecnica: PyJWT 2.x rechaza un PEM "-----BEGIN PUBLIC KEY-----" como
  secreto HMAC; por eso el material publico se publica/reutiliza como base64 del
  DER, que NO dispara esa proteccion y sigue siendo enteramente publico.)

  VULN #2 -- JWK/JKU header injection
  -----------------------------------
  Si el header del token trae `jwk` (clave embebida) o `jku` (URL a un JWKS), el
  verificador CONFIA en ella para obtener la clave de verificacion (clasico "el
  token dice con que clave verificarlo"). El atacante genera SU PROPIO par RSA,
  firma RS256 con su clave privada y embebe su clave publica en el header `jwk`
  (o la sirve por `jku`). El server verifica contra la clave del atacante -> OK.

OBJETIVO -- /admin/crown exige, ademas de una firma valida:
  - claim  role == "admin"
  - claim anidado  royal.lineage == "true-heir"
  - header  kid presente (cualquiera)  -> el guest trae kid=royal-2024
Un token admin "a medias" (solo role) NO basta: hay que clonar la estructura
completa de claims. Eso lo hace INSANE: no es solo "cambia role a admin".

La FLAG se inyecta por equipo via env FLAG. NUNCA hardcodeada.
"""
import json
import os
import time
import base64

import jwt  # PyJWT
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, Response, jsonify, request

from siem import emit
from reqlog import reqlog_http

app = Flask(__name__)


@app.before_request
def _log_request():
    """Loguea CADA peticion entrante COMPLETA (metodo, ruta, query, headers,
    body) para el SIEM del stream. No interfiere con el manejo normal."""
    try:
        src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        if src_ip and "," in src_ip:
            src_ip = src_ip.split(",")[0].strip()
        body = request.get_data(cache=True, as_text=True)
        reqlog_http(
            src_ip=src_ip,
            method=request.method,
            path=request.path,
            query=request.query_string.decode("utf-8", "replace"),
            headers=dict(request.headers),
            body=body,
        )
    except Exception:
        pass


FLAG = os.environ.get("FLAG", "HL4{EJEMPLO_LOCAL}")

ISSUER = "royal-console"
KID = "royal-2024"
GUEST_TTL = 3600

# --------------------------------------------------------------------------
# Par RSA del servidor (se genera al arrancar). La PUBLICA es publica a proposito.
# --------------------------------------------------------------------------
_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_pub = _priv.public_key()

PRIV_PEM = _priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
# Clave publica en PEM (para verificar RS256 con PyJWT, que necesita PEM/objeto).
PUB_PEM = _pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
# Material publico de la clave: SPKI en DER -> base64. Es lo que /pubkey publica
# en el campo "key" y, ademas, lo que el verificador reutiliza como SECRETO HMAC
# para HS256 (la confusion de algoritmos). Es enteramente publico.
PUB_DER_B64 = base64.b64encode(
    _pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
).decode("ascii")


def _b64url_uint(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _public_jwk() -> dict:
    nums = _pub.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": KID,
        "n": _b64url_uint(nums.n),
        "e": _b64url_uint(nums.e),
    }


def _jwk_to_pem(jwk: dict) -> bytes:
    """Convierte un JWK RSA (n,e) a clave publica PEM (para verificar)."""
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

    def _d(s: str) -> int:
        s = s + "=" * (-len(s) % 4)
        return int.from_bytes(base64.urlsafe_b64decode(s), "big")

    pub = RSAPublicNumbers(_d(jwk["e"]), _d(jwk["n"])).public_key()
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# --------------------------------------------------------------------------
# Verificador de token (DELIBERADAMENTE roto)
# --------------------------------------------------------------------------
def verify_token(token: str) -> dict:
    """Verifica un JWT y devuelve sus claims. Aqui viven las dos vulns.

    1) Lee el header SIN verificar para decidir como obtener la clave y el alg.
    2) Si el header trae `jwk` -> usa esa clave embebida (JWK injection).
       Si trae `jku` -> descarga el JWKS de esa URL (JKU injection).
       Si no -> usa el `alg` del token para elegir el material de clave:
         RS256 -> clave publica PEM (verificacion de firma normal).
         HS256 -> reutiliza el MATERIAL publico (PUB_DER_B64) como secreto HMAC.
                  -> confusion de algoritmos: el material es publico (/pubkey).
    """
    header = jwt.get_unverified_header(token)

    # --- VULN #2: la clave sale del propio token (jwk / jku) ---
    if "jwk" in header:
        key = _jwk_to_pem(header["jwk"])
        return jwt.decode(token, key=key, algorithms=["RS256"],
                          issuer=ISSUER, options={"verify_aud": False})

    if "jku" in header:
        import urllib.request

        with urllib.request.urlopen(header["jku"], timeout=3) as r:
            jwks = json.loads(r.read().decode("utf-8"))
        jwk = jwks["keys"][0]
        key = _jwk_to_pem(jwk)
        return jwt.decode(token, key=key, algorithms=["RS256"],
                          issuer=ISSUER, options={"verify_aud": False})

    # --- VULN #1: el `alg` del token decide el material de clave ---
    alg = (header.get("alg") or "RS256").upper()
    if alg == "HS256":
        # Material publico reutilizado como secreto HMAC (confusion de algos).
        key = PUB_DER_B64
        algorithms = ["HS256"]
    else:
        key = PUB_PEM
        algorithms = ["RS256"]

    return jwt.decode(
        token,
        key=key,
        algorithms=algorithms,
        issuer=ISSUER,
        options={"verify_aud": False},
    )


def issue_guest(username: str) -> str:
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "sub": username,
        "role": "guest",
        "royal": {"lineage": "commoner"},
        "iat": now,
        "exp": now + GUEST_TTL,
    }
    return jwt.encode(payload, PRIV_PEM, algorithm="RS256", headers={"kid": KID})


def _bearer() -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return request.cookies.get("token")


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------
INDEX = """<!doctype html><html lang="es"><head><meta charset="utf-8">
<title>Royal Console</title></head>
<body style="font-family:sans-serif;max-width:780px;margin:2rem auto;line-height:1.5">
<h1>&#128081; Royal Console</h1>
<p>Consola de administracion del Reino. La autenticacion es por <b>JWT (RS256)</b>.
Cualquier subdito puede obtener un token de invitado. Solo la corona
(<code>/admin/crown</code>) esta reservada a la realeza.</p>
<h3>Empezar</h3>
<ol>
<li><code>POST /api/login {"username":"tu-nombre"}</code> &rarr; token de invitado.</li>
<li><code>GET /api/whoami</code> con <code>Authorization: Bearer &lt;token&gt;</code>.</li>
<li><code>GET /admin/crown</code> &rarr; requiere un token <b>admin</b> con linaje real.</li>
</ol>
<h3>Claves publicas</h3>
<ul>
<li><a href="/jwks.json">/jwks.json</a> (JWK)</li>
<li><a href="/pubkey">/pubkey</a> (clave publica: PEM + SPKI/DER en base64)</li>
</ul>
<p style="color:#888">Honra a la corona. Que reine la justicia.</p>
</body></html>"""


@app.get("/")
def index():
    return Response(INDEX, mimetype="text/html")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/jwks.json")
def jwks():
    return jsonify({"keys": [_public_jwk()]})


@app.get("/pubkey")
def pubkey():
    # Publica la clave publica del Reino en dos formatos. El campo "key"
    # (SPKI/DER en base64) es el material que el verificador reutiliza.
    return jsonify({
        "kty": "RSA",
        "alg": "RS256",
        "kid": KID,
        "format": "spki-der-b64",
        "key": PUB_DER_B64,
        "pem": PUB_PEM.decode("ascii"),
    })


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "guest").strip()[:64] or "guest"
    token = issue_guest(username)
    return jsonify({
        "token": token,
        "type": "Bearer",
        "note": "Token de invitado (role=guest). La corona exige privilegios de admin.",
    })


@app.get("/api/whoami")
def whoami():
    token = _bearer()
    if not token:
        return jsonify({"error": "falta token (Authorization: Bearer ...)"}), 401
    src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    try:
        claims = verify_token(token)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"token invalido: {exc}"}), 401
    return jsonify({
        "ok": True,
        "sub": claims.get("sub"),
        "role": claims.get("role"),
        "royal": claims.get("royal"),
    })


@app.get("/admin/crown")
def crown():
    token = _bearer()
    src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if not token:
        return jsonify({"error": "falta token (Authorization: Bearer ...)"}), 401

    try:
        header = jwt.get_unverified_header(token)
        claims = verify_token(token)
    except Exception as exc:  # noqa: BLE001
        emit("auth_failure", "warn", src_ip=src_ip,
             detail={"endpoint": "/admin/crown", "reason": str(exc)[:200]})
        return jsonify({"error": f"token invalido: {exc}"}), 401

    # --- Doble check: role admin + linaje real anidado + kid presente ---
    role_ok = claims.get("role") == "admin"
    lineage_ok = isinstance(claims.get("royal"), dict) and \
        claims["royal"].get("lineage") == "true-heir"
    kid_ok = "kid" in header

    if not (role_ok and lineage_ok and kid_ok):
        emit("privilege_escalation_attempt", "warn", src_ip=src_ip,
             detail={"role": claims.get("role"), "royal": claims.get("royal"),
                     "kid": header.get("kid")})
        return jsonify({
            "error": "acceso denegado: la corona exige role=admin y linaje real",
            "your_role": claims.get("role"),
            "your_lineage": (claims.get("royal") or {}).get("lineage"),
        }), 403

    # Token forjado correctamente: confusion de algoritmos o jwk/jku injection.
    emit("flag_access", "alert", src_ip=src_ip,
         detail={"endpoint": "/admin/crown", "alg": header.get("alg"),
                 "forged_via": "jwk-header" if "jwk" in header
                 else ("jku-header" if "jku" in header else "alg-confusion")})
    return jsonify({
        "ok": True,
        "message": "Larga vida al Rey. La corona es tuya.",
        "flag": FLAG,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
