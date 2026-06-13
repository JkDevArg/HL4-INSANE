"""LedgerX API — api-bola-01 (API INSANE).

Cadena de vulnerabilidades encadenadas:
  1) JWT MAL VALIDADO: el verificador acepta tokens con `alg: none` (sin firma).
     -> un atacante puede forjar la identidad/claims que quiera.
  2) BOLA / IDOR: GET /api/users/{user_id}/notes y /api/accounts/{id} no
     comprueban propiedad -> se enumeran objetos de otros usuarios (incl. admin).
  3) MASS ASSIGNMENT: PATCH /api/users/me acepta campos arbitrarios del body,
     incluyendo `role` y `user_id` -> escalada de privilegios.

Objetivo: leer el secreto (FLAG) del usuario admin en /api/admin/secret.

La FLAG se inyecta por equipo vía env FLAG. NO hardcodeada.
"""
import base64
import json
import os
import secrets
import time

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

from siem import emit

app = FastAPI(title="LedgerX API", docs_url=None, redoc_url=None, openapi_url=None)

FLAG = os.environ.get("FLAG", "flag{EJEMPLO_LOCAL}")
JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(16))

# --- "Base de datos" en memoria ---
# El admin (user_id=1) tiene el secreto. Los jugadores se registran como user.
USERS: dict[int, dict] = {
    1: {
        "user_id": 1,
        "username": "admin",
        "password": secrets.token_hex(24),  # no se puede adivinar
        "role": "admin",
        "secret": FLAG,  # el premio
    },
}
NOTES: dict[int, list[str]] = {
    # Pista BOLA: el admin dejó una nota que apunta al endpoint del secreto.
    1: [
        "Recordatorio: rotar el secreto corporativo en /api/admin/secret",
        "El secreto SOLO debe verlo el rol admin (user_id 1).",
    ],
}
ACCOUNTS: dict[int, dict] = {
    1001: {"account_id": 1001, "owner": 1, "balance": 9_999_999, "iban": "PE00-ADMIN"},
}
_next_user_id = 2
_next_account_id = 1002


# ---------------- JWT (deliberadamente mal validado) ----------------
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def make_token(user_id: int, role: str) -> str:
    """Genera un token HS256 legítimo para los usuarios reales."""
    import hashlib
    import hmac

    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"user_id": user_id, "role": role, "iat": int(time.time())}).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = _b64url(hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def verify_token(token: str) -> dict:
    """VULN #1: validación rota.

    Si el header dice alg=none, se acepta SIN verificar firma. Esto permite
    forjar cualquier claim. (Para alg=HS256 sí verifica, pero el atacante
    no necesita la clave: basta con alg=none.)
    """
    try:
        h_b64, p_b64, sig_b64 = token.split(".")
        header = json.loads(_b64url_decode(h_b64))
        payload = json.loads(_b64url_decode(p_b64))
    except Exception:
        raise HTTPException(status_code=401, detail="token inválido")

    alg = header.get("alg", "").lower()
    if alg == "none":
        # ¡Aceptado sin firma! (la trampa)
        return payload
    if alg == "hs256":
        import hashlib
        import hmac

        expected = _b64url(
            hmac.new(JWT_SECRET.encode(), f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(expected, sig_b64):
            raise HTTPException(status_code=401, detail="firma inválida")
        return payload
    raise HTTPException(status_code=401, detail="alg no soportado")


def current_user(authorization: str = Header(default="")) -> dict:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="falta Bearer token")
    payload = verify_token(authorization[7:])
    return payload


# ---------------- Schemas ----------------
class Register(BaseModel):
    username: str
    password: str


class Login(BaseModel):
    username: str
    password: str


# ---------------- Endpoints ----------------
@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def root():
    return {
        "api": "LedgerX",
        "endpoints": [
            "POST /api/register", "POST /api/login",
            "GET /api/users/{id}/notes", "GET /api/accounts/{id}",
            "GET /api/users/me", "PATCH /api/users/me",
            "GET /api/admin/secret",
        ],
    }


@app.post("/api/register")
def register(body: Register):
    global _next_user_id
    uid = _next_user_id
    _next_user_id += 1
    USERS[uid] = {
        "user_id": uid, "username": body.username,
        "password": body.password, "role": "user", "secret": None,
    }
    NOTES.setdefault(uid, [])
    return {"user_id": uid, "role": "user"}


@app.post("/api/login")
def login(body: Login):
    for u in USERS.values():
        if u["username"] == body.username and u["password"] == body.password:
            return {"token": make_token(u["user_id"], u["role"])}
    raise HTTPException(status_code=401, detail="credenciales inválidas")


@app.get("/api/users/me")
def get_me(user=Depends(current_user)):
    uid = user.get("user_id")
    u = USERS.get(uid)
    if not u:
        raise HTTPException(status_code=404, detail="no existe")
    return {k: v for k, v in u.items() if k != "password"}


@app.patch("/api/users/me")
def patch_me(request: Request, user=Depends(current_user), body: dict = Body(...)):
    """VULN #3: MASS ASSIGNMENT.

    Vuelca el body directo sobre el registro del usuario. Acepta `role`,
    `user_id`, `secret`, etc. -> el atacante se asciende a admin.
    """
    uid = user.get("user_id")
    u = USERS.get(uid)
    if not u:
        raise HTTPException(status_code=404, detail="no existe")
    # Sin allow-list: todo lo que venga en el body se asigna.
    for k, v in body.items():
        u[k] = v
    if body.get("role") == "admin":
        emit("scan_detected", "alert", src_ip=request.client.host if request.client else None,
             detail={"vuln": "mass-assignment", "user_id": uid})
    return {k: v for k, v in u.items() if k != "password"}


@app.get("/api/users/{user_id}/notes")
def get_notes(user_id: int, request: Request, user=Depends(current_user)):
    """VULN #2: BOLA. No comprueba que user_id == user del token."""
    if user_id != user.get("user_id"):
        emit("scan_detected", "warn", src_ip=request.client.host if request.client else None,
             detail={"vuln": "bola-notes", "target": user_id, "actor": user.get("user_id")})
    return {"user_id": user_id, "notes": NOTES.get(user_id, [])}


@app.get("/api/accounts/{account_id}")
def get_account(account_id: int, request: Request, user=Depends(current_user)):
    """VULN #2 (bis): BOLA sobre cuentas."""
    acc = ACCOUNTS.get(account_id)
    if not acc:
        raise HTTPException(status_code=404, detail="no existe")
    if acc["owner"] != user.get("user_id"):
        emit("scan_detected", "warn", src_ip=request.client.host if request.client else None,
             detail={"vuln": "bola-account", "target": account_id})
    return acc


@app.get("/api/admin/secret")
def admin_secret(request: Request, user=Depends(current_user)):
    """Entrega la FLAG. Requiere rol admin (alcanzable por mass assignment o
    por forjar un JWT alg=none con role=admin)."""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="solo admin")
    emit("scan_detected", "alert", src_ip=request.client.host if request.client else None,
         detail={"event": "admin-secret-read", "actor": user.get("user_id")})
    return {"secret": FLAG}
