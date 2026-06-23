"""LedgerPay API — api-bola-02 "Mass Assignment Heist" (API INSANE).

Plataforma de facturación B2B. Las cuentas tienen un `tier` (free/pro/
enterprise) y un `org_role` (member/org_admin). Solo un `org_admin` puede
leer los secretos de la organización (la FLAG vive en GET /api/v1/org/secrets).

CADENA DE EXPLOTACIÓN (mass assignment encadenado, no un solo campo):

  Paso 1 — MASS ASSIGNMENT sobre el PERFIL:
    PATCH /api/v1/accounts/me acepta un modelo Pydantic con `extra=allow`,
    y luego vuelca TODOS los campos (incluidos los extra) sobre el registro
    de la cuenta. Un usuario raso (`tier=free`) puede inyectar `tier`,
    `credit_limit`, etc. Subirse a `tier=enterprise` desbloquea el flujo de
    aprobación de facturas (que normalmente solo ven cuentas enterprise).

  Paso 2 — MASS ASSIGNMENT sobre la APROBACIÓN:
    POST /api/v1/invoices/{id}/approve solo está disponible para enterprise.
    El cuerpo de aprobación TAMBIÉN es mass-assignable: acepta un campo
    `approver_role`. El backend confía en ese valor y, si la aprobación se
    sella con `approver_role=org_admin`, PROMUEVE la cuenta del aprobador a
    `org_role=org_admin` (regla de negocio: "quien aprueba como org_admin ES
    reconocido como org_admin"). Además la factura debe quedar `approved`.

  Paso 3 — LECTURA DEL SECRETO:
    GET /api/v1/org/secrets exige `org_role=org_admin`. Ahí está la FLAG.

Por qué INSANE: no basta con poner `role=admin`. Hay que (a) descubrir que el
perfil es mass-assignable, (b) entender que `tier=enterprise` es un gate de
negocio para la ruta de aprobación, (c) descubrir que la aprobación ADEMÁS es
mass-assignable y que `approver_role` reescribe el rol org. Son 2 mass
assignments encadenados + comprensión del flujo de facturación.

La FLAG se inyecta por equipo vía env FLAG. NO hardcodeada.
"""
import os
import secrets
import time

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from siem import emit
from reqlog import reqlog_http

app = FastAPI(title="LedgerPay API", docs_url=None, redoc_url=None, openapi_url=None)


# Middleware ASGI PURO (no @app.middleware("http")): el override de
# request._receive sobre BaseHTTPMiddleware rompe el body en starlette 0.37.x.
class ReqLogMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        chunks: list[bytes] = []
        more = True
        while more:
            message = await receive()
            if message["type"] == "http.request":
                chunks.append(message.get("body", b"") or b"")
                more = message.get("more_body", False)
            elif message["type"] == "http.disconnect":
                more = False
        raw = b"".join(chunks)
        try:
            headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in scope.get("headers", [])}
            src_ip = headers.get("x-forwarded-for")
            if src_ip and "," in src_ip:
                src_ip = src_ip.split(",")[0].strip()
            if not src_ip:
                client = scope.get("client")
                src_ip = client[0] if client else "?"
            reqlog_http(
                src_ip=src_ip,
                method=scope.get("method", "?"),
                path=scope.get("path", "/"),
                query=(scope.get("query_string") or b"").decode("latin-1"),
                headers=headers,
                body=raw,
            )
        except Exception:
            pass
        _sent = False

        async def _receive():
            nonlocal _sent
            if not _sent:
                _sent = True
                return {"type": "http.request", "body": raw, "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, _receive, send)


app.add_middleware(ReqLogMiddleware)


FLAG = os.environ.get("FLAG", "HL4{EJEMPLO_LOCAL}")

# --- "Base de datos" en memoria ---
# Cada cuenta es un registro mass-assignable. token -> account_id.
# Una cuenta "seed" enterprise/org_admin existe pero su token no es accesible
# (no se puede loguear sin credenciales que no se conocen); está solo para
# tener una org con secretos. El jugador crea SU cuenta y debe escalar.
ACCOUNTS: dict[int, dict] = {}
TOKENS: dict[str, int] = {}
INVOICES: dict[int, dict] = {}

_next_account_id = 1000
_next_invoice_id = 5000

ORG_SECRETS = {
    # El premio. Solo visible para org_role == "org_admin".
    "ledger_master_key": FLAG,
    "note": "Clave maestra del ledger corporativo. Restringida a org_admin.",
}


def _new_account(email: str, name: str) -> dict:
    """Crea una cuenta raso: tier=free, org_role=member. Sin privilegios."""
    global _next_account_id
    aid = _next_account_id
    _next_account_id += 1
    acc = {
        "account_id": aid,
        "email": email,
        "name": name,
        "tier": "free",            # free < pro < enterprise
        "credit_limit": 0,
        "org_role": "member",      # member < org_admin (gate del secreto)
        "verified": False,
    }
    ACCOUNTS[aid] = acc
    return acc


def _seed_invoice(account_id: int) -> dict:
    """Crea una factura pendiente asociada a una cuenta (para aprobar)."""
    global _next_invoice_id
    iid = _next_invoice_id
    _next_invoice_id += 1
    inv = {
        "invoice_id": iid,
        "account_id": account_id,
        "amount": 1000,
        "currency": "PEN",
        "status": "pending",       # pending -> approved
        "approver_role": None,
    }
    INVOICES[iid] = inv
    return inv


def current_account(authorization: str = Header(default="")) -> dict:
    """Auth por token simple (opaco) emitido en el registro."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="falta Bearer token")
    token = authorization[7:]
    aid = TOKENS.get(token)
    if aid is None or aid not in ACCOUNTS:
        raise HTTPException(status_code=401, detail="token inválido")
    return ACCOUNTS[aid]


# ---------------- Schemas ----------------
class Register(BaseModel):
    email: str
    name: str


class AccountPatch(BaseModel):
    """VULN #1: el modelo permite campos EXTRA (mass assignment).

    Solo `name` y `email` deberían ser editables por el usuario, pero
    `extra="allow"` deja pasar `tier`, `credit_limit`, `org_role`, etc.
    El handler vuelca model_dump() COMPLETO sobre el registro.
    """
    model_config = ConfigDict(extra="allow")
    name: str | None = None
    email: str | None = None


class ApprovePatch(BaseModel):
    """VULN #2: el cuerpo de aprobación también admite campos EXTRA.

    Lo "normal" sería un body vacío o `{comment}`. Pero `extra="allow"` deja
    inyectar `approver_role`, que el backend trata como rol con el que se
    sella la aprobación (y promueve la cuenta del aprobador).
    """
    model_config = ConfigDict(extra="allow")
    comment: str | None = None


# ---------------- Endpoints ----------------
@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def root():
    return {
        "api": "LedgerPay",
        "version": "v1",
        "endpoints": [
            "POST /api/v1/accounts/register",
            "GET  /api/v1/accounts/me",
            "PATCH /api/v1/accounts/me",
            "GET  /api/v1/invoices",
            "POST /api/v1/invoices/{id}/approve  (solo tier=enterprise)",
            "GET  /api/v1/org/secrets            (solo org_role=org_admin)",
        ],
        "docs": "Edita tu perfil con PATCH /api/v1/accounts/me. Solo name/email.",
    }


@app.post("/api/v1/accounts/register")
def register(body: Register):
    """Alta de cuenta. Siempre tier=free, org_role=member. Devuelve token y
    una factura pendiente lista para (intentar) aprobar."""
    token = secrets.token_hex(24)
    acc = _new_account(body.email, body.name)
    TOKENS[token] = acc["account_id"]
    inv = _seed_invoice(acc["account_id"])
    return {
        "token": token,
        "account": acc,
        "pending_invoice_id": inv["invoice_id"],
    }


@app.get("/api/v1/accounts/me")
def get_me(acc=Depends(current_account)):
    return acc


@app.patch("/api/v1/accounts/me")
def patch_me(request: Request, acc=Depends(current_account), body: AccountPatch = Body(...)):
    """VULN #1: MASS ASSIGNMENT del perfil.

    Vuelca model_dump() ENTERO (incluidos campos extra) sobre el registro.
    Sin allow-list: el atacante puede setear `tier`, `credit_limit`, `org_role`...
    Nota: setear directamente `org_role=org_admin` aquí da acceso, PERO el
    flujo "esperado/realista" es subir tier y luego abusar de la aprobación;
    ambos caminos cuentan. Lo difícil es DESCUBRIR los nombres de campo.
    """
    incoming = body.model_dump(exclude_unset=True)
    # account_id es inmutable (no lo dejamos reescribir para no romper el store).
    incoming.pop("account_id", None)
    for k, v in incoming.items():
        acc[k] = v
    extras = [k for k in incoming if k not in ("name", "email")]
    if extras:
        emit("scan_detected", "alert",
             src_ip=request.client.host if request.client else None,
             detail={"vuln": "mass-assignment-profile",
                     "account_id": acc["account_id"], "fields": extras})
    return acc


@app.get("/api/v1/invoices")
def list_invoices(acc=Depends(current_account)):
    """Lista las facturas de la cuenta actual."""
    mine = [i for i in INVOICES.values() if i["account_id"] == acc["account_id"]]
    return {"invoices": mine}


@app.post("/api/v1/invoices/{invoice_id}/approve")
def approve_invoice(invoice_id: int, request: Request,
                    acc=Depends(current_account), body: ApprovePatch = Body(default=None)):
    """Aprobación de factura. GATE de negocio: solo tier=enterprise.

    VULN #2: el body es mass-assignable. Si trae `approver_role`, se sella la
    aprobación con ese rol y, cuando es `org_admin`, la cuenta del aprobador
    se PROMUEVE a org_role=org_admin (regla: el que aprueba como org_admin lo
    es). Esto encadena con el paso 1 (haber subido a enterprise).
    """
    if acc.get("tier") != "enterprise":
        raise HTTPException(
            status_code=403,
            detail="aprobar facturas requiere tier=enterprise",
        )
    inv = INVOICES.get(invoice_id)
    if not inv:
        raise HTTPException(status_code=404, detail="factura no existe")

    payload = body.model_dump(exclude_unset=True) if body is not None else {}
    approver_role = payload.get("approver_role", "member")

    inv["status"] = "approved"
    inv["approver_role"] = approver_role
    inv["approved_by"] = acc["account_id"]

    promoted = False
    if approver_role == "org_admin":
        # Regla de negocio (deliberadamente insegura): el aprobador que firma
        # como org_admin queda reconocido como org_admin de la organización.
        acc["org_role"] = "org_admin"
        promoted = True
        emit("scan_detected", "alert",
             src_ip=request.client.host if request.client else None,
             detail={"vuln": "mass-assignment-approve",
                     "account_id": acc["account_id"], "invoice_id": invoice_id})

    return {"invoice": inv, "org_role": acc["org_role"], "promoted": promoted}


@app.get("/api/v1/org/secrets")
def org_secrets(request: Request, acc=Depends(current_account)):
    """Entrega la FLAG. Requiere org_role=org_admin (alcanzable solo por la
    cadena de mass assignment)."""
    if acc.get("org_role") != "org_admin":
        raise HTTPException(status_code=403, detail="solo org_admin")
    emit("scan_detected", "alert",
         src_ip=request.client.host if request.client else None,
         detail={"event": "org-secrets-read", "account_id": acc["account_id"]})
    return {"org_secrets": ORG_SECRETS, "ts": int(time.time())}
