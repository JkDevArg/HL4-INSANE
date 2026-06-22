"""Phantom Cache — pwn-pickle-03 (PWN INSANE).

VULN central: DESERIALIZACION INSEGURA DE PICKLE (RCE) sobre datos del cliente,
encadenada con una FUGA DE CLAVE de firma HMAC que un atacante necesita para
forjar un blob de sesion valido.

Que es "Phantom Cache":
  Un store de sesiones SSO distribuido. El front entrega a cada cliente un
  "session token" que es, literalmente, el ESTADO DE SESION serializado con
  pickle, comprimido en base64 y FIRMADO con HMAC-SHA256 (formato `b64.sig`).
  En cada peticion el servidor recibe ese token, VERIFICA la firma y luego hace
  pickle.loads() del payload para "rehidratar" la sesion. Es el clasico
  anti-patron "encrypt-then-MAC mal entendido": la firma da integridad pero
  NO impide que el contenido sea un gadget de pickle si el atacante conoce la
  clave. pickle.loads() sobre datos no confiables == ejecucion de codigo.

Cadena de explotacion (INSANE — 3 eslabones):

  1) FUGA DE LA CLAVE HMAC. El servicio arrastra un endpoint de debug heredado
     `GET /debug/config` que se "protege" con una comprobacion debil del header
     X-Debug-Token contra os.environ. El detalle: el repositorio del servicio
     quedo expuesto en `/.git/` (montado como estatico por error), y el commit
     que "removio" el token de debug del codigo lo dejo en el historial. El
     atacante recupera DEBUG_TOKEN del .git, llama a /debug/config y obtiene el
     SIGNING_KEY (la clave HMAC usada para firmar/verificar los tokens de
     sesion). [Para mantener el reto autocontenido, el .git expuesto se
     materializa como un endpoint `GET /.git/config` y `GET /.git/logs/HEAD`
     que filtran el DEBUG_TOKEN — simula un .git leakeado sin requerir un repo
     real dentro de la imagen.]

  2) FORJA DEL PICKLE FIRMADO. Con SIGNING_KEY el atacante serializa con pickle
     un objeto cuyo __reduce__ ejecuta un comando (RCE), lo empaqueta como
     base64, calcula el HMAC-SHA256 con la clave filtrada y arma el token
     `b64payload.hexsig`. El servidor lo da por valido (la firma cuadra) y hace
     pickle.loads() -> se ejecuta el gadget.

  3) RCE -> EXFIL DE LA FLAG. El gadget lee la FLAG (env FLAG, tambien escrita a
     /flag.txt al arrancar) y la devuelve. El endpoint /cache/restore refleja el
     resultado de la deserializacion, asi que el atacante recibe la flag en la
     respuesta.

La FLAG se inyecta por equipo via env FLAG. NO hardcodeada.
"""
import base64
import hashlib
import hmac
import os
import pickle  # noqa: S403 — uso INTENCIONALMENTE inseguro (es la vuln del reto)
import secrets
import zlib

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from siem import emit
from reqlog import reqlog_http

app = FastAPI(title="Phantom Cache", docs_url=None, redoc_url=None, openapi_url=None)

# --------------------------------------------------------------------------
# Secretos del servicio.
#   FLAG       : objetivo. Solo por env (con default local). Tambien a /flag.txt
#                para que un RCE "real" (cat /flag.txt) tambien la encuentre.
#   SIGNING_KEY: clave HMAC que firma/verifica los tokens de sesion. Es lo que
#                el atacante debe FILTRAR para poder forjar un pickle valido.
#   DEBUG_TOKEN: token del endpoint de debug heredado. Quedo "olvidado" en el
#                historial .git expuesto (eslabon 1 de la cadena).
# --------------------------------------------------------------------------
FLAG = os.environ.get("FLAG", "flag{EJEMPLO_LOCAL}")
SIGNING_KEY = os.environ.get("SIGNING_KEY", secrets.token_hex(24)).encode()
DEBUG_TOKEN = os.environ.get("DEBUG_TOKEN", "dbg_" + secrets.token_hex(8))

# Materializa la flag tambien en disco: un RCE generico (os.system('cat
# /flag.txt')) tambien la recupera, no solo leer el env.
try:
    with open("/flag.txt", "w", encoding="utf-8") as _f:
        _f.write(FLAG + "\n")
except Exception:
    pass


# --------------------------------------------------------------------------
# Tokens de sesion = pickle(obj) -> zlib -> base64  +  HMAC-SHA256(b64).
# Formato en el wire:  "<b64payload>.<hexsig>".
# --------------------------------------------------------------------------
def _sign(payload_b64: bytes) -> str:
    return hmac.new(SIGNING_KEY, payload_b64, hashlib.sha256).hexdigest()


def _pack_session(obj) -> str:
    """Serializa una sesion a un token firmado (lo que el server entrega)."""
    raw = pickle.dumps(obj)
    payload_b64 = base64.b64encode(zlib.compress(raw))
    sig = _sign(payload_b64)
    return payload_b64.decode() + "." + sig


def _unpack_session(token: str):
    """Verifica la firma y deserializa.

    VULN: tras verificar el HMAC, hace pickle.loads() sobre el contenido. La
    firma SOLO garantiza integridad; si el atacante conoce SIGNING_KEY puede
    firmar CUALQUIER pickle (incluido un gadget __reduce__) y pasara la
    verificacion -> RCE.
    """
    if "." not in token:
        raise ValueError("formato de token invalido (falta firma)")
    payload_b64, _, sig = token.rpartition(".")
    expected = _sign(payload_b64.encode())
    # Comparacion en tiempo constante: la firma NO es el punto debil del reto.
    if not hmac.compare_digest(sig, expected):
        raise ValueError("firma HMAC invalida")
    raw = zlib.decompress(base64.b64decode(payload_b64))
    return pickle.loads(raw)  # noqa: S301 — deserializacion insegura = la vuln


# --------------------------------------------------------------------------
# Middleware ASGI PURO: loguea CADA peticion COMPLETA para el SIEM del stream
# (linea CTFREQ via reqlog). Copiado tal cual de api-cache-05 (lee el body
# completo y lo reinyecta para los handlers).
# --------------------------------------------------------------------------
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
            query = (scope.get("query_string") or b"").decode("latin-1")
            reqlog_http(
                src_ip=src_ip,
                method=scope.get("method", "?"),
                path=scope.get("path", "/"),
                query=query,
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


def _client_ip(request: Request) -> str | None:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


# --------------------------------------------------------------------------
# Portada / ayuda.
# --------------------------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def root():
    return {
        "app": "Phantom Cache",
        "desc": "Store de sesiones SSO distribuido. Tu token de sesion ES tu "
                "estado serializado y firmado.",
        "endpoints": [
            "GET  /cache/new       -> emite un token de sesion firmado",
            "POST /cache/restore   -> rehidrata una sesion desde tu token (body: token=...)",
            "GET  /debug/config    -> [heredado] requiere header X-Debug-Token",
        ],
        "note": "El token tiene formato '<payload_b64>.<hmac_sha256>'.",
    }


# --------------------------------------------------------------------------
# Emite un token de sesion legitimo (para que el jugador vea el formato).
# --------------------------------------------------------------------------
@app.get("/cache/new")
def cache_new():
    session = {
        "uid": "guest-" + secrets.token_hex(4),
        "role": "guest",
        "scopes": ["read"],
        "phantom": True,
    }
    token = _pack_session(session)
    return {"token": token, "session": session}


# --------------------------------------------------------------------------
# VULN central — rehidrata la sesion: verifica HMAC y luego pickle.loads().
# --------------------------------------------------------------------------
@app.post("/cache/restore")
async def cache_restore(request: Request):
    # Acepta token por form (token=...), por JSON {"token": "..."} o por header.
    token = None
    ctype = request.headers.get("content-type", "")
    body = await request.body()
    if "application/json" in ctype:
        try:
            import json
            token = (json.loads(body or b"{}") or {}).get("token")
        except Exception:
            token = None
    else:
        # form-urlencoded: token=...
        try:
            from urllib.parse import parse_qs
            qs = parse_qs(body.decode("utf-8", "replace"))
            token = (qs.get("token") or [None])[0]
        except Exception:
            token = None
    if not token:
        token = request.headers.get("x-session-token")
    if not token:
        raise HTTPException(status_code=400, detail="falta 'token' (form, json o header X-Session-Token)")

    try:
        session = _unpack_session(token)
    except ValueError as exc:
        emit(
            "scan_detected", "warn",
            src_ip=_client_ip(request),
            detail={"vuln": "pickle-restore", "result": "rechazado", "reason": str(exc)},
        )
        raise HTTPException(status_code=400, detail=f"token invalido: {exc}")

    # Si la firma cuadra, el server CONFIA y deserializa. Si fue un gadget de
    # pickle, ya se ejecuto en _unpack_session(); aqui solo reflejamos el
    # resultado para que el atacante reciba la salida del RCE.
    emit(
        "scan_detected", "alert",
        src_ip=_client_ip(request),
        detail={"vuln": "pickle-restore", "result": "deserializado", "type": type(session).__name__},
    )
    return JSONResponse({"status": "ok", "session": _safe_repr(session)})


def _safe_repr(obj):
    """Refleja el objeto deserializado de forma JSON-segura (incluye el
    resultado de un gadget __reduce__, que tipicamente es str/bytes)."""
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8", "replace")
        except Exception:
            return obj.hex()
    if isinstance(obj, dict):
        return {str(k): _safe_repr(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_safe_repr(v) for v in obj]
    return repr(obj)


# --------------------------------------------------------------------------
# Eslabon 1 — FUGA DE CLAVE.
#
# (a) El ".git" expuesto: simulamos un repo leakeado. /.git/config y
#     /.git/logs/HEAD filtran el DEBUG_TOKEN que un commit "olvido".
# (b) /debug/config: protegido con X-Debug-Token (== DEBUG_TOKEN). Devuelve la
#     config interna, incluida SIGNING_KEY.
# --------------------------------------------------------------------------
@app.get("/.git/config")
def git_config():
    body = (
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = false\n"
        "[remote \"origin\"]\n"
        "\turl = git@git.phantom.internal:sso/phantom-cache.git\n"
        "[branch \"main\"]\n"
        "\tremote = origin\n"
    )
    return PlainTextResponse(body)


@app.get("/.git/logs/HEAD")
def git_logs_head(request: Request):
    """El historial filtra el commit que 'removio' el token de debug del codigo
    pero lo dejo plano en el mensaje del commit."""
    emit(
        "scan_detected", "warn",
        src_ip=_client_ip(request),
        detail={"vuln": "git-exposed", "path": "/.git/logs/HEAD"},
    )
    line = (
        "0000000000000000000000000000000000000000 a1b2c3d4 dev <dev@phantom.internal> "
        "1700000000 +0000\tcommit (initial): bootstrap phantom-cache sso store\n"
        "a1b2c3d4 e5f6a7b8 dev <dev@phantom.internal> "
        f"1700000100 +0000\tcommit: chore: drop hardcoded debug token "
        f"(was X-Debug-Token: {DEBUG_TOKEN}) — move behind env\n"
    )
    return PlainTextResponse(line)


@app.get("/debug/config")
def debug_config(request: Request, x_debug_token: str | None = Header(default=None)):
    """Endpoint de debug heredado. 'Protegido' por X-Debug-Token. Si cuadra,
    filtra la config interna incluida SIGNING_KEY -> el atacante ya puede forjar
    tokens de sesion (pickle firmado)."""
    if not x_debug_token or not hmac.compare_digest(x_debug_token, DEBUG_TOKEN):
        emit(
            "scan_detected", "warn",
            src_ip=_client_ip(request),
            detail={"vuln": "debug-endpoint", "result": "denegado"},
        )
        raise HTTPException(status_code=401, detail="X-Debug-Token requerido/invalido")

    emit(
        "scan_detected", "alert",
        src_ip=_client_ip(request),
        detail={"vuln": "debug-endpoint", "result": "config-filtrada"},
    )
    return {
        "service": "phantom-cache",
        "session_format": "base64(zlib(pickle)).hmac_sha256",
        "signing_key": SIGNING_KEY.decode(),
        "signing_algo": "HMAC-SHA256",
        "warning": "rotar SIGNING_KEY antes de prod",
    }
