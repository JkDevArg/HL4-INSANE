"""EdgeNews API — api-cache-05 (API INSANE · "Poisoned Edge").

VULN central: WEB CACHE DECEPTION detras de un CDN/edge simulado (nginx).

Topologia:
  jugador --> nginx (edge cache, .24:8080) --> api:8000 (este servicio)

Cadena de explotacion (INSANE):

  1) PATH CONFUSION en la API: el router de FastAPI hace "prefix match" laxo
     sobre /api/v1/profile, de modo que /api/v1/profile/cualquier-cosa.css
     devuelve EXACTAMENTE la misma respuesta sensible que /api/v1/profile
     (datos del usuario autenticado por su cookie de sesion). La extension
     ".css" en la URL es puro ruido para la API, pero NO para el edge.

  2) CACHE-KEY INSEGURO en el edge (nginx): el edge cachea por path+extension
     y IGNORA la cookie y el Cache-Control de respuestas que "parecen"
     estaticas (terminan en .css/.js o cuelgan de /static/). Asi, la respuesta
     PERSONALIZADA de un usuario autenticado acaba guardada en una clave de
     cache PUBLICA, servible a cualquiera sin cookie.

  3) VICTIMA (admin-bot): hay un bot admin interno (thread) que, cada pocos
     segundos, desencola las URLs que un atacante "comparte" via
     POST /api/v1/share?url=... y las visita CON SU PROPIA COOKIE de sesion
     admin. Si el atacante encola /api/v1/profile/x.css, el bot pide esa URL
     autenticado como admin -> el edge cachea la respuesta del admin (que
     incluye su session_token) bajo una clave .css publica.

  4) El atacante pide DESPUES la misma URL .css (sin cookie). El edge le sirve
     la copia cacheada del PERFIL DEL ADMIN -> obtiene el session_token admin
     -> con esa cookie lee GET /api/v1/admin/flag -> FLAG.

La FLAG se inyecta por equipo via env FLAG. NO hardcodeada.
"""
import os
import secrets
import threading
import time
from collections import deque

from fastapi import Cookie, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from siem import emit
from reqlog import reqlog_http

app = FastAPI(title="EdgeNews API", docs_url=None, redoc_url=None, openapi_url=None)

FLAG = os.environ.get("FLAG", "HL4{EJEMPLO_LOCAL}")

# El bot admin pide URLs a traves del edge (nginx), no directo a la API, para
# que el edge sea quien cachee. En la red de equipo el edge es "cache:8080".
EDGE_BASE = os.environ.get("EDGE_BASE", "http://cache:8080")
BOT_INTERVAL = float(os.environ.get("BOT_INTERVAL", "4.0"))


# --------------------------------------------------------------------------
# "Base de datos" de sesiones en memoria.
#   - El admin tiene una sesion fija (su session_token es el secreto a robar).
#   - Los jugadores se registran y reciben su propia sesion.
# --------------------------------------------------------------------------
ADMIN_TOKEN = "adm_" + secrets.token_hex(20)

SESSIONS: dict[str, dict] = {
    ADMIN_TOKEN: {
        "username": "admin",
        "role": "admin",
        "email": "admin@edgenews.internal",
        "session_token": ADMIN_TOKEN,
        "note": "Sesion privilegiada. NO compartir este token.",
    },
}


def _new_user_session(username: str) -> str:
    tok = "usr_" + secrets.token_hex(20)
    SESSIONS[tok] = {
        "username": username,
        "role": "user",
        "email": f"{username}@edgenews.example",
        "session_token": tok,
        "note": "Sesion de lector estandar.",
    }
    return tok


# --------------------------------------------------------------------------
# Middleware ASGI PURO: loguea CADA peticion COMPLETA para el SIEM del stream
# (linea CTFREQ via reqlog). Mismo CONTRATO que api-bola-01 (lee el body
# completo y lo reinyecta para los handlers), pero implementado como middleware
# ASGI puro para no romper el listener de desconexion de Starlette.
# --------------------------------------------------------------------------
class ReqLogMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Buffer del body completo (los handlers lo vuelven a leer reinyectado).
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

        # Reinyecta el body bufferizado para los handlers aguas abajo.
        _sent = False

        async def _receive():
            nonlocal _sent
            if not _sent:
                _sent = True
                return {"type": "http.request", "body": raw, "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, _receive, send)


app.add_middleware(ReqLogMiddleware)


def _session_from_cookie(session: str | None) -> dict | None:
    if not session:
        return None
    return SESSIONS.get(session)


# --------------------------------------------------------------------------
# Endpoints publicos / de portada
# --------------------------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def root():
    return {
        "app": "EdgeNews",
        "edge": "servido tras un CDN de borde (cache estatico agresivo)",
        "endpoints": [
            "POST /api/v1/register   -> crea lector y devuelve cookie 'session'",
            "GET  /api/v1/profile    -> tu perfil (requiere cookie 'session')",
            "POST /api/v1/share?url= -> el editor (admin-bot) revisa el enlace",
            "GET  /api/v1/admin/flag -> solo admin",
        ],
        "hint": "El editor jefe revisa cada enlace que le compartes con su propia sesion.",
    }


@app.post("/api/v1/register")
def register(username: str = Query(default="lector")):
    tok = _new_user_session(username)
    resp = JSONResponse({"username": username, "role": "user", "session_token": tok})
    # cookie de sesion (el jugador la usa para SUS propias peticiones)
    resp.set_cookie("session", tok, httponly=False, samesite="lax")
    return resp


# --------------------------------------------------------------------------
# VULN #1 — PATH CONFUSION
#
# Una sola funcion sirve /api/v1/profile y CUALQUIER /api/v1/profile/<resto>.
# El "resto" (incluida una extension .css/.js) se ignora por completo: la
# respuesta es siempre el perfil del usuario autenticado por la cookie.
#
# La respuesta marca Cache-Control: private, no-store ... pero el edge la
# ignora para URLs que "parecen" estaticas (ver nginx). Ese es el bug del edge.
# --------------------------------------------------------------------------
def _render_profile(sess: dict) -> Response:
    body = (
        "EdgeNews — Perfil de usuario\n"
        f"usuario: {sess['username']}\n"
        f"rol: {sess['role']}\n"
        f"email: {sess['email']}\n"
        f"session_token: {sess['session_token']}\n"
        f"nota: {sess['note']}\n"
    )
    resp = PlainTextResponse(body)
    # La API SI intenta protegerse: marca la respuesta como privada.
    # El fallo esta en el EDGE, que no respeta esto para rutas *.css/*.js.
    resp.headers["Cache-Control"] = "private, no-store, max-age=0"
    return resp


@app.get("/api/v1/profile")
def profile_root(session: str | None = Cookie(default=None)):
    sess = _session_from_cookie(session)
    if not sess:
        raise HTTPException(status_code=401, detail="sesion requerida (cookie 'session')")
    return _render_profile(sess)


@app.get("/api/v1/profile/{tail:path}")
def profile_path_confusion(tail: str, request: Request, session: str | None = Cookie(default=None)):
    """VULN #1: el sufijo arbitrario (p.ej. 'avatar.css') se descarta y se
    devuelve el MISMO perfil sensible. Esto es lo que permite que una URL
    'estatica' (.css) entregue contenido autenticado."""
    sess = _session_from_cookie(session)
    if not sess:
        raise HTTPException(status_code=401, detail="sesion requerida (cookie 'session')")
    if tail and (tail.endswith(".css") or tail.endswith(".js") or "/" in tail):
        emit(
            "scan_detected", "warn",
            src_ip=request.client.host if request.client else None,
            detail={"vuln": "path-confusion", "tail": tail[:120], "actor": sess["username"]},
        )
    return _render_profile(sess)


# --------------------------------------------------------------------------
# VICTIMA — el admin-bot revisa enlaces compartidos
#
# Cola de URLs que los jugadores comparten. Un thread interno las visita a
# traves del EDGE con la cookie de sesion del admin. Asi el edge cachea la
# respuesta del admin si la URL parece estatica.
# --------------------------------------------------------------------------
_share_queue: "deque[str]" = deque(maxlen=200)
_queue_lock = threading.Lock()


@app.post("/api/v1/share")
def share(request: Request, url: str = Query(...)):
    """El atacante 'comparte' un enlace con el editor (admin-bot). Solo se
    aceptan rutas relativas de EdgeNews para que el bot las visite en su propio
    dominio CON su cookie admin. Devuelve rapido; el bot procesa async."""
    # Normaliza a ruta relativa: el bot SOLO navega dentro de EdgeNews.
    path = url.strip()
    # Si viene una URL absoluta, quedarnos con el path (defensa minima: el bot
    # no sale del sitio; aun asi la vuln de cache deception es interna).
    for prefix in ("http://", "https://"):
        if path.lower().startswith(prefix):
            rest = path[len(prefix):]
            slash = rest.find("/")
            path = rest[slash:] if slash != -1 else "/"
            break
    if not path.startswith("/"):
        path = "/" + path

    with _queue_lock:
        _share_queue.append(path)

    emit(
        "scan_detected", "warn",
        src_ip=request.client.host if request.client else None,
        detail={"event": "share-submitted", "path": path[:160]},
    )
    return {"status": "encolado", "path": path, "msg": "El editor jefe revisara tu enlace en breve."}


def _admin_bot_loop():
    """Thread interno: simula a un admin que abre cada enlace compartido CON SU
    cookie de sesion, a traves del edge. Es la 'victima' del cache deception."""
    import urllib.request

    # Espera a que el edge este arriba.
    time.sleep(3.0)
    while True:
        try:
            path = None
            with _queue_lock:
                if _share_queue:
                    path = _share_queue.popleft()
            if path:
                target = EDGE_BASE.rstrip("/") + path
                req = urllib.request.Request(target, method="GET")
                # La cookie ADMIN viaja en la peticion del bot -> respuesta sensible.
                req.add_header("Cookie", f"session={ADMIN_TOKEN}")
                req.add_header("User-Agent", "EdgeNews-EditorBot/1.0")
                try:
                    urllib.request.urlopen(req, timeout=4.0).read()
                except Exception:
                    pass
            else:
                time.sleep(BOT_INTERVAL)
        except Exception:
            time.sleep(BOT_INTERVAL)


@app.on_event("startup")
def _start_bot():
    t = threading.Thread(target=_admin_bot_loop, daemon=True)
    t.start()


# --------------------------------------------------------------------------
# Objetivo final: la flag, solo para sesion admin.
# --------------------------------------------------------------------------
@app.get("/api/v1/admin/flag")
def admin_flag(request: Request, session: str | None = Cookie(default=None)):
    sess = _session_from_cookie(session)
    if not sess or sess.get("role") != "admin":
        raise HTTPException(status_code=403, detail="solo admin")
    emit(
        "scan_detected", "alert",
        src_ip=request.client.host if request.client else None,
        detail={"event": "admin-flag-read", "actor": sess.get("username")},
    )
    return {"flag": FLAG}
