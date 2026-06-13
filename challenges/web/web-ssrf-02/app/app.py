"""PixelForge — web-ssrf-02 (Web INSANE).

Vulnerabilidad central: SSRF CIEGO con bypass de filtro hasta un endpoint de
metadata interno (estilo cloud metadata 169.254.169.254, aquí simulado en la
red del equipo como el servicio `metadata` -> 172.30.N.13).

El servicio "PixelForge" descarga una imagen desde una URL que tú le das
(/api/fetch) y devuelve SOLO metadatos del recurso descargado (tamaño, tipo,
hash) -> es un SSRF *ciego* (no te devuelve el cuerpo crudo de forma directa).

Defensa (deliberadamente rota):
  1) Bloquea hosts "obvios": localhost, metadata, 127.0.0.1, 169.254.169.254 y
     los rangos privados/loopback/link-local que logre PARSEAR.
  2) VULN PRINCIPAL — extracción de host ingenua: para validar, el filtro toma
     "lo que hay antes del '@'" como host (asume que no hay userinfo). Pero la
     librería HTTP (requests/urllib3) trata correctamente esa parte como
     userinfo y se CONECTA al host que va DESPUÉS del '@'. Divergencia de
     parsers -> el atacante hace que el filtro vea un host de confianza y la
     petición salga hacia el metadata interno.
       http://<host-confiable>%2f@metadata:8080/latest/meta-data/...
  3) VULN SECUNDARIA — SSRF-via-redirect: el host se valida ANTES de seguir
     redirects y NO se revalida el Location (TOCTOU).

Cadena INSANE para resolver:
  - Bypass del filtro con la confusión de parser (`%2f@`) apuntando a `metadata`.
  - Llegas al metadata interno: GET http://metadata:8080/latest/meta-data/
  - Enumeras: .../iam/security-credentials/  -> nombre del rol
  - Lees el rol: .../iam/security-credentials/<rol>  -> JSON con la FLAG
    (campo "Token"). Ese rol expone el secreto SOLO a peticiones que vienen
    desde dentro (con el User-Agent del fetcher), nunca a un navegador.

La FLAG se inyecta por equipo vía env FLAG. NO hardcodeada.
"""
import hashlib
import ipaddress
import os
import socket
import urllib.parse

import requests
from flask import Flask, Response, jsonify, request

from siem import emit
from reqlog import reqlog_http

app = Flask(__name__)


@app.before_request
def _log_request():
    """Loguea CADA petición entrante COMPLETA (método, ruta, query, headers,
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

FLAG = os.environ.get("FLAG", "flag{EJEMPLO_LOCAL}")
# Host interno del servicio de metadata (otro contenedor del MISMO equipo).
METADATA_HOST = os.environ.get("METADATA_HOST", "metadata")

FETCH_UA = "PixelForge-Fetcher/2.1"
FETCH_TIMEOUT = 4.0
MAX_REDIRECTS = 5

# Hosts/redes que el filtro intenta bloquear.
BLOCKED_NAMES = {"localhost", "metadata", "metadata.internal", "metadata.google.internal"}
BLOCKED_LITERALS = {"127.0.0.1", "169.254.169.254", "0.0.0.0", "::1"}


# --------------------------------------------------------------------------
# Filtro de SSRF (deliberadamente débil)
# --------------------------------------------------------------------------
def _is_blocked_ip(ip_str: str) -> bool:
    """Bloquea loopback / link-local / privadas SI logra parsear la IP."""
    try:
        ip = ipaddress.ip_address(ip_str.strip("[]"))
    except ValueError:
        return False
    return ip.is_loopback or ip.is_link_local or ip.is_private


def _extract_host_naive(netloc: str) -> str:
    """VULN PRINCIPAL: extracción de host INGENUA.

    Un montón de filtros caseros hacen exactamente esto: cortan en '@' y se
    quedan con la PRIMERA parte como host, asumiendo que no hay userinfo. Pero
    `requests`/urllib3 tratan esa parte como credenciales y se conectan al host
    que va DESPUÉS del '@'. Esa divergencia es el bypass:

        netloc = "trusted.cdn%2f@metadata:8080"
        filtro ve host = "trusted.cdn%2f"   (permitido)
        requests conecta a "metadata:8080"  (interno!)
    """
    first = netloc.split("@", 1)[0]      # <- toma lo de ANTES del '@' (el bug)
    host = first.split(":", 1)[0]        # quita puerto
    return host.strip().lower().strip(".")


def host_allowed(netloc: str) -> bool:
    """Valida el `netloc` con la extracción ingenua y el block-list."""
    h = _extract_host_naive(netloc)
    if not h:
        return False
    if h in BLOCKED_NAMES:
        return False
    if h in BLOCKED_LITERALS:
        return False
    if _is_blocked_ip(h):
        return False
    return True


def _fetch_once(url: str):
    """Una petición SIN seguir redirects (para poder inspeccionar el Location)."""
    return requests.get(
        url,
        headers={"User-Agent": FETCH_UA, "Accept": "*/*"},
        timeout=FETCH_TIMEOUT,
        allow_redirects=False,
        stream=True,
    )


def fetch_with_manual_redirects(url: str, src_ip: str | None):
    """Sigue redirects MANUALMENTE pero — la vuln #2 — solo valida el host de
    la PRIMERA URL. Los `Location` de las redirecciones se siguen sin volver a
    pasar por host_allowed(). SSRF-via-redirect."""
    current = url
    for hop in range(MAX_REDIRECTS + 1):
        parsed = urllib.parse.urlsplit(current)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("esquema no permitido")

        resp = _fetch_once(current)

        # Detección/telemetría: ¿el destino real resolvió a algo interno?
        try:
            real_ip = socket.gethostbyname(parsed.hostname or "")
            if _is_blocked_ip(real_ip) or (parsed.hostname or "").lower() == METADATA_HOST:
                emit("scan_detected", "alert", src_ip=src_ip,
                     detail={"vuln": "ssrf-internal-hit", "url": current, "resolved": real_ip})
        except OSError:
            pass

        if resp.is_redirect and "Location" in resp.headers:
            current = urllib.parse.urljoin(current, resp.headers["Location"])
            resp.close()
            continue  # <- NO se revalida el nuevo host (la trampa)
        return resp, current
    raise ValueError("demasiados redirects")


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------
INDEX = """<!doctype html><html lang="es"><head><meta charset="utf-8">
<title>PixelForge</title></head><body style="font-family:sans-serif;max-width:760px;margin:2rem auto">
<h1>PixelForge &middot; Avatar Importer</h1>
<p>Importa un avatar desde una URL pública. Procesamos la imagen y te
devolvemos sus metadatos (tamaño, tipo, hash). Por seguridad, el acceso a la
red interna y al endpoint de metadata del proveedor cloud está <b>bloqueado</b>.</p>
<form onsubmit="ev(event)">
  <input id="u" style="width:70%" placeholder="https://ejemplo.com/avatar.png" value="https://example.com/">
  <button>Importar</button>
</form>
<pre id="out" style="background:#111;color:#0f0;padding:1rem;white-space:pre-wrap"></pre>
<p style="color:#888">API: <code>POST /api/fetch {"url": "..."}</code></p>
<script>
async function ev(e){e.preventDefault();
 const r=await fetch('/api/fetch',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({url:document.getElementById('u').value})});
 document.getElementById('out').textContent=JSON.stringify(await r.json(),null,2);}
</script></body></html>"""


@app.get("/")
def index():
    return Response(INDEX, mimetype="text/html")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/fetch")
def api_fetch():
    src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "falta 'url'"}), 400

    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        return jsonify({"error": "solo http/https"}), 400

    # El filtro valida el `netloc` con su extracción ingenua de host (la vuln).
    if not host_allowed(parsed.netloc):
        emit("scan_detected", "warn", src_ip=src_ip,
             detail={"vuln": "ssrf-blocked-host", "netloc": parsed.netloc})
        return jsonify({"error": "host no permitido (red interna bloqueada)"}), 403

    try:
        resp, final_url = fetch_with_manual_redirects(url, src_ip)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"no se pudo importar: {exc}"}), 502

    body = resp.raw.read(64 * 1024, decode_content=True) or b""
    resp.close()
    ctype = resp.headers.get("Content-Type", "application/octet-stream")

    # SSRF CIEGO: devolvemos metadatos del recurso, no el cuerpo crudo... salvo
    # que el recurso se identifique como metadata interno (texto/json), en cuyo
    # caso PixelForge lo trata como "perfil" y lo refleja. Eso cierra la cadena.
    out = {
        "imported": True,
        "final_url": final_url,
        "content_type": ctype,
        "bytes": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
    }
    if ctype.startswith(("text/", "application/json")):
        out["preview"] = body.decode("utf-8", errors="replace")[:2048]
    return jsonify(out)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
