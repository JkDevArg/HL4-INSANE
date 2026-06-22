"""reqlog — logging COMPLETO de peticiones de jugadores hacia un reto.

OBJETIVO: que el comentarista del stream vea CUALQUIER cosa que un jugador
envíe a un reto. Cada petición se imprime a STDOUT como UNA línea con el
prefijo `CTFREQ ` seguido de JSON compacto. Promtail recoge esas líneas
(filtro `CTFREQ `) y el caster-overlay las narra anonimizadas por equipo.

Formato EXACTO de la línea (HTTP):
  CTFREQ {"ts":"<iso8601>","challenge_id":"<id>","src_ip":"<ip cliente>",
          "proto":"http","method":"POST","path":"/api/fetch",
          "query":"url=...","headers":{...},"body":"<texto, ≤8192 chars>"}

Formato EXACTO de la línea (TCP):
  CTFREQ {"ts":"<iso8601>","challenge_id":"<id>","src_ip":"<ip cliente>",
          "proto":"tcp","method":null,"path":null,"query":null,
          "headers":{},"body":"<texto o hex, ≤8192 chars>"}

REGLAS:
  - challenge_id sale del env CHALLENGE_ID (ya presente en cada contenedor).
  - src_ip es la IP REAL del cliente (10.10.N.x). El reto SÍ la ve; la
    anonimización (Equipo/Jugador) la hace el caster, no aquí.
  - body se trunca a MAX_BODY chars (8192) para no inundar Loki.
  - NUNCA se loguea la FLAG propia del reto (env FLAG): se redacta si aparece
    incrustada en algún valor logueado (headers/body). Si el jugador envía por
    su cuenta una flag, eso sí se ve (es lo que él envió) — solo protegemos el
    secreto del propio servicio.

Este módulo NO tiene dependencias externas: solo stdlib. Se copia tal cual a
cada reto (junto a siem.py) porque cada Dockerfile usa su propio build context.
"""
import json
import os
import sys
from datetime import datetime, timezone

# Límite de tamaño del cuerpo logueado (caracteres). Coincide con el contrato
# del SIEM: el body se trunca a 8 KB.
MAX_BODY = 8192

CHALLENGE_ID = os.environ.get("CHALLENGE_ID", "unknown")

# FLAG propia del reto: NO debe salir nunca al log. Si aparece incrustada en
# algún valor (header/body), se sustituye por un marcador. Es defensa en
# profundidad; el reto normalmente no echa su FLAG en la entrada del jugador.
_FLAG = os.environ.get("FLAG", "")
_FLAG_REDACTION = "[FLAG-REDACTADA]"


def _now_iso() -> str:
    """Timestamp ISO-8601 UTC con sufijo Z (segundos)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _redact_flag(text: str) -> str:
    """Quita la FLAG propia del reto de cualquier texto a loguear."""
    if not text or not _FLAG:
        return text
    if _FLAG in text:
        return text.replace(_FLAG, _FLAG_REDACTION)
    return text


def _coerce_text(value) -> str:
    """Convierte un valor (bytes/str/otro) a texto seguro para JSON.

    - bytes: intenta decodificar UTF-8; si no es texto, devuelve repr hex
      (`hex:...`) para que el comentarista vea los bytes crudos recibidos.
    - resto: str().
    """
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        try:
            return bytes(value).decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            return "hex:" + bytes(value).hex()
    return str(value)


def _truncate(text: str) -> str:
    """Trunca a MAX_BODY chars añadiendo un sufijo indicativo."""
    if text is None:
        return ""
    if len(text) > MAX_BODY:
        return text[:MAX_BODY] + f"...[+{len(text) - MAX_BODY} chars]"
    return text


def _emit(record: dict) -> None:
    """Imprime la línea `CTFREQ {json}` a STDOUT con flush inmediato.

    Nunca lanza: el logging jamás debe tumbar el reto.
    """
    try:
        line = "CTFREQ " + json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        print(line, flush=True)
    except Exception:
        try:
            sys.stdout.flush()
        except Exception:
            pass


def reqlog_http(src_ip, method, path, query="", headers=None, body="") -> None:
    """Loguea una petición HTTP COMPLETA recibida por el reto.

    src_ip  : IP real del cliente (Flask request.remote_addr / X-Forwarded-For;
              FastAPI request.client.host).
    method  : método HTTP ("GET", "POST", ...).
    path    : ruta SIN query string ("/api/fetch").
    query   : query string cruda ("url=http://..."), sin el '?' inicial.
    headers : dict de TODOS los headers (claves str, valores str).
    body    : cuerpo crudo (str o bytes). Se trunca a 8192 chars.
    """
    hdrs = {}
    if headers:
        for k, v in dict(headers).items():
            hdrs[str(k)] = _redact_flag(_coerce_text(v))

    record = {
        "ts": _now_iso(),
        "challenge_id": CHALLENGE_ID,
        "src_ip": _coerce_text(src_ip) or "?",
        "proto": "http",
        "method": _coerce_text(method) or "?",
        "path": _coerce_text(path) or "/",
        "query": _redact_flag(_coerce_text(query)),
        "headers": hdrs,
        "body": _truncate(_redact_flag(_coerce_text(body))),
    }
    _emit(record)


def reqlog_tcp(src_ip, data, label=None) -> None:
    """Loguea datos crudos recibidos por un reto TCP (crypto/pwn).

    src_ip : IP real del cliente (handler.client_address[0]).
    data   : bytes o str recibidos (una línea o bloque). Si no es texto UTF-8,
             se loguea como 'hex:...'. Se trunca a 8192 chars.
    label  : etiqueta opcional del tipo de dato (p.ej. "line", "raw"); se
             guarda como header informativo para dar contexto.
    """
    headers = {}
    if label:
        headers["kind"] = str(label)

    record = {
        "ts": _now_iso(),
        "challenge_id": CHALLENGE_ID,
        "src_ip": _coerce_text(src_ip) or "?",
        "proto": "tcp",
        "method": None,
        "path": None,
        "query": None,
        "headers": headers,
        "body": _truncate(_redact_flag(_coerce_text(data))),
    }
    _emit(record)
