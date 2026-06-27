# siem-collector — Microservicio FastAPI del SIEM del CTF
#
# Responsabilidades (ver docs/ARCHITECTURE.md secciones 3 y 5):
#   - POST /event : recibe eventos JSON con el esquema EXACTO de la sección 5.
#   - Reenvía cada evento a Loki (push API) con labels: source, team_id,
#     event_type, severity.
#   - Dispara alertas cuando la severidad o el tipo de evento lo ameritan
#     (log estructurado + hook opcional fire-and-forget a Discord).
#   - GET /health para readiness/liveness.
#
# Escucha en el puerto 9000 (contrato sección 3: siem-collector 9000).

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Literal, Optional

import httpx
from fastapi import FastAPI, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Configuración (todo por variables de entorno, con defaults de Docker)
# ---------------------------------------------------------------------------

# URL de la API de push de Loki. En docker-compose el hostname es "loki".
LOKI_PUSH_URL = os.getenv("LOKI_PUSH_URL", "http://loki:3100/loki/api/v1/push")

# Webhook opcional de Discord para alertas. Si está vacío, no se notifica.
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "").strip()

# Timeouts en segundos para llamadas salientes.
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "5"))

# ---------------------------------------------------------------------------
# Logging estructurado a stdout (lo recoge Docker/Promtail si se desea).
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("siem-collector")

# ---------------------------------------------------------------------------
# Esquema de evento (contrato sección 5 — RESPETAR EXACTAMENTE)
# ---------------------------------------------------------------------------

# Conjuntos cerrados de valores válidos según el contrato.
SourceType = Literal["platform", "vpn", "suricata", "challenge"]
EventType = Literal[
    "login",
    "submit",
    "flag_ok",
    "flag_fail",
    "cheat_flag_share",
    "vpn_connect",
    "vpn_disconnect",
    "vpn_ban",
    "ids_alert",
    "scan_detected",
    "instance_start",
    "instance_stop",
]
Severity = Literal["info", "warn", "alert", "critical"]

# Condiciones que disparan una ALERTA.
ALERT_SEVERITIES = {"alert", "critical"}
ALERT_EVENT_TYPES = {"cheat_flag_share", "scan_detected", "ids_alert", "vpn_ban"}


class SiemEvent(BaseModel):
    """Evento normalizado del SIEM. Esquema EXACTO de la sección 5."""

    ts: str = Field(..., description="Timestamp ISO-8601 UTC, ej: 2026-06-13T18:00:00Z")
    source: SourceType
    team_id: str = Field(..., examples=["team_03"])
    user: str
    src_ip: str
    event_type: EventType
    severity: Severity
    challenge_id: Optional[str] = Field(
        default=None, description="ID del reto si aplica, ej: web-supply-01"
    )
    detail: Dict[str, Any] = Field(default_factory=dict, description="Forma libre")

    @field_validator("ts")
    @classmethod
    def _validar_ts(cls, v: str) -> str:
        # Aceptamos ISO-8601; normalizamos 'Z' a offset para validar parseable.
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"ts no es ISO-8601 válido: {v}") from exc
        return v


# ---------------------------------------------------------------------------
# Cliente HTTP compartido (se crea en el lifespan de la app)
# ---------------------------------------------------------------------------

app = FastAPI(
    title="CTF SIEM Collector",
    version="1.0.0",
    description="Ingesta de eventos SIEM → Loki + alertas (CTFHL4-INSANE)",
)

_http_client: Optional[httpx.AsyncClient] = None


@app.on_event("startup")
async def _startup() -> None:
    global _http_client
    _http_client = httpx.AsyncClient(timeout=HTTP_TIMEOUT)
    log.info("collector iniciado | loki=%s | discord=%s",
             LOKI_PUSH_URL, "on" if DISCORD_WEBHOOK_URL else "off")


@app.on_event("shutdown")
async def _shutdown() -> None:
    global _http_client
    if _http_client is not None:
        await _http_client.aclose()
        _http_client = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts_to_loki_ns(ts: str) -> str:
    """Convierte un timestamp ISO-8601 a nanosegundos epoch (string), formato
    requerido por la Loki push API. Si falla, usa 'ahora'."""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return str(int(dt.timestamp() * 1_000_000_000))
    except ValueError:
        return str(time.time_ns())


def _is_alert(event: SiemEvent) -> bool:
    """Determina si el evento debe escalar a ALERTA."""
    return event.severity in ALERT_SEVERITIES or event.event_type in ALERT_EVENT_TYPES


async def _push_to_loki(event: SiemEvent) -> None:
    """Reenvía el evento a Loki con labels: source, team_id, event_type,
    severity. El cuerpo completo del evento va como línea de log (JSON)."""
    assert _http_client is not None

    # Loki exige un set ACOTADO de labels (alta cardinalidad = problema).
    # Por contrato: source, team_id, event_type, severity.
    stream_labels = {
        "source": event.source,
        "team_id": event.team_id,
        "event_type": event.event_type,
        "severity": event.severity,
        "job": "siem-collector",
    }

    # El resto (user, src_ip, challenge_id, detail) viaja en la línea JSON,
    # consultable luego con LogQL | json en Grafana.
    line = event.model_dump_json()

    payload = {
        "streams": [
            {
                "stream": stream_labels,
                "values": [[_ts_to_loki_ns(event.ts), line]],
            }
        ]
    }

    try:
        resp = await _http_client.post(LOKI_PUSH_URL, json=payload)
        if resp.status_code >= 300:
            log.error("push a Loki falló %s: %s", resp.status_code, resp.text[:200])
    except httpx.HTTPError as exc:
        # No tumbamos la ingesta por un fallo de Loki; lo registramos.
        log.error("error enviando a Loki: %s", exc)


async def _fire_discord(event: SiemEvent) -> None:
    """Hook opcional fire-and-forget a Discord. No bloquea ni propaga errores."""
    if not DISCORD_WEBHOOK_URL or _http_client is None:
        return

    content = (
        f"**ALERTA SIEM** `{event.severity.upper()}`\n"
        f"- tipo: `{event.event_type}`\n"
        f"- equipo: `{event.team_id}` | usuario: `{event.user}`\n"
        f"- src_ip: `{event.src_ip}`\n"
        f"- reto: `{event.challenge_id or '-'}`\n"
        f"- ts: `{event.ts}`\n"
        f"- detalle: ```{json.dumps(event.detail, ensure_ascii=False)[:500]}```"
    )
    try:
        await _http_client.post(DISCORD_WEBHOOK_URL, json={"content": content})
    except httpx.HTTPError as exc:
        log.warning("no se pudo notificar a Discord: %s", exc)


def _raise_alert(event: SiemEvent) -> None:
    """Loguea la alerta de forma estructurada y dispara el hook de Discord
    en segundo plano (fire-and-forget)."""
    log.warning(
        "ALERTA | type=%s severity=%s team=%s user=%s src_ip=%s challenge=%s detail=%s",
        event.event_type,
        event.severity,
        event.team_id,
        event.user,
        event.src_ip,
        event.challenge_id,
        json.dumps(event.detail, ensure_ascii=False),
    )
    # No esperamos a Discord: lanzamos la tarea y seguimos.
    asyncio.create_task(_fire_discord(event))


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> Dict[str, str]:
    """Healthcheck simple para Docker / orquestación."""
    return {"status": "ok", "service": "siem-collector"}


@app.post("/event", status_code=status.HTTP_202_ACCEPTED)
async def ingest_event(event: SiemEvent) -> JSONResponse:
    """Ingesta de un evento SIEM.

    Flujo:
      1. Pydantic valida el esquema (sección 5). Si falla → 422 automático.
      2. Si es alerta → log estructurado + hook Discord (fire-and-forget).
      3. Reenvío a Loki con los labels del contrato.
    """
    alerted = _is_alert(event)
    if alerted:
        _raise_alert(event)

    await _push_to_loki(event)

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={"accepted": True, "alert": alerted},
    )


# Permite ejecutarlo directo: `python -m app.main` (útil fuera de Docker).
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=9000, reload=False)
