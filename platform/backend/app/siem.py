"""Emision de eventos al SIEM collector.

Respeta el esquema EXACTO de ARCHITECTURE.md seccion 5. La emision es
fire-and-forget: si el collector esta caido, NO debe romper la request
del jugador (try/except silencioso con log).
"""
import logging
from datetime import datetime, timezone
from typing import Any, Literal

import httpx

from app.config import get_settings

settings = get_settings()
logger = logging.getLogger("siem")

# Tipos validos segun el contrato (seccion 5).
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
]
Severity = Literal["info", "warn", "alert", "critical"]


def build_event(
    *,
    event_type: EventType,
    severity: Severity,
    team_id: str | None = None,
    user: str | None = None,
    src_ip: str | None = None,
    challenge_id: str | None = None,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Construye el dict del evento con el esquema del contrato.

    `ts` en formato ISO-8601 UTC con sufijo Z, como en el ejemplo del doc.
    """
    return {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "platform",
        "team_id": team_id,
        "user": user,
        "src_ip": src_ip,
        "event_type": event_type,
        "severity": severity,
        "challenge_id": challenge_id,
        "detail": detail or {},
    }


async def emit_event(
    *,
    event_type: EventType,
    severity: Severity,
    team_id: str | None = None,
    user: str | None = None,
    src_ip: str | None = None,
    challenge_id: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """POST async fire-and-forget al collector. Nunca propaga excepciones."""
    event = build_event(
        event_type=event_type,
        severity=severity,
        team_id=team_id,
        user=user,
        src_ip=src_ip,
        challenge_id=challenge_id,
        detail=detail,
    )
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(f"{settings.collector_url}/event", json=event)
    except Exception as exc:  # noqa: BLE001 - no debe romper la request
        # El collector caido no afecta el juego; solo se registra localmente.
        logger.warning("No se pudo enviar evento SIEM (%s): %s", event_type, exc)
