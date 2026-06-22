"""Emision de eventos al SIEM collector desde un reto.

Respeta el esquema EXACTO de ARCHITECTURE.md seccion 5. Fire-and-forget:
si el collector esta caido, NUNCA rompe la request del jugador.

Copiable tal cual a cualquier reto Python (web/api/crypto).
"""
import logging
import os
import threading
from datetime import datetime, timezone

import urllib.request
import json

logger = logging.getLogger("siem")

COLLECTOR_URL = os.environ.get("COLLECTOR_URL", "http://collector:9000")
TEAM_ID = os.environ.get("TEAM_ID", "team_local")
CHALLENGE_ID = os.environ.get("CHALLENGE_ID", "unknown")


def _post(event: dict) -> None:
    try:
        data = json.dumps(event).encode()
        req = urllib.request.Request(
            f"{COLLECTOR_URL}/event",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=2.0)
    except Exception as exc:  # noqa: BLE001 - el collector caido no afecta el juego
        logger.warning("No se pudo enviar evento SIEM: %s", exc)


def emit(event_type: str, severity: str, src_ip: str | None = None, detail: dict | None = None) -> None:
    """Emite un evento async (thread) para no bloquear la respuesta del reto."""
    event = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "challenge",
        "team_id": TEAM_ID,
        "user": TEAM_ID,
        "src_ip": src_ip,
        "event_type": event_type,
        "severity": severity,
        "challenge_id": CHALLENGE_ID,
        "detail": detail or {},
    }
    threading.Thread(target=_post, args=(event,), daemon=True).start()
