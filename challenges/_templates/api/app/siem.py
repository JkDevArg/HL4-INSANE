"""Emision de eventos al SIEM collector (esquema ARCHITECTURE.md §5).

Fire-and-forget: el collector caido nunca rompe la request del jugador.
Copiable a cualquier reto Python.
"""
import json
import logging
import os
import threading
import urllib.request
from datetime import datetime, timezone

logger = logging.getLogger("siem")

COLLECTOR_URL = os.environ.get("COLLECTOR_URL", "http://collector:9000")
TEAM_ID = os.environ.get("TEAM_ID", "team_local")
CHALLENGE_ID = os.environ.get("CHALLENGE_ID", "unknown")


def _post(event: dict) -> None:
    try:
        data = json.dumps(event).encode()
        req = urllib.request.Request(
            f"{COLLECTOR_URL}/event", data=data,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        urllib.request.urlopen(req, timeout=2.0)
    except Exception as exc:  # noqa: BLE001
        logger.warning("No se pudo enviar evento SIEM: %s", exc)


def emit(event_type: str, severity: str, src_ip: str | None = None, detail: dict | None = None) -> None:
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
