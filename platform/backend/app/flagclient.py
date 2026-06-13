"""Cliente del flag-service (ARCHITECTURE.md seccion 4).

La plataforma NUNCA guarda flags en claro: valida SIEMPRE contra el
flag-service. Tambien resuelve "de quien es esta flag" para el anti-cheat
de flag-share (requisito 7).

El contrato base del flag-service es:
  POST /validate {team_id, challenge_id, flag} -> {valid: bool}

El doc menciona ademas POST /whose-flag {flag} -> team_id dueno. Si ese
endpoint existe lo usamos directamente; si no (404 / no implementado),
DERIVAMOS el dueno: como la flag es unica por (team, challenge), probamos
la flag recibida contra /validate para cada team_id candidato fijando el
challenge_id del reto que se esta enviando. El team que valide es el dueno.
"""
import logging

import httpx

from app.config import get_settings

settings = get_settings()
logger = logging.getLogger("flagclient")


async def validate_flag(team_id: str, challenge_id: str, flag: str) -> bool:
    """Valida una flag contra el flag-service. Devuelve True si es correcta."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post(
                f"{settings.flag_service_url}/validate",
                json={"team_id": team_id, "challenge_id": challenge_id, "flag": flag},
            )
            resp.raise_for_status()
            return bool(resp.json().get("valid", False))
    except Exception as exc:  # noqa: BLE001
        logger.error("Error validando flag con flag-service: %s", exc)
        # Ante fallo del servicio, NO damos por valida la flag.
        return False


async def whose_flag(flag: str, challenge_id: str, team_count: int) -> str | None:
    """Determina a que equipo pertenece una flag, para el anti-cheat.

    1) Intenta el endpoint dedicado POST /whose-flag {flag}.
    2) Si no existe, deriva el dueno probando la flag con /validate contra
       cada team_id candidato (team_01..team_NN) fijando el challenge_id.

    Devuelve el team_id dueno o None si ningun equipo coincide
    (flag invalida / inventada).
    """
    # --- Camino 1: endpoint dedicado ---
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post(
                f"{settings.flag_service_url}/whose-flag", json={"flag": flag}
            )
            if resp.status_code == 200:
                owner = resp.json().get("team_id")
                return owner or None
            # 404 / 405 => endpoint no implementado, caemos al fallback.
    except Exception as exc:  # noqa: BLE001
        logger.warning("whose-flag no disponible, derivando por validate: %s", exc)

    # --- Camino 2: derivacion por fuerza dirigida sobre el mismo challenge ---
    # La flag depende de (team_id, challenge_id); fijando challenge_id solo
    # puede validar contra exactamente un team_id (su dueno).
    for n in range(1, team_count + 1):
        candidate = f"team_{n:02d}"
        if await validate_flag(candidate, challenge_id, flag):
            return candidate
    return None
