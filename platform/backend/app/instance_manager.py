"""Gestor de instancias Docker on-demand.

Cada equipo puede iniciar/detener su propia instancia de un reto.
Las instancias corren en la red aislada del equipo (ctf_team_NN / 172.30.N.0/24).
Se usa docker compose via subprocess para mantener compatibilidad con el stack existente.
"""
import asyncio
import json
import logging
import os
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

CHALLENGES_DIR = Path(os.getenv("CHALLENGES_DIR", "/challenges"))
FLAG_SERVICE_URL = os.getenv("FLAG_SERVICE_URL", "http://flag-service:8001")


def _team_n(team_id: str) -> int:
    return int(team_id.split("_")[-1])


def _project(team_id: str, challenge_id: str) -> str:
    return f"ctf_{team_id}_{challenge_id.replace('-', '_')}"


def _team_network(team_id: str) -> str:
    return f"ctf_{team_id}"


def _team_subnet(team_id: str) -> str:
    return f"172.30.{_team_n(team_id)}.0/24"


def _find_compose(challenge_id: str) -> Path | None:
    for cat_dir in CHALLENGES_DIR.iterdir():
        if not cat_dir.is_dir():
            continue
        p = cat_dir / challenge_id / "docker-compose.yml"
        if p.exists():
            return p
    return None


async def _fetch_flag(team_id: str, challenge_id: str) -> str:
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.get(
            f"{FLAG_SERVICE_URL}/flag",
            params={"team_id": team_id, "challenge_id": challenge_id},
        )
        r.raise_for_status()
        return r.json()["flag"]


def _ensure_network(team_id: str) -> None:
    net = _team_network(team_id)
    # os.popen().read() devuelve "[]" (stdout) cuando la red no existe — exit code
    # es 1 pero stdout no está vacío y no contiene "Error". Usamos os.system() que
    # devuelve el exit code real para detectar correctamente si la red falta.
    rc = os.system(f"docker network inspect {net} >/dev/null 2>&1")
    if rc != 0:
        subnet = _team_subnet(team_id)
        os.system(f"docker network create --subnet {subnet} {net} >/dev/null 2>&1 || true")
        logger.info("Red %s creada (%s)", net, subnet)


async def start_instance(team_id: str, challenge_id: str) -> None:
    compose_path = _find_compose(challenge_id)
    if compose_path is None:
        raise FileNotFoundError(f"docker-compose.yml no encontrado para {challenge_id}")

    flag = await _fetch_flag(team_id, challenge_id)
    n = _team_n(team_id)
    project = _project(team_id, challenge_id)
    net = _team_network(team_id)

    _ensure_network(team_id)

    env = {
        **os.environ,
        "TEAM_ID": team_id,
        "TEAM_N": str(n),
        "FLAG": flag,
        "CHAL_NET": net,
    }

    proc = await asyncio.create_subprocess_exec(
        "docker", "compose",
        "-p", project,
        "-f", str(compose_path),
        "up", "-d", "--build",
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode != 0:
        err = stderr.decode(errors="replace")[:600]
        logger.error("Error al iniciar %s para %s: %s", challenge_id, team_id, err)
        raise RuntimeError(f"docker compose up falló: {err}")

    logger.info("Instancia %s/%s iniciada", team_id, challenge_id)


async def stop_instance(team_id: str, challenge_id: str) -> None:
    compose_path = _find_compose(challenge_id)
    if compose_path is None:
        return

    project = _project(team_id, challenge_id)
    net = _team_network(team_id)

    env = {
        **os.environ,
        "TEAM_ID": team_id,
        "TEAM_N": str(_team_n(team_id)),
        "FLAG": "x",
        "CHAL_NET": net,
    }

    proc = await asyncio.create_subprocess_exec(
        "docker", "compose",
        "-p", project,
        "-f", str(compose_path),
        "down", "--remove-orphans",
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await proc.communicate()
    logger.info("Instancia %s/%s detenida", team_id, challenge_id)


async def get_status(team_id: str, challenge_id: str) -> str:
    """Consulta Docker y devuelve 'running' o 'stopped'."""
    project = _project(team_id, challenge_id)

    proc = await asyncio.create_subprocess_exec(
        "docker", "compose",
        "-p", project,
        "ps", "--format", "json",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()

    if proc.returncode != 0 or not stdout.strip():
        return "stopped"

    raw = stdout.decode(errors="replace").strip()
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return "running" if any(c.get("State") == "running" for c in data) else "stopped"
        if isinstance(data, dict):
            return "running" if data.get("State") == "running" else "stopped"
    except json.JSONDecodeError:
        # docker compose ps puede devolver una linea por contenedor (JSONL)
        for line in raw.splitlines():
            try:
                obj = json.loads(line)
                if obj.get("State") == "running":
                    return "running"
            except json.JSONDecodeError:
                pass

    return "stopped"
