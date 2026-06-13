# -*- coding: utf-8 -*-
"""
Panel de administración del CTFHL4-INSANE.

AISLADO del caster público y de los jugadores: el docker-compose publica este
servicio SOLO en 127.0.0.1:8091, así que únicamente se alcanza por túnel SSH.

Funciones:
  - Login obligatorio (password en env ADMIN_PASSWORD, comparado con hmac.compare_digest).
  - Métricas EN VIVO leídas del socket de Docker (/var/run/docker.sock) vía httpx.
  - Control ON/OFF por equipo (docker stop/start), restringido por lista blanca
    a contenedores cuyo nombre empieza por "ctf_team_". Nunca toca otros contenedores.

Convenciones (ARCHITECTURE.md / launch-team-challenges.sh):
  - Contenedores de reto por equipo: ctf_team_NN_<reto>-...-1
  - Red SIEM net_siem 10.10.200.0/24 (solo admin).
"""

import asyncio
import hashlib
import hmac
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any

import httpx
from fastapi import Cookie, FastAPI, HTTPException, Path as PathParam, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

# ── Configuración ───────────────────────────────────────────────────────────

# Password de admin. Si no se define, se genera uno aleatorio (no usable) para
# que el panel NUNCA quede abierto con un default conocido.
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD") or secrets.token_urlsafe(32)

# Secreto para firmar el token de sesión (cookie). Aleatorio por proceso:
# reiniciar el panel invalida sesiones, que es el comportamiento deseado.
_SESSION_SECRET = os.environ.get("ADMIN_SESSION_SECRET") or secrets.token_bytes(32)
if isinstance(_SESSION_SECRET, str):
    _SESSION_SECRET = _SESSION_SECRET.encode()

# Duración de la sesión (segundos).
SESSION_TTL = int(os.environ.get("ADMIN_SESSION_TTL", "28800"))  # 8 h

# Socket de Docker (montado por el compose). httpx habla HTTP sobre este socket.
DOCKER_SOCK = os.environ.get("DOCKER_SOCK", "/var/run/docker.sock")

# LISTA BLANCA: el panel SOLO controla contenedores de reto de equipo.
# Cualquier acción de start/stop se rechaza si el nombre no casa este patrón.
TEAM_CONTAINER_RE = re.compile(r"^/?ctf_team_(\d{2})_")
# Patrón para extraer el número de equipo de un nombre de contenedor.
TEAM_NUM_RE = re.compile(r"ctf_team_(\d{2})_")

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

app = FastAPI(title="CTFHL4 Admin Panel", docs_url=None, redoc_url=None, openapi_url=None)

# ── Cliente Docker (httpx sobre socket Unix) ─────────────────────────────────
# transport=AsyncHTTPTransport(uds=...) habla el protocolo HTTP de Docker.
# El host de la URL es ficticio ("docker"); el transporte usa el socket.
_docker_client: httpx.AsyncClient | None = None


def docker() -> httpx.AsyncClient:
    global _docker_client
    if _docker_client is None:
        transport = httpx.AsyncHTTPTransport(uds=DOCKER_SOCK)
        _docker_client = httpx.AsyncClient(
            transport=transport, base_url="http://docker", timeout=15.0
        )
    return _docker_client


@app.on_event("shutdown")
async def _close_docker():
    if _docker_client is not None:
        await _docker_client.aclose()


# ── Sesión: token firmado (HMAC) en cookie httpOnly ──────────────────────────

def _make_token() -> str:
    """Token = expiración|firma_hmac. Firma sobre la expiración con el secreto."""
    exp = str(int(time.time()) + SESSION_TTL)
    sig = hmac.new(_SESSION_SECRET, exp.encode(), hashlib.sha256).hexdigest()
    return f"{exp}.{sig}"


def _valid_token(token: str | None) -> bool:
    if not token or "." not in token:
        return False
    exp_str, sig = token.rsplit(".", 1)
    expected = hmac.new(_SESSION_SECRET, exp_str.encode(), hashlib.sha256).hexdigest()
    # Comparación en tiempo constante para no filtrar la firma.
    if not hmac.compare_digest(sig, expected):
        return False
    try:
        return int(exp_str) > int(time.time())
    except ValueError:
        return False


def _require_auth(session: str | None) -> None:
    if not _valid_token(session):
        raise HTTPException(status_code=401, detail="No autenticado")


# ── Endpoints de autenticación ───────────────────────────────────────────────

@app.get("/healthz")
async def healthz():
    """Único endpoint sin login (para el healthcheck del compose)."""
    return {"status": "ok"}


@app.post("/api/login")
async def login(response: Response, payload: dict[str, Any]):
    """Valida la password de admin con comparación en tiempo constante."""
    supplied = str(payload.get("password", ""))
    if not hmac.compare_digest(supplied, ADMIN_PASSWORD):
        # Pequeño retardo para frenar fuerza bruta.
        await asyncio.sleep(0.5)
        raise HTTPException(status_code=401, detail="Contraseña incorrecta")
    token = _make_token()
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        samesite="strict",
        max_age=SESSION_TTL,
        path="/",
    )
    return {"ok": True}


@app.post("/api/logout")
async def logout(response: Response):
    response.delete_cookie("session", path="/")
    return {"ok": True}


@app.get("/api/whoami")
async def whoami(session: str | None = Cookie(default=None)):
    return {"authenticated": _valid_token(session)}


# ── Helpers Docker ────────────────────────────────────────────────────────────

async def _list_ctf_containers() -> list[dict]:
    """Lista todos los contenedores (incluye parados) con prefijo ctf_team_."""
    r = await docker().get("/containers/json", params={"all": "true"})
    r.raise_for_status()
    out = []
    for c in r.json():
        names = c.get("Names", [])
        if any(TEAM_CONTAINER_RE.match(n) for n in names):
            out.append(c)
    return out


async def _list_all_containers() -> list[dict]:
    r = await docker().get("/containers/json", params={"all": "true"})
    r.raise_for_status()
    return r.json()


def _container_name(c: dict) -> str:
    names = c.get("Names") or []
    return (names[0] if names else c.get("Id", "")[:12]).lstrip("/")


def _team_of(name: str) -> int | None:
    m = TEAM_NUM_RE.search(name)
    return int(m.group(1)) if m else None


async def _stats_once(cid: str) -> dict | None:
    """Una lectura puntual de stats (stream=false)."""
    try:
        r = await docker().get(f"/containers/{cid}/stats", params={"stream": "false"})
        r.raise_for_status()
        return r.json()
    except (httpx.HTTPError, ValueError):
        return None


def _calc_cpu_pct(stats: dict) -> float:
    """CPU% al estilo `docker stats`: delta de uso vs delta de sistema * nCPUs."""
    try:
        cpu = stats["cpu_stats"]
        pre = stats["precpu_stats"]
        cpu_delta = cpu["cpu_usage"]["total_usage"] - pre["cpu_usage"]["total_usage"]
        sys_delta = cpu.get("system_cpu_usage", 0) - pre.get("system_cpu_usage", 0)
        # online_cpus puede faltar; cae al tamaño de percpu_usage o 1.
        ncpu = cpu.get("online_cpus") or len(
            cpu["cpu_usage"].get("percpu_usage") or [1]
        )
        if sys_delta > 0 and cpu_delta > 0:
            return round((cpu_delta / sys_delta) * ncpu * 100.0, 2)
    except (KeyError, TypeError, ZeroDivisionError):
        pass
    return 0.0


def _calc_mem(stats: dict) -> tuple[int, int]:
    """(uso_bytes, limite_bytes). Descuenta cache como hace docker stats."""
    try:
        ms = stats["memory_stats"]
        usage = ms.get("usage", 0)
        cache = (ms.get("stats") or {}).get("cache", 0) or (ms.get("stats") or {}).get(
            "inactive_file", 0
        )
        return max(usage - cache, 0), ms.get("limit", 0)
    except (KeyError, TypeError):
        return 0, 0


def _calc_net(stats: dict) -> tuple[int, int]:
    """(rx_bytes, tx_bytes) sumando todas las interfaces."""
    rx = tx = 0
    for iface in (stats.get("networks") or {}).values():
        rx += iface.get("rx_bytes", 0)
        tx += iface.get("tx_bytes", 0)
    return rx, tx


async def _container_metrics(c: dict) -> dict:
    """Métricas de un contenedor. Si está parado, no consulta stats."""
    name = _container_name(c)
    cid = c["Id"]
    state = c.get("State", "unknown")
    base = {
        "id": cid[:12],
        "name": name,
        "team": _team_of(name),
        "state": state,
        "cpu_pct": 0.0,
        "mem_used": 0,
        "mem_limit": 0,
        "mem_pct": 0.0,
        "net_rx": 0,
        "net_tx": 0,
    }
    if state != "running":
        return base
    stats = await _stats_once(cid)
    if not stats:
        return base
    mem_used, mem_limit = _calc_mem(stats)
    rx, tx = _calc_net(stats)
    base.update(
        cpu_pct=_calc_cpu_pct(stats),
        mem_used=mem_used,
        mem_limit=mem_limit,
        mem_pct=round((mem_used / mem_limit * 100.0), 2) if mem_limit else 0.0,
        net_rx=rx,
        net_tx=tx,
    )
    return base


# ── Endpoint de métricas EN VIVO ──────────────────────────────────────────────

@app.get("/api/stats")
async def api_stats(session: str | None = Cookie(default=None)):
    _require_auth(session)

    containers = await _list_all_containers()

    # Métricas de cada contenedor en paralelo (una lectura de stats trae
    # cpu_stats + precpu_stats, así que un solo GET basta para el CPU%).
    metrics = await asyncio.gather(*[_container_metrics(c) for c in containers])

    teams: dict[int, dict] = {}
    stack: list[dict] = []          # plataforma + SIEM (no es de equipo)
    top: list[dict] = []

    host_cpu = 0.0
    host_mem_used = 0

    for m in metrics:
        top.append(m)
        host_cpu += m["cpu_pct"]
        host_mem_used += m["mem_used"]
        t = m["team"]
        if t is None:
            stack.append(m)
            continue
        agg = teams.setdefault(
            t,
            {
                "team": t,
                "containers": 0,
                "running": 0,
                "cpu_pct": 0.0,
                "mem_used": 0,
                "net_rx": 0,
                "net_tx": 0,
            },
        )
        agg["containers"] += 1
        if m["state"] == "running":
            agg["running"] += 1
        agg["cpu_pct"] = round(agg["cpu_pct"] + m["cpu_pct"], 2)
        agg["mem_used"] += m["mem_used"]
        agg["net_rx"] += m["net_rx"]
        agg["net_tx"] += m["net_tx"]

    # Total de RAM del host (desde /info de Docker).
    host_mem_total = 0
    host_ncpu = 0
    try:
        info = (await docker().get("/info")).json()
        host_mem_total = info.get("MemTotal", 0)
        host_ncpu = info.get("NCPU", 0)
    except (httpx.HTTPError, ValueError):
        pass

    # Top contenedores por CPU (luego por memoria), solo los que consumen algo.
    top_sorted = sorted(
        [t for t in top if t["state"] == "running"],
        key=lambda x: (x["cpu_pct"], x["mem_used"]),
        reverse=True,
    )[:10]

    return JSONResponse(
        {
            "host": {
                # CPU% del host normalizado a 100% = todos los núcleos.
                "cpu_pct": round(host_cpu / host_ncpu, 2) if host_ncpu else round(host_cpu, 2),
                "cpu_pct_raw": round(host_cpu, 2),
                "ncpu": host_ncpu,
                "mem_used": host_mem_used,
                "mem_total": host_mem_total,
                "mem_pct": round(host_mem_used / host_mem_total * 100.0, 2)
                if host_mem_total
                else 0.0,
            },
            "teams": sorted(teams.values(), key=lambda x: x["team"]),
            "stack": sorted(stack, key=lambda x: x["name"]),
            "top": top_sorted,
            "ts": int(time.time()),
        }
    )


# ── Control ON/OFF por equipo ─────────────────────────────────────────────────

async def _team_container_ids(n: int) -> list[tuple[str, str]]:
    """(id, nombre) de los contenedores ctf_team_NN_* del equipo n."""
    prefix = f"ctf_team_{n:02d}_"
    out = []
    for c in await _list_ctf_containers():
        name = _container_name(c)
        # Defensa en profundidad: revalida la lista blanca antes de cualquier acción.
        if name.startswith(prefix) and TEAM_CONTAINER_RE.match("/" + name):
            out.append((c["Id"], name))
    return out


async def _apply_action(n: int, action: str) -> dict:
    """action ∈ {stop, start, restart}. Solo afecta contenedores ctf_team_NN_*."""
    ids = await _team_container_ids(n)
    if not ids:
        raise HTTPException(status_code=404, detail=f"Equipo {n:02d} sin contenedores")
    results = []
    for cid, name in ids:
        # SEGURIDAD: el nombre ya pasó la lista blanca en _team_container_ids.
        try:
            r = await docker().post(f"/containers/{cid}/{action}", timeout=60.0)
            # 204 = ok, 304 = ya estaba en ese estado (no es error).
            ok = r.status_code in (204, 304)
            results.append({"name": name, "ok": ok, "code": r.status_code})
        except httpx.HTTPError as e:
            results.append({"name": name, "ok": False, "error": str(e)})
    return {"team": n, "action": action, "count": len(results), "results": results}


@app.post("/api/team/{n}/stop")
async def team_stop(
    session: str | None = Cookie(default=None),
    n: int = PathParam(..., ge=1, le=99),
):
    _require_auth(session)
    return await _apply_action(n, "stop")


@app.post("/api/team/{n}/start")
async def team_start(
    session: str | None = Cookie(default=None),
    n: int = PathParam(..., ge=1, le=99),
):
    _require_auth(session)
    return await _apply_action(n, "start")


@app.post("/api/team/{n}/restart")
async def team_restart(
    session: str | None = Cookie(default=None),
    n: int = PathParam(..., ge=1, le=99),
):
    _require_auth(session)
    return await _apply_action(n, "restart")


# ── UI estática ───────────────────────────────────────────────────────────────

@app.get("/")
async def index(session: str | None = Cookie(default=None)):
    # Siempre sirve la SPA; el JS decide login vs dashboard según /api/whoami.
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
