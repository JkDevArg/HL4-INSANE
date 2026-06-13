"""Dependencias FastAPI: extraccion de IP, gate VPN, check de ban y
resolucion del equipo autenticado (current_team).
"""
import ipaddress

import redis.asyncio as aioredis
from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import decode_access_token, session_is_active
from app.config import get_settings
from app.db import get_db, get_redis
from app.models import Team

settings = get_settings()


# ----------------------------------------------------------------------------
# IP de origen
# ----------------------------------------------------------------------------
def get_client_ip(request: Request) -> str:
    """Obtiene la IP real del cliente.

    Detras de nginx confiamos en X-Forwarded-For (primer hop). Si no, usamos
    la IP del socket. Configurable por `trust_forwarded_for`.
    """
    if settings.trust_forwarded_for:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            # El primer valor es el cliente original.
            return xff.split(",")[0].strip()
        real = request.headers.get("x-real-ip")
        if real:
            return real.strip()
    return request.client.host if request.client else "0.0.0.0"


# ----------------------------------------------------------------------------
# Gate VPN-only (requisito 3)
# ----------------------------------------------------------------------------
def require_vpn(request: Request) -> str:
    """Rechaza requests cuyo src_ip no este en el rango VPN (10.10.0.0/16).

    Devuelve la IP de origen (reutilizable por otras dependencias).
    """
    src_ip = get_client_ip(request)
    try:
        ip = ipaddress.ip_address(src_ip)
        network = ipaddress.ip_network(settings.vpn_cidr, strict=False)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="IP de origen invalida. Acceso permitido solo por VPN.",
        )
    if ip not in network:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso permitido unicamente desde la VPN del evento.",
        )
    return src_ip


# ----------------------------------------------------------------------------
# Check de ban (requisito 4)
# ----------------------------------------------------------------------------
def ban_key(team_id: str) -> str:
    # El sistema VPN pone esta key (ARCHITECTURE 6.2): ban:team_NN
    return f"ban:{team_id}"


async def ensure_not_banned(team_id: str, redis: aioredis.Redis) -> None:
    """Lanza 403 si el equipo esta baneado (key ban:team_NN en Redis)."""
    if await redis.exists(ban_key(team_id)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Equipo baneado. Contacta a la organizacion del CTF.",
        )


# ----------------------------------------------------------------------------
# current_team (autenticacion por JWT + sesion activa + no baneado + VPN)
# ----------------------------------------------------------------------------
async def get_current_team(
    request: Request,
    src_ip: str = Depends(require_vpn),
    authorization: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
) -> Team:
    """Resuelve el equipo autenticado a partir del Bearer token.

    Aplica en cadena: gate VPN -> JWT valido -> sesion activa en Redis ->
    equipo existe -> equipo no baneado. Adjunta src_ip al request.state para
    que los routers emitan eventos SIEM con la IP correcta.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de autenticacion requerido.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization.split(" ", 1)[1].strip()
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalido o expirado.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    team_id = payload.get("team_id")
    session_id = payload.get("sid")
    if not team_id or not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token malformado.")

    # La sesion debe seguir viva en Redis (limite de 4 / no revocada).
    if not await session_is_active(redis, team_id, session_id):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesion expirada o cerrada. Inicia sesion nuevamente.",
        )

    # Ban check tambien sobre la API, no solo en login.
    await ensure_not_banned(team_id, redis)

    result = await db.execute(select(Team).where(Team.team_id == team_id))
    team = result.scalar_one_or_none()
    if team is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Equipo inexistente.")

    # Disponible para los routers (emision de eventos SIEM).
    request.state.src_ip = src_ip
    request.state.session_id = session_id
    return team
