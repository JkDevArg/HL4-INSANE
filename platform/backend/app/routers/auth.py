"""Router de autenticacion: login y /me.

Aplica gate VPN, check de ban y limite de 4 sesiones concurrentes.
"""
import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import (
    create_access_token,
    register_session,
    revoke_session,
    verify_password,
)
from app.db import get_db, get_redis
from app.deps import ensure_not_banned, get_current_team, require_vpn
from app.models import Team
from app.schemas import LoginRequest, MeResponse, TokenResponse
from app.siem import emit_event

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    src_ip: str = Depends(require_vpn),  # gate VPN antes de todo
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
):
    """Login por usuario/contrasena. Cada equipo es una cuenta.

    Pasos: gate VPN -> credenciales -> ban check -> limite de sesiones ->
    emite evento SIEM `login`.
    """
    result = await db.execute(select(Team).where(Team.team_id == body.username))
    team = result.scalar_one_or_none()

    # Mensaje generico para no revelar si el usuario existe.
    invalid = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales invalidas."
    )
    if team is None or not verify_password(body.password, team.password_hash):
        # Evento de intento fallido (severidad warn).
        await emit_event(
            event_type="login",
            severity="warn",
            team_id=body.username,
            user=body.username,
            src_ip=src_ip,
            detail={"result": "fail", "reason": "bad_credentials"},
        )
        raise invalid

    # Limite de 4 sesiones concurrentes (requisito 2).
    session_id = await register_session(redis, team.team_id)
    if session_id is None:
        await emit_event(
            event_type="login",
            severity="warn",
            team_id=team.team_id,
            user=team.team_id,
            src_ip=src_ip,
            detail={"result": "fail", "reason": "max_sessions"},
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Maximo de 4 sesiones activas alcanzado para este equipo.",
        )

    token = create_access_token(team.team_id, session_id)

    await emit_event(
        event_type="login",
        severity="info",
        team_id=team.team_id,
        user=team.team_id,
        src_ip=src_ip,
        detail={"result": "ok", "session_id": session_id},
    )

    return TokenResponse(
        access_token=token,
        team_id=team.team_id,
        display_name=team.display_name,
    )


@router.get("/me", response_model=MeResponse)
async def me(team: Team = Depends(get_current_team)):
    """Devuelve el equipo autenticado (valida VPN + JWT + sesion + ban)."""
    return MeResponse(team_id=team.team_id, display_name=team.display_name)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    team: Team = Depends(get_current_team),
    redis: aioredis.Redis = Depends(get_redis),
):
    """Cierra la sesion actual (libera un cupo de los 4)."""
    session_id = getattr(request.state, "session_id", None)
    if session_id:
        await revoke_session(redis, team.team_id, session_id)
