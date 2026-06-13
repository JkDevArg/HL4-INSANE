"""Router de retos: listado, submit de flags, anti-cheat de flag-share.

El submit es el corazon del juego. Flujo (requisitos 6 y 7):
  1. Rate-limit por equipo (Redis) para frenar fuerza bruta.
  2. Emite evento SIEM `submit`.
  3. Anti-cheat: averigua de quien es la flag (whose-flag/derivacion).
       - Si pertenece a OTRO equipo -> NO da puntos, evento `cheat_flag_share`
         severity critical con ambos team_id + red flag en Redis.
  4. Valida la flag contra flag-service para el equipo que la envia.
       - OK  -> registra solve idempotente, evento `flag_ok`.
       - Fail -> evento `flag_fail`.
"""
import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db import get_db, get_redis
from app.deps import get_current_team
from app.flagclient import validate_flag, whose_flag
from app.models import Challenge, Solve, Team
from app.schemas import ChallengeOut, SubmitRequest, SubmitResponse
from app.siem import emit_event

settings = get_settings()
router = APIRouter(prefix="/challenges", tags=["challenges"])


# ----------------------------------------------------------------------------
# Rate-limit de submits (Redis, ventana deslizante simple por contador)
# ----------------------------------------------------------------------------
async def _check_submit_rate(redis: aioredis.Redis, team_id: str) -> bool:
    """True si el equipo aun tiene cupo de submits en la ventana actual."""
    key = f"submit_rl:{team_id}"
    count = await redis.incr(key)
    if count == 1:
        # Primer submit de la ventana: fija expiracion.
        await redis.expire(key, settings.submit_rate_window)
    return count <= settings.submit_rate_limit


async def _solved_ids(db: AsyncSession, team_pk: int) -> set[str]:
    """Conjunto de challenge_id ya resueltos por el equipo."""
    result = await db.execute(select(Solve.challenge_id).where(Solve.team_pk == team_pk))
    return {row[0] for row in result.all()}


def _team_n(team_id: str) -> str:
    """'team_03' -> '3'. Numero de equipo para renderizar el connection_info."""
    suffix = team_id.split("_")[-1]
    try:
        return str(int(suffix))  # quita el cero a la izquierda (03 -> 3)
    except ValueError:
        return suffix


def _render_conn(connection_info: str, team_id: str) -> str:
    """Sustituye la plantilla {N} por el numero del equipo en la pista de conexion.

    Cada equipo ve la IP interna de SU instancia (172.30.N.x), alcanzable solo
    desde su propia VPN (aislamiento por nftables).
    """
    return connection_info.replace("{N}", _team_n(team_id))


@router.get("", response_model=list[ChallengeOut])
async def list_challenges(
    team: Team = Depends(get_current_team),
    db: AsyncSession = Depends(get_db),
):
    """Lista los retos visibles al equipo. NO expone la flag.

    Marca `solved=True` en los que el equipo ya resolvio.
    """
    result = await db.execute(
        select(Challenge).where(Challenge.visible.is_(True)).order_by(Challenge.sort_order)
    )
    challenges = result.scalars().all()
    solved = await _solved_ids(db, team.id)

    return [
        ChallengeOut(
            id=c.challenge_id,
            category=c.category,
            name=c.name,
            difficulty=c.difficulty,
            points=c.points,
            description=c.description,
            connection_info=_render_conn(c.connection_info, team.team_id),
            solved=c.challenge_id in solved,
        )
        for c in challenges
    ]


@router.post("/{challenge_id}/submit", response_model=SubmitResponse)
async def submit_flag(
    challenge_id: str,
    body: SubmitRequest,
    request: Request,
    team: Team = Depends(get_current_team),
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
):
    """Recibe una flag, aplica anti-cheat y la valida contra flag-service."""
    src_ip = getattr(request.state, "src_ip", None)
    flag = body.flag.strip()

    # --- Reto existe y es visible ---
    result = await db.execute(
        select(Challenge).where(
            Challenge.challenge_id == challenge_id, Challenge.visible.is_(True)
        )
    )
    challenge = result.scalar_one_or_none()
    if challenge is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Reto no encontrado.")

    # --- Rate-limit (anti fuerza bruta) ---
    if not await _check_submit_rate(redis, team.team_id):
        await emit_event(
            event_type="submit",
            severity="warn",
            team_id=team.team_id,
            user=team.team_id,
            src_ip=src_ip,
            challenge_id=challenge_id,
            detail={"result": "rate_limited"},
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiados intentos. Espera un momento antes de reintentar.",
        )

    # --- Evento de intento de submit ---
    await emit_event(
        event_type="submit",
        severity="info",
        team_id=team.team_id,
        user=team.team_id,
        src_ip=src_ip,
        challenge_id=challenge_id,
        detail={"flag_len": len(flag)},
    )

    # --- Idempotencia: si ya esta resuelto, no reprocesa ---
    already = await db.execute(
        select(Solve).where(Solve.team_pk == team.id, Solve.challenge_id == challenge_id)
    )
    if already.scalar_one_or_none() is not None:
        return SubmitResponse(
            correct=True,
            already_solved=True,
            points_awarded=0,
            message="Reto ya resuelto anteriormente.",
        )

    # --- Anti-cheat flag-share (requisito 7) ---
    # Averigua a que equipo pertenece la flag enviada para ESTE reto.
    owner = await whose_flag(flag, challenge_id, settings.team_count)
    if owner is not None and owner != team.team_id:
        # Flag de otro equipo: trampa. No da puntos.
        await _flag_red(redis, team.team_id, owner)
        await emit_event(
            event_type="cheat_flag_share",
            severity="critical",
            team_id=team.team_id,
            user=team.team_id,
            src_ip=src_ip,
            challenge_id=challenge_id,
            detail={
                "submitter_team": team.team_id,
                "owner_team": owner,
                "reason": "flag_share",
            },
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Flag perteneciente a otro equipo. Incidente registrado.",
        )

    # --- Validacion normal contra flag-service ---
    is_valid = await validate_flag(team.team_id, challenge_id, flag)
    if not is_valid:
        await emit_event(
            event_type="flag_fail",
            severity="warn",
            team_id=team.team_id,
            user=team.team_id,
            src_ip=src_ip,
            challenge_id=challenge_id,
            detail={"result": "invalid_flag"},
        )
        return SubmitResponse(correct=False, message="Flag incorrecta.")

    # --- Flag correcta: registra solve (idempotente por unique constraint) ---
    solve = Solve(
        team_pk=team.id,
        team_id=team.team_id,
        challenge_id=challenge_id,
        points=challenge.points,
    )
    db.add(solve)
    try:
        await db.commit()
    except IntegrityError:
        # Carrera: otro request inserto el mismo solve. No duplica puntos.
        await db.rollback()
        return SubmitResponse(
            correct=True,
            already_solved=True,
            points_awarded=0,
            message="Reto ya resuelto anteriormente.",
        )

    await emit_event(
        event_type="flag_ok",
        severity="info",
        team_id=team.team_id,
        user=team.team_id,
        src_ip=src_ip,
        challenge_id=challenge_id,
        detail={"points": challenge.points},
    )

    return SubmitResponse(
        correct=True,
        points_awarded=challenge.points,
        message=f"Correcto! +{challenge.points} puntos.",
    )


async def _flag_red(redis: aioredis.Redis, submitter: str, owner: str) -> None:
    """Marca la red flag del anti-cheat en Redis (consumible por el sistema VPN/SIEM).

    Sigue la convencion del proyecto (teams_red_flag) usada por el anti-cheat v2.
    """
    await redis.sadd("teams_red_flag", submitter)
    await redis.incr(f"red_flag:{submitter}")
    # Deja rastro del par para auditoria.
    await redis.sadd(f"flag_share:{submitter}", owner)
