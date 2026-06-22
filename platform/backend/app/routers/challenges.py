"""Router de retos: listado (filtrado por asignacion de equipo), submit y anti-cheat."""
import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db import get_db, get_redis
from app.deps import get_current_team
from app.flagclient import validate_flag, whose_flag
from app.instance_manager import get_status
from app.models import Challenge, ChallengeInstance, Solve, Team, TeamChallengeAssignment
from app.schemas import ChallengeOut, SubmitRequest, SubmitResponse
from app.siem import emit_event

settings = get_settings()
router = APIRouter(prefix="/challenges", tags=["challenges"])


async def _check_submit_rate(redis: aioredis.Redis, team_id: str) -> bool:
    key = f"submit_rl:{team_id}"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, settings.submit_rate_window)
    return count <= settings.submit_rate_limit


async def _solved_ids(db: AsyncSession, team_pk: int) -> set[str]:
    result = await db.execute(select(Solve.challenge_id).where(Solve.team_pk == team_pk))
    return {row[0] for row in result.all()}


async def _instance_statuses(db: AsyncSession, team_id: str) -> dict[str, str]:
    r = await db.execute(
        select(ChallengeInstance).where(ChallengeInstance.team_id == team_id)
    )
    return {i.challenge_id: i.status for i in r.scalars().all()}


def _team_n(team_id: str) -> str:
    suffix = team_id.split("_")[-1]
    try:
        return str(int(suffix))
    except ValueError:
        return suffix


def _render_conn(connection_info: str, team_id: str) -> str:
    return connection_info.replace("{N}", _team_n(team_id))


@router.get("", response_model=list[ChallengeOut])
async def list_challenges(
    team: Team = Depends(get_current_team),
    db: AsyncSession = Depends(get_db),
):
    """Lista SOLO los retos asignados al equipo autenticado.

    Anti-trampa: cada equipo ve exclusivamente sus propios retos.
    Incluye el estado de la instancia Docker para que el frontend muestre Start/Stop.
    """
    # IDs de retos asignados al equipo
    asgn = await db.execute(
        select(TeamChallengeAssignment.challenge_id).where(
            TeamChallengeAssignment.team_id == team.team_id
        )
    )
    assigned_ids = {row[0] for row in asgn.all()}

    if not assigned_ids:
        return []

    result = await db.execute(
        select(Challenge)
        .where(Challenge.challenge_id.in_(assigned_ids))
        .where(Challenge.visible.is_(True))
        .order_by(Challenge.sort_order)
    )
    challenges = result.scalars().all()

    solved = await _solved_ids(db, team.id)
    inst_map = await _instance_statuses(db, team.team_id)

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
            instance_status=inst_map.get(c.challenge_id, "stopped"),
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
    src_ip = getattr(request.state, "src_ip", None)
    flag = body.flag.strip()

    # Verificar que el reto está asignado a este equipo
    asgn = await db.execute(
        select(TeamChallengeAssignment).where(
            TeamChallengeAssignment.team_id == team.team_id,
            TeamChallengeAssignment.challenge_id == challenge_id,
        )
    )
    if asgn.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Este reto no está asignado a tu equipo.",
        )

    result = await db.execute(
        select(Challenge).where(
            Challenge.challenge_id == challenge_id, Challenge.visible.is_(True)
        )
    )
    challenge = result.scalar_one_or_none()
    if challenge is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Reto no encontrado.")

    if not await _check_submit_rate(redis, team.team_id):
        await emit_event(
            event_type="submit", severity="warn",
            team_id=team.team_id, user=team.team_id, src_ip=src_ip,
            challenge_id=challenge_id, detail={"result": "rate_limited"},
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiados intentos. Espera un momento.",
        )

    await emit_event(
        event_type="submit", severity="info",
        team_id=team.team_id, user=team.team_id, src_ip=src_ip,
        challenge_id=challenge_id, detail={"flag_len": len(flag)},
    )

    already = await db.execute(
        select(Solve).where(Solve.team_pk == team.id, Solve.challenge_id == challenge_id)
    )
    if already.scalar_one_or_none() is not None:
        return SubmitResponse(correct=True, already_solved=True, points_awarded=0,
                              message="Reto ya resuelto anteriormente.")

    owner = await whose_flag(flag, challenge_id, settings.team_count)
    if owner is not None and owner != team.team_id:
        await _flag_red(redis, team.team_id, owner)
        await emit_event(
            event_type="cheat_flag_share", severity="critical",
            team_id=team.team_id, user=team.team_id, src_ip=src_ip,
            challenge_id=challenge_id,
            detail={"submitter_team": team.team_id, "owner_team": owner, "reason": "flag_share"},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Flag perteneciente a otro equipo. Incidente registrado.",
        )

    is_valid = await validate_flag(team.team_id, challenge_id, flag)
    if not is_valid:
        await emit_event(
            event_type="flag_fail", severity="warn",
            team_id=team.team_id, user=team.team_id, src_ip=src_ip,
            challenge_id=challenge_id, detail={"result": "invalid_flag"},
        )
        return SubmitResponse(correct=False, message="Flag incorrecta.")

    solve = Solve(team_pk=team.id, team_id=team.team_id,
                  challenge_id=challenge_id, points=challenge.points)
    db.add(solve)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return SubmitResponse(correct=True, already_solved=True, points_awarded=0,
                              message="Reto ya resuelto anteriormente.")

    await emit_event(
        event_type="flag_ok", severity="info",
        team_id=team.team_id, user=team.team_id, src_ip=src_ip,
        challenge_id=challenge_id, detail={"points": challenge.points},
    )
    return SubmitResponse(correct=True, points_awarded=challenge.points,
                          message=f"Correcto! +{challenge.points} puntos.")


async def _flag_red(redis: aioredis.Redis, submitter: str, owner: str) -> None:
    await redis.sadd("teams_red_flag", submitter)
    await redis.incr(f"red_flag:{submitter}")
    await redis.sadd(f"flag_share:{submitter}", owner)
