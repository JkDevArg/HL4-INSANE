"""Router: ciclo de vida de instancias on-demand (Start / Stop / Status)."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.deps import get_current_team
from app.instance_manager import get_status, start_instance, stop_instance
from app.models import ChallengeInstance, Team, TeamChallengeAssignment
from app.schemas import InstanceOut
from app.siem import emit_event

router = APIRouter(prefix="/instances", tags=["instances"])


async def _assert_assigned(db: AsyncSession, team_id: str, challenge_id: str) -> None:
    r = await db.execute(
        select(TeamChallengeAssignment).where(
            TeamChallengeAssignment.team_id == team_id,
            TeamChallengeAssignment.challenge_id == challenge_id,
        )
    )
    if r.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Este reto no está asignado a tu equipo.",
        )


async def _upsert_instance(
    db: AsyncSession, team_id: str, challenge_id: str
) -> ChallengeInstance:
    r = await db.execute(
        select(ChallengeInstance).where(
            ChallengeInstance.team_id == team_id,
            ChallengeInstance.challenge_id == challenge_id,
        )
    )
    inst = r.scalar_one_or_none()
    if inst is None:
        inst = ChallengeInstance(team_id=team_id, challenge_id=challenge_id)
        db.add(inst)
        await db.flush()
    return inst


@router.post("/{challenge_id}/start", response_model=InstanceOut)
async def start(
    challenge_id: str,
    team: Team = Depends(get_current_team),
    db: AsyncSession = Depends(get_db),
):
    await _assert_assigned(db, team.team_id, challenge_id)
    inst = await _upsert_instance(db, team.team_id, challenge_id)

    if inst.status == "running":
        return InstanceOut(challenge_id=challenge_id, status="running", message="Ya está corriendo.")

    inst.status = "starting"
    await db.commit()

    try:
        await start_instance(team.team_id, challenge_id)
        inst.status = "running"
        inst.started_at = datetime.now(tz=timezone.utc)
        await db.commit()
    except Exception as exc:
        inst.status = "error"
        await db.commit()
        raise HTTPException(status_code=500, detail=f"Error al iniciar: {str(exc)[:300]}")

    await emit_event(
        event_type="instance_start",
        severity="info",
        team_id=team.team_id,
        user=team.team_id,
        challenge_id=challenge_id,
        detail={"action": "start"},
    )
    return InstanceOut(challenge_id=challenge_id, status="running", message="Instancia iniciada.")


@router.post("/{challenge_id}/stop", response_model=InstanceOut)
async def stop(
    challenge_id: str,
    team: Team = Depends(get_current_team),
    db: AsyncSession = Depends(get_db),
):
    await _assert_assigned(db, team.team_id, challenge_id)
    inst = await _upsert_instance(db, team.team_id, challenge_id)

    await stop_instance(team.team_id, challenge_id)
    inst.status = "stopped"
    inst.started_at = None
    await db.commit()

    await emit_event(
        event_type="instance_stop",
        severity="info",
        team_id=team.team_id,
        user=team.team_id,
        challenge_id=challenge_id,
        detail={"action": "stop"},
    )
    return InstanceOut(challenge_id=challenge_id, status="stopped", message="Instancia detenida.")


@router.get("/{challenge_id}/status", response_model=InstanceOut)
async def instance_status(
    challenge_id: str,
    team: Team = Depends(get_current_team),
    db: AsyncSession = Depends(get_db),
):
    await _assert_assigned(db, team.team_id, challenge_id)
    real = await get_status(team.team_id, challenge_id)
    inst = await _upsert_instance(db, team.team_id, challenge_id)

    if inst.status != real and real in ("running", "stopped"):
        inst.status = real
        await db.commit()

    return InstanceOut(challenge_id=challenge_id, status=real)


@router.get("", response_model=list[InstanceOut])
async def list_instances(
    team: Team = Depends(get_current_team),
    db: AsyncSession = Depends(get_db),
):
    r = await db.execute(
        select(ChallengeInstance).where(ChallengeInstance.team_id == team.team_id)
    )
    return [InstanceOut(challenge_id=i.challenge_id, status=i.status) for i in r.scalars().all()]
