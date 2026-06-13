"""Router del scoreboard: puntos por equipo, orden y desempate por tiempo."""
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.deps import get_current_team
from app.models import Solve, Team
from app.schemas import ScoreboardEntry, ScoreboardResponse

router = APIRouter(tags=["scoreboard"])


@router.get("/scoreboard", response_model=ScoreboardResponse)
async def scoreboard(
    _team: Team = Depends(get_current_team),  # requiere VPN + auth
    db: AsyncSession = Depends(get_db),
):
    """Tabla de posiciones.

    Orden: mas puntos primero; a igualdad de puntos, gana quien llego antes
    a ese puntaje (ultimo solve mas temprano = mejor, criterio CTF estandar).
    """
    # Agregados por equipo via LEFT JOIN para incluir equipos sin solves.
    stmt = (
        select(
            Team.team_id,
            Team.display_name,
            func.coalesce(func.sum(Solve.points), 0).label("points"),
            func.count(Solve.id).label("solves"),
            func.max(Solve.solved_at).label("last_solve"),
        )
        .select_from(Team)
        .outerjoin(Solve, Solve.team_pk == Team.id)
        .group_by(Team.id, Team.team_id, Team.display_name)
    )
    rows = (await db.execute(stmt)).all()

    # Ordena en Python: puntos desc, luego last_solve asc (None al final).
    def sort_key(r):
        last = r.last_solve
        # Equipos sin solve van al final del desempate.
        return (-int(r.points), last.timestamp() if last else float("inf"))

    ordered = sorted(rows, key=sort_key)

    entries = [
        ScoreboardEntry(
            rank=i + 1,
            team_id=r.team_id,
            display_name=r.display_name,
            points=int(r.points),
            solves=int(r.solves),
            last_solve=r.last_solve,
        )
        for i, r in enumerate(ordered)
    ]
    return ScoreboardResponse(entries=entries)
