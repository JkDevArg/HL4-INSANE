"""Modelos ORM: equipos, retos, solves, asignaciones e instancias on-demand."""
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class Team(Base):
    __tablename__ = "teams"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    team_id: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(64), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    solves: Mapped[list["Solve"]] = relationship(back_populates="team", cascade="all, delete-orphan")


class Challenge(Base):
    """Metadata de reto visible al jugador. La flag nunca se guarda aqui."""

    __tablename__ = "challenges"

    challenge_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    difficulty: Mapped[str] = mapped_column(String(32), nullable=False)
    points: Mapped[int] = mapped_column(Integer, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    connection_info: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    visible: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    solves: Mapped[list["Solve"]] = relationship(back_populates="challenge")


class Solve(Base):
    __tablename__ = "solves"
    __table_args__ = (UniqueConstraint("team_pk", "challenge_id", name="uq_team_challenge"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    team_pk: Mapped[int] = mapped_column(ForeignKey("teams.id"), nullable=False, index=True)
    team_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    challenge_id: Mapped[str] = mapped_column(ForeignKey("challenges.challenge_id"), nullable=False)
    points: Mapped[int] = mapped_column(Integer, nullable=False)
    solved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    team: Mapped["Team"] = relationship(back_populates="solves")
    challenge: Mapped["Challenge"] = relationship(back_populates="solves")


class TeamChallengeAssignment(Base):
    """Asigna exactamente que reto le corresponde a cada equipo por categoria.

    Anti-trampa: ningun equipo ve ni puede submitear retos de otro equipo.
    Cada team_id recibe exactamente un reto unico por categoria (web/api/crypto/reversing).
    """

    __tablename__ = "team_challenge_assignments"
    __table_args__ = (UniqueConstraint("team_id", "challenge_id", name="uq_team_assignment"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    team_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("teams.team_id"), nullable=False, index=True
    )
    challenge_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("challenges.challenge_id"), nullable=False
    )
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class ChallengeInstance(Base):
    """Ciclo de vida de la instancia Docker de un reto para un equipo especifico.

    Los jugadores inician/detienen su instancia on-demand desde la UI.
    El status se sincroniza con docker compose ps en cada consulta.
    """

    __tablename__ = "challenge_instances"
    __table_args__ = (UniqueConstraint("team_id", "challenge_id", name="uq_team_instance"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    team_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("teams.team_id"), nullable=False, index=True
    )
    challenge_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("challenges.challenge_id"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="stopped")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    container_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
