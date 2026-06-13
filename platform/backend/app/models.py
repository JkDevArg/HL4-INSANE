"""Modelos ORM: equipos, retos y solves.

Las flags NUNCA se guardan aqui (se validan via flag-service). La tabla
de challenges solo lleva metadata visible al jugador.
"""
from datetime import datetime

from sqlalchemy import (
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
    """Un equipo = una cuenta de acceso (team_01 .. team_10)."""

    __tablename__ = "teams"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # team_id logico, p.ej. "team_03". Es el username de login.
    team_id: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(64), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    solves: Mapped[list["Solve"]] = relationship(back_populates="team", cascade="all, delete-orphan")


class Challenge(Base):
    """Metadata de reto visible al jugador. No contiene la flag."""

    __tablename__ = "challenges"

    # PK = challenge_id logico, p.ej. "web-supply-01".
    challenge_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    category: Mapped[str] = mapped_column(String(32), nullable=False)        # web | api | crypto
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    difficulty: Mapped[str] = mapped_column(String(32), nullable=False)      # insane
    points: Mapped[int] = mapped_column(Integer, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # Pista de conexion / endpoint mostrada al jugador (opcional).
    connection_info: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    visible: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    solves: Mapped[list["Solve"]] = relationship(back_populates="challenge")


class Solve(Base):
    """Registro de un reto resuelto por un equipo. Unico por (team, challenge)."""

    __tablename__ = "solves"
    __table_args__ = (UniqueConstraint("team_pk", "challenge_id", name="uq_team_challenge"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    team_pk: Mapped[int] = mapped_column(ForeignKey("teams.id"), nullable=False, index=True)
    # Guardamos tambien el team_id logico para consultas rapidas del scoreboard.
    team_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    challenge_id: Mapped[str] = mapped_column(ForeignKey("challenges.challenge_id"), nullable=False)
    points: Mapped[int] = mapped_column(Integer, nullable=False)
    solved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    team: Mapped["Team"] = relationship(back_populates="solves")
    challenge: Mapped["Challenge"] = relationship(back_populates="solves")
