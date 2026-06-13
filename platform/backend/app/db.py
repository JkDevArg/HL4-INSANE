"""Capa de base de datos (SQLAlchemy async) y cliente Redis compartido."""
from collections.abc import AsyncGenerator

import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings

settings = get_settings()

# --- PostgreSQL async ---
engine = create_async_engine(settings.database_url, echo=False, pool_pre_ping=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


class Base(DeclarativeBase):
    """Base declarativa para los modelos ORM."""


# --- Redis (sesiones, bans, rate-limit) ---
# Cliente unico reutilizado por toda la app.
redis_client: aioredis.Redis = aioredis.from_url(
    settings.redis_url, encoding="utf-8", decode_responses=True
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependencia FastAPI que entrega una sesion de DB y la cierra al final."""
    async with SessionLocal() as session:
        yield session


async def get_redis() -> aioredis.Redis:
    """Dependencia FastAPI que entrega el cliente Redis compartido."""
    return redis_client


async def init_db() -> None:
    """Crea las tablas si no existen (idempotente). Usado por seed y arranque."""
    # Importacion local para registrar los modelos en el metadata.
    from app import models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
