"""Utilidades de autenticacion: hashing de contrasenas, JWT y sesiones Redis.

Cada equipo es una cuenta. El JWT lleva el claim `team_id` y un `sid`
(session id) que se registra en Redis para imponer el limite de 4
sesiones concurrentes por equipo (ARCHITECTURE / requisito 2).
"""
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
import redis.asyncio as aioredis
from jose import JWTError, jwt

from app.config import get_settings

settings = get_settings()


# ----------------------------------------------------------------------------
# Contrasenas (bcrypt directo; passlib es incompatible con bcrypt 4.x)
# ----------------------------------------------------------------------------
def hash_password(plain: str) -> str:
    """Genera el hash bcrypt de la contrasena."""
    # bcrypt limita a 72 bytes; truncamos para evitar errores con claves largas.
    raw = plain.encode("utf-8")[:72]
    return bcrypt.hashpw(raw, bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verifica una contrasena contra su hash bcrypt."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8")[:72], hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# ----------------------------------------------------------------------------
# JWT
# ----------------------------------------------------------------------------
def create_access_token(team_id: str, session_id: str) -> str:
    """Genera un JWT con team_id + sid + expiracion."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": team_id,
        "team_id": team_id,
        "sid": session_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.jwt_expire_minutes)).timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict | None:
    """Decodifica y valida el JWT. Devuelve el payload o None si es invalido."""
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except JWTError:
        return None


# ----------------------------------------------------------------------------
# Sesiones en Redis (limite de 4 concurrentes por equipo)
# ----------------------------------------------------------------------------
def _sessions_key(team_id: str) -> str:
    return f"sessions:{team_id}"


async def register_session(redis: aioredis.Redis, team_id: str) -> str | None:
    """Intenta registrar una nueva sesion para el equipo.

    Devuelve el session_id si hay cupo (< max_sessions_per_team), o None si
    el equipo ya tiene el maximo de sesiones activas. Las sesiones se guardan
    en un sorted set con score = timestamp de expiracion, de modo que las
    caducadas se purgan antes de contar.
    """
    key = _sessions_key(team_id)
    now = datetime.now(timezone.utc).timestamp()
    expire_at = now + settings.session_ttl_seconds

    # Purga sesiones expiradas (score < ahora).
    await redis.zremrangebyscore(key, 0, now)

    current = await redis.zcard(key)
    if current >= settings.max_sessions_per_team:
        return None

    session_id = uuid.uuid4().hex
    await redis.zadd(key, {session_id: expire_at})
    # TTL de respaldo sobre la key completa.
    await redis.expire(key, settings.session_ttl_seconds)
    return session_id


async def session_is_active(redis: aioredis.Redis, team_id: str, session_id: str) -> bool:
    """Verifica que el session_id siga vigente (no expirado ni revocado)."""
    key = _sessions_key(team_id)
    now = datetime.now(timezone.utc).timestamp()
    await redis.zremrangebyscore(key, 0, now)
    score = await redis.zscore(key, session_id)
    return score is not None


async def revoke_session(redis: aioredis.Redis, team_id: str, session_id: str) -> None:
    """Elimina una sesion (logout)."""
    await redis.zrem(_sessions_key(team_id), session_id)
