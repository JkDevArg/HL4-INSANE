"""Configuracion central de la platform-api.

Todas las variables sensibles llegan por entorno (ver .env.example).
IMPORTANTE: aqui NO vive el MASTER_SECRET de las flags; la validacion
de flags se delega SIEMPRE al flag-service (ver ARCHITECTURE.md seccion 4).
"""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Base de datos / cache ---
    # Usamos nombres de host Docker (mapeados luego en docker-compose).
    database_url: str = "postgresql+asyncpg://ctf:ctf@postgres:5432/ctf"
    redis_url: str = "redis://redis:6379/0"

    # --- Servicios internos (red 10.10.100.0/24) ---
    flag_service_url: str = "http://flag-service:8001"
    collector_url: str = "http://collector:9000"

    # --- JWT ---
    jwt_secret: str = "cambia-esto-en-produccion"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 720  # 12h, dura toda la jornada del CTF

    # --- Gate de red (solo VPN) ---
    # Rango del pool VPN segun ARCHITECTURE.md seccion 2.
    vpn_cidr: str = "10.10.0.0/16"
    # Si esta activo, se confia en la cabecera X-Forwarded-For (nginx delante).
    trust_forwarded_for: bool = True

    # --- Politicas anti-cheat / rate-limit ---
    submit_rate_limit: int = 10          # submits permitidos por ventana
    submit_rate_window: int = 60         # segundos de la ventana
    max_sessions_per_team: int = 4       # maximo de sesiones concurrentes por equipo
    session_ttl_seconds: int = 720 * 60  # vida de la sesion en Redis (= jwt_expire_minutes)

    # --- Numero de equipos del evento ---
    team_count: int = 10


@lru_cache
def get_settings() -> Settings:
    """Singleton de settings (cacheado)."""
    return Settings()
