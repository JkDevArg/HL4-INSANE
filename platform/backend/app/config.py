"""Configuracion central de la platform-api."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = "postgresql+asyncpg://ctf:ctf@postgres:5432/ctf"
    redis_url: str = "redis://redis:6379/0"

    flag_service_url: str = "http://flag-service:8001"
    collector_url: str = "http://collector:9000"

    jwt_secret: str = "cambia-esto-en-produccion"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 720

    vpn_cidr: str = "10.10.0.0/16"
    trust_forwarded_for: bool = True

    submit_rate_limit: int = 10
    submit_rate_window: int = 60
    max_sessions_per_team: int = 4
    session_ttl_seconds: int = 720 * 60

    # 5 equipos — un reto unico por categoria por equipo
    team_count: int = 5


@lru_cache
def get_settings() -> Settings:
    return Settings()
