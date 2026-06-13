"""Punto de entrada de la platform-api (FastAPI).

Monta los routers, configura CORS para el frontend (servido tras nginx en
la misma red VPN) y crea las tablas al arrancar si no existen.
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.db import init_db
from app.routers import auth, challenges, scoreboard

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Crea tablas si no existen (la siembra de datos la hace seed.py).
    await init_db()
    yield


app = FastAPI(
    title="CTFHL4-INSANE platform-api",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url=None,
)

# CORS: el frontend vive en el mismo dominio VPN; abierto a la red interna.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(challenges.router)
app.include_router(scoreboard.router)


@app.get("/health", tags=["meta"])
async def health():
    """Healthcheck simple (sin gate VPN, para readiness de docker/nginx)."""
    return {"status": "ok"}
