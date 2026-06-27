import hmac
import hashlib
import os
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

app = FastAPI(title="CTFHL4 Flag Service", docs_url=None, redoc_url=None)

MASTER_SECRET = os.environ["MASTER_SECRET"]


# Challenges con flag estática (igual para todos los equipos).
# La flag se obtiene dentro del propio reto, no vía HMAC por equipo.
STATIC_FLAGS: dict[str, str] = {
    "gobl1n-poke-l4bs": "HL4{pok3m0n-for3v3r-Hackl4bs}",
}


def generate_flag(team_id: str, challenge_id: str) -> str:
    if challenge_id in STATIC_FLAGS:
        return STATIC_FLAGS[challenge_id]
    # Formato HL4{...}, único por (equipo, reto) vía HMAC
    key = f"{MASTER_SECRET}:{team_id}:{challenge_id}".encode()
    digest = hmac.new(MASTER_SECRET.encode(), key, hashlib.sha256).hexdigest()
    return f"HL4{{{digest[:20]}}}"


class ValidateRequest(BaseModel):
    team_id: str
    challenge_id: str
    flag: str


class WhoseFlagRequest(BaseModel):
    flag: str
    # challenge_id es opcional pero acota la busqueda (recomendado).
    challenge_id: str | None = None


# Universo de equipos y retos para resolver whose-flag.
# Se puede sobre-escribir por entorno (CSV) sin tocar codigo.
TEAM_COUNT = int(os.environ.get("TEAM_COUNT", "10"))
CHALLENGE_IDS = [c for c in os.environ.get("CHALLENGE_IDS", "").split(",") if c]


@app.get("/flag")
def get_flag(team_id: str, challenge_id: str, request: Request):
    # En producción: validar que la request viene de un reto interno, no del cliente
    if not team_id or not challenge_id:
        raise HTTPException(status_code=400, detail="team_id y challenge_id requeridos")
    return {"flag": generate_flag(team_id, challenge_id)}


@app.post("/validate")
def validate_flag(body: ValidateRequest):
    expected = generate_flag(body.team_id, body.challenge_id)
    correct = hmac.compare_digest(expected, body.flag)
    return {"valid": correct}


@app.post("/whose-flag")
def whose_flag(body: WhoseFlagRequest):
    """Anti-cheat (ARCHITECTURE seccion 4): devuelve a que equipo pertenece
    una flag. Como la flag es HMAC(team_id, challenge_id), buscamos el par
    que la genera.

    - Si se provee challenge_id: solo se prueban los team_id (rapido y exacto).
    - Si no: se prueba contra la lista CHALLENGE_IDS (si esta configurada).

    Respuesta: {team_id: str|null, challenge_id: str|null}.
    """
    teams = [f"team_{n:02d}" for n in range(1, TEAM_COUNT + 1)]
    challenges = [body.challenge_id] if body.challenge_id else CHALLENGE_IDS

    for team_id in teams:
        for challenge_id in challenges:
            if hmac.compare_digest(generate_flag(team_id, challenge_id), body.flag):
                return {"team_id": team_id, "challenge_id": challenge_id}
    return {"team_id": None, "challenge_id": None}


@app.get("/health")
def health():
    return {"status": "ok"}
