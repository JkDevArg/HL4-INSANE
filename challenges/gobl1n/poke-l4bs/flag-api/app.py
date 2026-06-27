import os
import time
import uuid

from fastapi import FastAPI, HTTPException, Request, Response

app = FastAPI()

FLAG = os.environ.get("FLAG", "HL4{test_gobl1n_flag}")
PLAY_SECONDS = int(os.environ.get("PLAY_SECONDS", "180"))

# session_id -> created_at (timestamp UNIX)
# Simple in-memory store; el contenedor es por-equipo, no necesita persistencia.
sessions: dict[str, float] = {}


@app.post("/session")
async def create_session(request: Request, response: Response):
    """Registra (o reutiliza) una sesión de juego e inicia el timer."""
    sid = request.cookies.get("ctf_sid")
    if sid and sid in sessions:
        elapsed = time.time() - sessions[sid]
        remaining = max(0, int(PLAY_SECONDS - elapsed))
        return {"remaining": remaining, "reused": True}
    sid = str(uuid.uuid4())
    sessions[sid] = time.time()
    response.set_cookie(
        "ctf_sid", sid,
        httponly=True,
        samesite="strict",
        max_age=7200,
        path="/",
    )
    return {"remaining": PLAY_SECONDS, "reused": False}


@app.get("/status")
async def get_status(request: Request):
    """Devuelve si hay sesión activa y cuántos segundos quedan."""
    sid = request.cookies.get("ctf_sid")
    if not sid or sid not in sessions:
        return {"has_session": False, "remaining": PLAY_SECONDS}
    elapsed = time.time() - sessions[sid]
    remaining = max(0, int(PLAY_SECONDS - elapsed))
    return {"has_session": True, "remaining": remaining}


@app.get("/flag")
async def get_flag(request: Request):
    """Entrega la flag solo si el timer de gameplay ya expiró."""
    sid = request.cookies.get("ctf_sid")
    if not sid or sid not in sessions:
        raise HTTPException(
            status_code=403,
            detail="Abre el reto desde el navegador del challenge",
        )
    elapsed = time.time() - sessions[sid]
    remaining = max(0, int(PLAY_SECONDS - elapsed))
    if remaining > 0:
        raise HTTPException(
            status_code=403,
            detail=f"Sigue jugando {remaining}s más",
        )
    return {"flag": FLAG}
