import os
from fastapi import FastAPI

app = FastAPI()

FLAG = os.environ.get("FLAG", "HL4{test_gobl1n_flag}")


@app.get("/flag")
async def get_flag():
    return {"flag": FLAG}


# Stubs mantenidos por compatibilidad con peticiones del overlay antiguo
@app.post("/session")
async def session():
    return {"ok": True}


@app.get("/status")
async def status():
    return {"has_session": True, "remaining": 0}
