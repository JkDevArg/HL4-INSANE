"""Template de reto API (FastAPI).

- Lee la flag SOLO de os.environ["FLAG"] (inyectada por equipo).
- NO hardcodea flags.

Reemplaza la logica por tu vulnerabilidad real (BOLA, mass assignment, JWT...).
"""
import os

from fastapi import FastAPI, Header, HTTPException, Request

from siem import emit

app = FastAPI(title="template-api", docs_url=None, redoc_url=None)

FLAG = os.environ.get("FLAG", "HL4{EJEMPLO_LOCAL}")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/me")
def me():
    return {"user": "guest", "role": "user"}


# Ejemplo: endpoint admin que entrega la flag. En el reto real,
# llegar como admin requiere explotar la cadena de vulnerabilidades.
@app.get("/admin/flag")
def admin_flag(request: Request, x_role: str = Header(default="user")):
    if x_role != "admin":
        emit("scan_detected", "warn", src_ip=request.client.host if request.client else None,
             detail={"path": "/admin/flag", "role": x_role})
        raise HTTPException(status_code=403, detail="forbidden")
    return {"flag": FLAG}
