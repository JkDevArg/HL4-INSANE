"""Template de reto WEB (Flask).

- Lee la flag SOLO de os.environ["FLAG"] (inyectada por equipo).
- NO hardcodea flags.
- Ejemplo de emision SIEM opcional (siem.py).

Reemplaza la logica de abajo por tu vulnerabilidad real.
"""
import os

from flask import Flask, jsonify, request

from siem import emit

app = Flask(__name__)

# La flag se inyecta por equipo. En local cae a un valor de ejemplo.
FLAG = os.environ.get("FLAG", "flag{EJEMPLO_LOCAL}")


@app.get("/")
def index():
    return jsonify({"app": "template-web", "hint": "reemplaza esta logica por el reto real"})


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


# Ejemplo: un endpoint "protegido" que entrega la flag.
# En un reto real, llegar aqui requiere explotar la vulnerabilidad.
@app.get("/admin/flag")
def admin_flag():
    if request.headers.get("X-Admin") != "true":
        # Acceso sospechoso -> evento SIEM opcional.
        emit("scan_detected", "warn", src_ip=request.remote_addr,
             detail={"path": "/admin/flag", "reason": "missing-admin-header"})
        return jsonify({"error": "forbidden"}), 403
    return jsonify({"flag": FLAG})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
