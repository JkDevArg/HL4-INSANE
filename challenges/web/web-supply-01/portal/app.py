"""DevOps Portal — web-supply-01 (Supply chain INSANE).

Escenario realista:
  - ACME tiene un index PyPI PRIVADO (servicio `registry`) que permite subir
    paquetes SIN firma ni revisión (mala práctica muy común en empresas).
  - El portal reconstruye un microservicio interno (`acme-billing`) que depende
    del paquete interno `acme-utils`. El "build runner" instala las dependencias
    desde ese index privado, prefiriéndolo sobre PyPI público.
  - La FLAG vive en el entorno del build runner (secreto de CI). Si el atacante
    logra ejecutar código durante el `pip install`, lee el secreto.

Vulnerabilidad central: DEPENDENCY CONFUSION / SUPPLY CHAIN.
El atacante publica una versión MAYOR de `acme-utils` en el registry interno,
con un `setup.py` que ejecuta código en tiempo de instalación (RCE en el runner).

NOTA: la flag se inyecta por equipo vía env FLAG. NO está hardcodeada.
"""
import os
import re
import subprocess
import tempfile
import uuid

from flask import Flask, jsonify, request, Response

from siem import emit
from reqlog import reqlog_http

app = Flask(__name__)


@app.before_request
def _log_request():
    """Loguea CADA petición entrante COMPLETA (método, ruta, query, headers,
    body) para el SIEM del stream. No interfiere con el manejo normal."""
    try:
        # IP real del cliente (detrás del proxy/VPN puede venir en XFF).
        src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        if src_ip and "," in src_ip:
            src_ip = src_ip.split(",")[0].strip()
        # Cuerpo crudo (form/json/texto) tal cual lo envió el jugador.
        body = request.get_data(cache=True, as_text=True)
        reqlog_http(
            src_ip=src_ip,
            method=request.method,
            path=request.path,
            query=request.query_string.decode("utf-8", "replace"),
            headers=dict(request.headers),
            body=body,
        )
    except Exception:
        # El logging jamás debe tumbar el reto.
        pass

FLAG = os.environ.get("FLAG", "flag{EJEMPLO_LOCAL}")
REGISTRY_URL = os.environ.get("REGISTRY_URL", "http://registry:8080")

# Resultados de builds (en memoria). build_id -> log.
BUILDS: dict[str, dict] = {}

# Nombre del paquete interno que el runner reinstala en cada build.
INTERNAL_PACKAGE = "acme-utils"

INDEX_PAGE = """<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>ACME DevOps Portal</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:780px;margin:40px auto;color:#1c2128;background:#f6f8fa}
 code,pre{background:#eef1f4;padding:2px 6px;border-radius:4px}
 .card{background:#fff;border:1px solid #d0d7de;border-radius:8px;padding:18px;margin:14px 0}
 button{background:#1f6feb;color:#fff;border:0;padding:8px 14px;border-radius:6px;cursor:pointer}
 h1{font-size:22px}
</style></head><body>
<h1>ACME · DevOps Portal</h1>
<div class="card">
 <h3>Microservicio: <code>acme-billing</code></h3>
 <p>Build runner reconstruye el servicio e instala dependencias desde el
    <b>registry interno</b> de la empresa.</p>
 <p>Index privado: <code>%REGISTRY%/simple/</code></p>
 <form action="/build" method="post"><button>Rebuild acme-billing</button></form>
</div>
<div class="card">
 <h3>Política de dependencias (CI)</h3>
 <pre>pip install --index-url %REGISTRY%/simple/ \\
     --extra-index-url https://pypi.org/simple/ \\
     acme-utils</pre>
 <p>El index interno tiene <b>prioridad</b>. Cualquiera con acceso a la red
    interna puede publicar paquetes (sin firma). <i>(TODO seguridad: firmar)</i></p>
</div>
<div class="card">
 <h3>API</h3>
 <ul>
   <li><code>POST /build</code> → lanza un build, devuelve build_id + log</li>
   <li><code>GET /build/&lt;id&gt;</code> → log del build</li>
 </ul>
</div>
</body></html>"""


@app.get("/")
def index():
    return Response(INDEX_PAGE.replace("%REGISTRY%", REGISTRY_URL), mimetype="text/html")


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


def _run_build(build_id: str) -> dict:
    """Ejecuta el build runner del microservicio acme-billing.

    Etapas (CI realista):
      1) `pip install acme-utils` desde el index INTERNO (con prioridad sobre
         PyPI público) -> dependency confusion: se instala la versión MAYOR
         que el atacante haya publicado en el registry.
      2) "Smoke test" post-build: el runner IMPORTA la dependencia recién
         instalada y registra su banner de versión en el log del build.
         (Patrón común: validar que la dependencia carga tras instalarla.)

    Diseño de seguridad del reto:
      - La FLAG se inyecta como secreto de CI SOLO en el entorno del runner.
        El paquete malicioso, al ser importado en el smoke test, lee ese env
        y lo incorpora a su salida -> exfiltración vía el log del build.
      - El portal NO entrega la flag directamente: hay que controlar el código
        que el runner ejecuta (la dependencia).
    """
    workdir = tempfile.mkdtemp(prefix=f"build_{build_id}_")
    deps = os.path.join(workdir, "deps")
    env = os.environ.copy()
    # Secreto de CI disponible SOLO para el runner (no expuesto vía HTTP).
    env["FLAG"] = FLAG
    env["CI"] = "true"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"

    install_cmd = [
        "pip", "install",
        "--no-cache-dir",
        "--target", deps,
        "--index-url", f"{REGISTRY_URL}/simple/",
        "--extra-index-url", "https://pypi.org/simple/",
        "--upgrade",
        INTERNAL_PACKAGE,
    ]
    log_parts = [f"$ {' '.join(install_cmd)}"]
    try:
        proc = subprocess.run(
            install_cmd, cwd=workdir, env=env,
            capture_output=True, text=True, timeout=120,
        )
        log_parts.append(proc.stdout)
        log_parts.append(proc.stderr)
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        return {"id": build_id, "rc": -1, "log": "install timeout"}

    # 2) Smoke test: importar la dependencia instalada y emitir su banner.
    # El runner exporta el banner que la propia dependencia genere (controlable
    # por el atacante si envenenó el paquete).
    smoke = (
        "import importlib, sys\n"
        "try:\n"
        "    m = importlib.import_module('acme_utils')\n"
        "    fn = getattr(m, 'version_banner', None)\n"
        "    print('[smoke] acme_utils:', fn() if callable(fn) else getattr(m, '__version__', 'ok'))\n"
        "except Exception as e:\n"
        "    print('[smoke] import falló:', e)\n"
    )
    try:
        smoke_env = env.copy()
        smoke_env["PYTHONPATH"] = deps
        sproc = subprocess.run(
            ["python", "-c", smoke], cwd=workdir, env=smoke_env,
            capture_output=True, text=True, timeout=30,
        )
        log_parts.append(sproc.stdout)
        log_parts.append(sproc.stderr)
    except subprocess.TimeoutExpired:
        log_parts.append("[smoke] timeout")

    log = "\n".join(p for p in log_parts if p)
    return {"id": build_id, "rc": rc, "log": log[-8000:]}


@app.post("/build")
def build():
    build_id = uuid.uuid4().hex[:12]
    result = _run_build(build_id)
    BUILDS[build_id] = result

    # SIEM: un build que instala una version no-oficial de acme-utils es
    # sospechoso. Heuristica simple: el log menciona una version "rara".
    if re.search(r"acme-utils-\d+\.\d+", result["log"]) and result["rc"] == 0:
        emit("scan_detected", "alert", src_ip=request.remote_addr,
             detail={"build_id": build_id, "reason": "build-installed-internal-pkg"})

    return jsonify(result)


@app.get("/build/<bid>")
def get_build(bid: str):
    if bid not in BUILDS:
        return jsonify({"error": "not found"}), 404
    return jsonify(BUILDS[bid])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
