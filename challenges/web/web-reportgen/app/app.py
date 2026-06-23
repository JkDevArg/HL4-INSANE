"""ReportGen — web-reportgen (Web INSANE) · "Template Injection WAF".

Vulnerabilidad: SSTI (Server-Side Template Injection) en Jinja2 con WAF bypass.

El WAF bloquea palabras clave SSTI comunes con re.search sobre el string RAW
de la plantilla. El bypass: Jinja2 procesa secuencias de escape hexadecimales
(\x5f = '_') en el template ANTES de renderizar, pero el WAF comprueba el
string original ANTES de que Jinja2 lo procese. Usando \x5f\x5f en lugar de __
se bypasean las comprobaciones del WAF sin afectar la funcionalidad SSTI.

Bypass canónico:
  {{ lipsum['\x5f\x5fglobals\x5f\x5f']['os']['\x70\x6f\x70\x65\x6e']('cat /flag.txt')['\x72\x65\x61\x64']() }}

WAF ve: lipsum['\x5f\x5fglobals\x5f\x5f']... -> sin coincidencias con __globals__
Jinja2 renderiza: lipsum.__globals__['os'].popen('cat /flag.txt').read()
"""
import os
import re

from flask import Flask, jsonify, render_template_string, request
from jinja2 import TemplateError

from siem import emit
from reqlog import reqlog_http

app = Flask(__name__)

FLAG = os.environ.get("FLAG", "HL4{EJEMPLO_LOCAL}")

# Escribir flag a disco para que SSTI pueda leerla via os.popen
try:
    with open("/flag.txt", "w") as _fh:
        _fh.write(FLAG)
except OSError:
    pass

# ---------------------------------------------------------------------------
# WAF — lista de patrones bloqueados (aplicados al raw template string)
# ---------------------------------------------------------------------------
# Bloquea los bypasses más conocidos: __class__, __globals__, etc.
# PERO solo verifica el string tal cual: \x5f\x5f NO coincide con __
_WAF_PATTERNS = [
    r"__class__",
    r"__globals__",
    r"__builtins__",
    r"__subclasses__",
    r"__mro__",
    r"__base__",
    r"__init__",
    r"__import__",
    r"\bself\b",
    r"\brequest\b",
    r"\bconfig\b",
    r"\bimport\b",
    r"\beval\b",
    r"\bexec\b",
    r"\bpopen\b",
    r"\bsystem\b",
    r"\.read\(",
    r"\bopen\b",
    r"subprocess",
]

_WAF_RE = re.compile("|".join(_WAF_PATTERNS), re.IGNORECASE)


def _waf_check(template_str: str) -> str | None:
    """Retorna el patrón bloqueado o None si pasa el WAF."""
    m = _WAF_RE.search(template_str)
    return m.group(0) if m else None


# ---------------------------------------------------------------------------
# Plantilla base de la UI
# ---------------------------------------------------------------------------
_BASE_HTML = """<!doctype html>
<html lang="es">
<head><meta charset="utf-8">
<title>ReportGen v3</title>
<style>
body{font-family:sans-serif;background:#f4f6f9;margin:0;padding:0}
.navbar{background:#1a3a5c;color:white;padding:1rem 2rem;display:flex;align-items:center;gap:1rem}
.navbar h1{margin:0;font-size:1.4rem}
.container{max-width:900px;margin:2rem auto;padding:0 1rem}
.card{background:white;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1);padding:1.5rem;margin-bottom:1.5rem}
h2{color:#1a3a5c;margin-top:0}
textarea{width:100%;box-sizing:border-box;font-family:monospace;font-size:13px;border:1px solid #ccc;border-radius:4px;padding:.5rem}
button{background:#1a3a5c;color:white;border:none;padding:.6rem 1.4rem;border-radius:4px;cursor:pointer;font-size:1rem}
button:hover{background:#2a5a8c}
.output{background:#1e1e1e;color:#d4d4d4;font-family:monospace;padding:1rem;border-radius:4px;white-space:pre-wrap;min-height:3rem}
.error{background:#fff0f0;border:1px solid #f99;color:#900;padding:.8rem;border-radius:4px}
.waf-block{background:#fff3cd;border:1px solid #ffc107;color:#856404;padding:.8rem;border-radius:4px}
.badge{display:inline-block;padding:.2rem .6rem;border-radius:12px;font-size:.8rem;font-weight:bold}
.badge-insane{background:#dc3545;color:white}
small{color:#666}
</style>
</head>
<body>
<div class="navbar">
  <h1>ReportGen</h1>
  <span>Sistema de Generacion de Reportes Corporativos</span>
  <span class="badge badge-insane" style="margin-left:auto">SISTEMA INTERNO</span>
</div>
<div class="container">
  <div class="card">
    <h2>Personalizar Plantilla de Reporte</h2>
    <p>Ingresa tu plantilla Jinja2. Puedes usar variables de contexto disponibles:
    <code>company</code>, <code>date</code>, <code>report_id</code>, <code>author</code>.</p>
    <form method="POST" action="/render">
      <textarea name="template" rows="10" placeholder="Ej: Reporte de {{ company }} — Fecha: {{ date }}">{{ prefill }}</textarea><br><br>
      <button type="submit">Renderizar Reporte</button>
    </form>
    <br>
    <small>El sistema aplica filtros de seguridad para prevenir inyecciones maliciosas.</small>
  </div>

  {% if result is not none %}
  <div class="card">
    <h2>Resultado del Reporte</h2>
    {% if error %}
    <div class="error">{{ error }}</div>
    {% elif waf_blocked %}
    <div class="waf-block">WAF: Patron bloqueado detectado en la plantilla: <code>{{ waf_blocked }}</code></div>
    {% else %}
    <div class="output">{{ result }}</div>
    {% endif %}
  </div>
  {% endif %}

  <div class="card">
    <h2>Variables de Contexto Disponibles</h2>
    <table style="width:100%;border-collapse:collapse">
      <tr style="background:#f0f4f8"><th style="padding:.5rem;text-align:left">Variable</th><th style="padding:.5rem;text-align:left">Valor de ejemplo</th></tr>
      <tr><td style="padding:.5rem"><code>company</code></td><td style="padding:.5rem">Acme Corp S.A.</td></tr>
      <tr><td style="padding:.5rem"><code>date</code></td><td style="padding:.5rem">2024-01-15</td></tr>
      <tr><td style="padding:.5rem"><code>report_id</code></td><td style="padding:.5rem">RPT-20240115-001</td></tr>
      <tr><td style="padding:.5rem"><code>author</code></td><td style="padding:.5rem">Sistema Automatico</td></tr>
    </table>
    <br>
    <small>Nota: El acceso a variables internas del sistema esta restringido por el WAF.</small>
  </div>
</div>
</body>
</html>"""

# Contexto de plantilla (sin la flag)
_TEMPLATE_CONTEXT = {
    "company": "Acme Corp S.A.",
    "date": "2024-01-15",
    "report_id": "RPT-20240115-001",
    "author": "Sistema Automatico",
}


@app.before_request
def _log_request():
    try:
        src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        if src_ip and "," in src_ip:
            src_ip = src_ip.split(",")[0].strip()
        body = request.get_data(cache=True, as_text=True)
        reqlog_http(src_ip=src_ip, method=request.method, path=request.path,
                    query=request.query_string.decode("utf-8", "replace"),
                    headers=dict(request.headers), body=body)
    except Exception:
        pass


@app.get("/")
def index():
    return render_template_string(_BASE_HTML,
        result=None, error=None, waf_blocked=None,
        prefill="Reporte de {{ company }} — Fecha: {{ date }}")


@app.get("/health")
def health():
    return jsonify({"status": "ok", "engine": "Jinja2", "waf": "active"})


@app.post("/render")
def render():
    src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if src_ip and "," in src_ip:
        src_ip = src_ip.split(",")[0].strip()

    template_str = request.form.get("template", "")
    if not template_str:
        return render_template_string(_BASE_HTML,
            result="", error="Plantilla vacia", waf_blocked=None, prefill="")

    # WAF check — sobre el raw string, ANTES de que Jinja2 procese escapes
    blocked = _waf_check(template_str)
    if blocked:
        emit("waf_block", "warn", src_ip=src_ip,
             detail={"pattern": blocked, "template_snippet": template_str[:100]})
        return render_template_string(_BASE_HTML,
            result="", error=None, waf_blocked=blocked, prefill=template_str)

    # Renderizar con Jinja2 (vulnerable — SSTI intencional)
    try:
        # Jinja2 procesa \x5f como '_' durante el analisis del template
        rendered = render_template_string(template_str, **_TEMPLATE_CONTEXT)
    except TemplateError as e:
        return render_template_string(_BASE_HTML,
            result="", error=f"Error en plantilla: {e}", waf_blocked=None, prefill=template_str)
    except Exception as e:
        emit("render_error", "warn", src_ip=src_ip, detail={"error": str(e)})
        return render_template_string(_BASE_HTML,
            result="", error=f"Error inesperado: {e}", waf_blocked=None, prefill=template_str)

    # Detectar flag en el output (challenge_solved)
    if FLAG in rendered and FLAG != "HL4{EJEMPLO_LOCAL}":
        emit("challenge_solved", "alert", src_ip=src_ip,
             detail={"vuln": "ssti-jinja2-waf-bypass"})

    return render_template_string(_BASE_HTML,
        result=rendered, error=None, waf_blocked=None, prefill=template_str)


# API endpoint para herramientas automatizadas
@app.post("/api/render")
def api_render():
    src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if src_ip and "," in src_ip:
        src_ip = src_ip.split(",")[0].strip()

    data = request.get_json(silent=True) or {}
    template_str = data.get("template", "")
    if not template_str:
        return jsonify({"error": "template requerido"}), 400

    blocked = _waf_check(template_str)
    if blocked:
        emit("waf_block", "warn", src_ip=src_ip,
             detail={"pattern": blocked, "template_snippet": template_str[:100]})
        return jsonify({"error": "WAF_BLOCK", "blocked_pattern": blocked}), 403

    try:
        rendered = render_template_string(template_str, **_TEMPLATE_CONTEXT)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    if FLAG in rendered and FLAG != "HL4{EJEMPLO_LOCAL}":
        emit("challenge_solved", "alert", src_ip=src_ip,
             detail={"vuln": "ssti-jinja2-waf-bypass"})

    return jsonify({"rendered": rendered})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True)
