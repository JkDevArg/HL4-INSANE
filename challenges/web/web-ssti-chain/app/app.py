import os
import re
from functools import wraps
from jinja2 import Environment, BaseLoader, TemplateSyntaxError
from flask import Flask, render_template, request, redirect, url_for, session, jsonify

app = Flask(__name__)
app.secret_key = os.urandom(32)

FLAG = os.environ.get("FLAG", "HL4{EJEMPLO_LOCAL}")

# Write flag to /flag.txt at startup
try:
    with open("/flag.txt", "w") as f:
        f.write(FLAG + "\n")
except Exception:
    pass

# ---------------------------------------------------------------------------
# "Security" Sandbox
# ---------------------------------------------------------------------------
# Blocks these literal strings in the raw template source.
# Does NOT block partial strings or Jinja2 concatenation expressions.
# Bypass: use Jinja2 ~ operator to concatenate string parts at render time.
#   e.g., "__class__" is blocked, but "__cl" ~ "ass__" is not.
BLOCKED_STRINGS = [
    "__class__",
    "__base__",
    "__subclasses__",
    "__import__",
    "__builtins__",
    "popen",
    "os.path",
    " os ",
    "'os'",
    '"os"',
    "eval(",
    "exec(",
    "compile(",
    "subprocess",
    "open(",
    "system(",
]


def sandbox_check(template_src: str) -> tuple[bool, str]:
    """
    Check raw template source for blocked patterns.
    Returns (is_safe, reason).

    VULNERABILITY: checks literal strings, not runtime values.
    Jinja2's ~ operator concatenates at RENDER TIME, after this check.
    So `'__cl' ~ 'ass__'` passes the check but produces '__class__' at runtime.
    """
    for blocked in BLOCKED_STRINGS:
        if blocked in template_src:
            return False, f"Blocked pattern detected: '{blocked}'"
    return True, ""


# Custom Jinja2 environment with selected globals exposed
def create_jinja_env():
    env = Environment(loader=BaseLoader())
    # Expose Flask/Jinja2 globals that are useful for SSTI
    # These are standard Jinja2 globals available in Flask templates
    env.globals.update({
        "request": None,  # will be set per-request
        "config": None,
        "cycler": __import__("jinja2").utils.Markupify,  # placeholder
    })
    return env


# Use Flask's built-in render environment (which includes cycler, namespace, lipsum, etc.)
# These standard Jinja2 globals are the bypass vector
USERS = {
    "analyst": "R3port@2024!",
    "manager": "Manag3r!Pass",
    "admin": "Adm1n#Secure",
}

SAVED_TEMPLATES: list[dict] = [
    {
        "id": 1,
        "name": "Reporte Mensual",
        "content": "# Reporte de {{ month }}\n\nTotal ventas: {{ sales }}",
        "author": "analyst",
    },
    {
        "id": 2,
        "name": "Resumen Ejecutivo",
        "content": "Estimado {{ name }},\n\nAdjunto encontrará el resumen del período.",
        "author": "manager",
    },
]


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


@app.route("/")
def index():
    return render_template("index.html",
                           logged_in="username" in session,
                           username=session.get("username"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if USERS.get(username) == password:
            session["username"] = username
            return redirect(url_for("render_page"))
        error = "Credenciales inválidas."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/render", methods=["GET", "POST"])
def render_page():
    output = None
    error = None
    template_src = ""
    sandbox_blocked = False

    if request.method == "POST":
        template_src = request.form.get("template", "")

        # Apply sandbox check
        is_safe, reason = sandbox_check(template_src)
        if not is_safe:
            sandbox_blocked = True
            error = f"[Sandbox] {reason}"
        else:
            try:
                # Render using Flask's Jinja2 environment
                # This gives access to: cycler, namespace, lipsum, joiner, dict, range, etc.
                # The 'request' object is also available.
                tmpl = app.jinja_env.from_string(template_src)
                output = tmpl.render(
                    request=request,
                    config=app.config,
                    flag_hint="La flag está en /flag.txt",
                    report_title="Informe Personalizado",
                    company="ERP Corporativo",
                    year=2024,
                )
            except TemplateSyntaxError as e:
                error = f"Error de sintaxis Jinja2: {e}"
            except Exception as e:
                error = f"Error al renderizar: {e}"

    return render_template("render.html",
                           output=output,
                           error=error,
                           template_src=template_src,
                           sandbox_blocked=sandbox_blocked,
                           logged_in="username" in session,
                           username=session.get("username"))


@app.route("/templates")
@login_required
def templates_list():
    user_templates = [t for t in SAVED_TEMPLATES if t["author"] == session.get("username")]
    all_templates = SAVED_TEMPLATES
    return render_template("templates_list.html",
                           templates=all_templates,
                           username=session.get("username"))


@app.route("/templates/save", methods=["POST"])
@login_required
def save_template():
    name = request.form.get("name", "").strip()
    content = request.form.get("content", "").strip()
    if not name or not content:
        return jsonify({"error": "name and content required"}), 400
    new_id = max(t["id"] for t in SAVED_TEMPLATES) + 1
    SAVED_TEMPLATES.append({
        "id": new_id,
        "name": name,
        "content": content,
        "author": session["username"],
    })
    return jsonify({"status": "saved", "id": new_id})


@app.route("/api/sandbox-info")
def sandbox_info():
    return jsonify({
        "sandbox": "BasicSandbox v2.1",
        "engine": "Jinja2 3.1.3",
        "blocked_patterns": BLOCKED_STRINGS,
        "note": "El sandbox inspecciona el texto de la plantilla antes del renderizado.",
        "jinja2_globals": [
            "cycler", "namespace", "lipsum", "joiner", "dict", "range",
            "request", "config", "g", "session"
        ],
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
