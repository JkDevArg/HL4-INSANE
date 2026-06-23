import os
import re
import sqlite3
import json
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, g, send_from_directory, abort
)

app = Flask(__name__)
app.secret_key = os.urandom(32)

DB_PATH = "/app/data/erp.db"
FLAG = os.environ.get("FLAG", "HL4{EJEMPLO_LOCAL}")

# ---------------------------------------------------------------------------
# WAF - Bloquea patrones SQL comunes en query params y form data (POST body)
# NO inspecciona: JSON body, headers, cookies
# ---------------------------------------------------------------------------

WAF_PATTERNS = [
    r'\bUNION\b',
    r'\bSELECT\b',
    r'--',
    r'\bOR\b',
    r'\bAND\b',
    r'\bSLEEP\b',
    r'\bBENCHMARK\b',
    r'\bWAITFOR\b',
    r'\bDROP\b',
    r'\bINSERT\b',
    r'\bDELETE\b',
    r'\bUPDATE\b',
]

WAF_REGEX = re.compile(
    '|'.join(WAF_PATTERNS),
    re.IGNORECASE
)


def waf_check(value: str) -> bool:
    """Returns True if the value is flagged by WAF."""
    return bool(WAF_REGEX.search(value))


def waf_middleware():
    """
    Applies WAF to query string parameters and form-encoded POST data.
    JSON body is NOT inspected (WAF only understands form data).
    """
    # Check query string
    for key, value in request.args.items():
        if waf_check(value):
            return jsonify({
                "error": "WAF: Suspicious request blocked",
                "param": key,
                "waf_version": "BasicGuard v1.2"
            }), 403

    # Check form data (application/x-www-form-urlencoded and multipart)
    if request.content_type and 'application/json' not in request.content_type:
        for key, value in request.form.items():
            if waf_check(value):
                return jsonify({
                    "error": "WAF: Suspicious request blocked",
                    "param": key,
                    "waf_version": "BasicGuard v1.2"
                }), 403

    return None


@app.before_request
def before_request():
    waf_result = waf_middleware()
    if waf_result:
        return waf_result


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            return render_template("error.html", message="Acceso denegado: se requiere rol de administrador."), 403
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html", logged_in="username" in session, username=session.get("username"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # Parameterized query — safe from SQLi
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password)
        ).fetchone()
        if user:
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["user_id"] = user["id"]
            return redirect(url_for("orders"))
        error = "Credenciales inválidas."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/orders")
@login_required
def orders():
    db = get_db()

    # WAF bypass vector: the sort parameter can be supplied via JSON body
    # WAF checks query params and form data but NOT JSON body.
    # If Content-Type: application/json, Flask reads request.json instead of request.args.
    sort = None
    if request.is_json:
        sort = request.get_json(silent=True, force=True).get("sort", "id") if request.get_json(silent=True, force=True) else "id"
    else:
        sort = request.args.get("sort", "id")

    # VULNERABLE: sort is directly concatenated into SQL
    # Safe fallback columns for display purposes:
    valid_columns = ["id", "customer", "product", "quantity", "status", "total", "created_at"]

    try:
        query = f"SELECT id, customer, product, quantity, status, total, created_at FROM orders ORDER BY {sort}"
        rows = db.execute(query).fetchall()
        result = [dict(r) for r in rows]
        if request.is_json:
            return jsonify({"orders": result, "sort": sort, "count": len(result)})
        return render_template("orders.html", orders=result, sort=sort,
                               valid_columns=valid_columns,
                               username=session.get("username"),
                               role=session.get("role"))
    except Exception as e:
        error_msg = str(e)
        if request.is_json:
            return jsonify({"error": error_msg}), 500
        return render_template("orders.html", orders=[], sort=sort,
                               valid_columns=valid_columns,
                               error=error_msg,
                               username=session.get("username"),
                               role=session.get("role"))


@app.route("/inventory")
@login_required
def inventory():
    db = get_db()
    items = db.execute("SELECT * FROM inventory ORDER BY product").fetchall()
    return render_template("inventory.html", items=[dict(i) for i in items],
                           username=session.get("username"), role=session.get("role"))


@app.route("/admin")
@admin_required
def admin():
    db = get_db()
    users = db.execute("SELECT id, username, role, email FROM users ORDER BY id").fetchall()
    cfg = db.execute("SELECT * FROM config").fetchall()
    return render_template("admin.html",
                           users=[dict(u) for u in users],
                           config=[dict(c) for c in cfg],
                           username=session.get("username"),
                           role=session.get("role"))


@app.route("/admin/backup", methods=["POST"])
@admin_required
def admin_backup():
    db = get_db()
    backup_path = request.form.get("path", "/app/backups/backup.sql")

    # Write backup: dumps selected tables to a SQL file
    try:
        lines = []
        for table in ["users", "orders", "inventory", "flags", "config"]:
            rows = db.execute(f"SELECT * FROM {table}").fetchall()
            lines.append(f"-- Table: {table}")
            for row in rows:
                values = ", ".join(
                    f"'{str(v).replace(chr(39), chr(39)*2)}'" if v is not None else "NULL"
                    for v in row
                )
                lines.append(f"-- {table}: {values}")
        content = "\n".join(lines) + "\n"

        with open(backup_path, "w") as f:
            f.write(content)

        return jsonify({"status": "ok", "path": backup_path, "size": len(content)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/backup/download")
@admin_required
def backup_download():
    # PATH TRAVERSAL: filename is directly appended to /app/backups/
    filename = request.args.get("file", "backup.sql")
    # No path sanitization — allows ../uploads/whatever or ../../etc/passwd
    try:
        full_path = "/app/backups/" + filename
        with open(full_path) as f:
            content = f.read()
        from flask import Response
        return Response(content, mimetype="text/plain",
                        headers={"Content-Disposition": f"attachment; filename={os.path.basename(filename)}"})
    except Exception as e:
        return jsonify({"error": str(e)}), 404


@app.route("/api/orders")
@login_required
def api_orders():
    """
    JSON API for orders. WAF does NOT inspect JSON body.
    This endpoint reads sort from JSON body → SQLi bypass.
    """
    db = get_db()
    body = request.get_json(silent=True, force=True) or {}
    sort = body.get("sort", "id")

    try:
        query = f"SELECT id, customer, product, quantity, status, total FROM orders ORDER BY {sort}"
        rows = db.execute(query).fetchall()
        return jsonify({"orders": [dict(r) for r in rows], "sort": sort})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
