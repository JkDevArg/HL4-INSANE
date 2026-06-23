#!/usr/bin/env python3
"""
Corp profile webapp.
The /profile/info endpoint returns sensitive data (flag for admin).
Flask serves ANY path that matches its routes — so /profile/info.css
returns exactly the same response as /profile/info.
Nginx sees the .css extension and caches it for ALL subsequent requestors.
Attack:
  1. Admin bot visits /profile/info.css (authenticated, gets flag JSON)
  2. Nginx caches the response (keyed by URI, ignoring Set-Cookie)
  3. Attacker visits /profile/info.css unauthenticated — gets cached admin response
"""
import os
from flask import Flask, request, session, redirect, render_template_string, jsonify, make_response

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "cache-deception-secret-local")
FLAG = os.environ.get("FLAG", "HL4{EJEMPLO_LOCAL}")

USERS = {
    "admin":  {"password": "adminpass123", "flag": FLAG},
    "user1":  {"password": "user1pass",    "flag": None},
    "user2":  {"password": "user2pass",    "flag": None},
}

HTML_LOGIN = """<!DOCTYPE html>
<html>
<head>
  <title>Corp Portal — Login</title>
  <style>
    body { font-family: -apple-system, sans-serif; background: #eef2f7; display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }
    .box { background:white; padding:2rem 2.5rem; border-radius:8px; box-shadow:0 2px 12px rgba(0,0,0,0.1); min-width:300px; }
    h2 { text-align:center; color:#2c3e50; }
    input { width:100%; padding:0.55rem; margin:0.3rem 0 1rem 0; border:1px solid #ccc; border-radius:4px; box-sizing:border-box; }
    button { width:100%; padding:0.65rem; background:#2980b9; color:white; border:none; border-radius:4px; cursor:pointer; font-size:1rem; }
    button:hover { background:#2471a3; }
    .err { color:red; text-align:center; }
    .hint { font-size:0.8rem; color:#888; text-align:center; margin-top:1rem; }
  </style>
</head>
<body>
<div class="box">
  <h2>Corp Portal</h2>
  {% if error %}<p class="err">{{ error }}</p>{% endif %}
  <form method="POST">
    <label>Username</label>
    <input name="username" placeholder="user1" required>
    <label>Password</label>
    <input type="password" name="password" required>
    <button type="submit">Login</button>
  </form>
  <p class="hint">Demo accounts: user1/user1pass, user2/user2pass</p>
</div>
</body>
</html>"""

HTML_PROFILE = """<!DOCTYPE html>
<html>
<head>
  <title>Corp Portal — Profile</title>
  <style>
    body { font-family:-apple-system,sans-serif; background:#eef2f7; margin:0; }
    nav { background:#2c3e50; color:white; padding:0.8rem 2rem; display:flex; justify-content:space-between; }
    nav a { color:#85c1e9; text-decoration:none; }
    .content { max-width:700px; margin:2rem auto; }
    .card { background:white; padding:1.5rem; border-radius:6px; box-shadow:0 1px 4px rgba(0,0,0,0.1); margin-bottom:1rem; }
    h2 { color:#2c3e50; }
    code { background:#f0f0f0; padding:2px 6px; border-radius:3px; }
    .btn { display:inline-block; padding:0.4rem 1rem; background:#2980b9; color:white; border-radius:4px; text-decoration:none; }
  </style>
</head>
<body>
<nav><span><strong>Corp Portal</strong></span><span>{{ username }} <a href="/logout">Logout</a></span></nav>
<div class="content">
  <div class="card">
    <h2>Profile</h2>
    <p>Username: <code>{{ username }}</code></p>
    <p>Role: <code>{{ role }}</code></p>
    <p><a href="/profile/info" class="btn">View Profile API</a></p>
  </div>
  <div class="card">
    <h3>Quick Links</h3>
    <p>
      <a href="/profile/info">Profile Info (JSON)</a> |
      <a href="/profile/info.css">Profile Info CSS</a>
    </p>
    <p style="font-size:0.85rem;color:#888">
      Note: Static assets are served through our CDN cache for performance.
    </p>
  </div>
</div>
</body>
</html>"""


@app.route("/")
def index():
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = USERS.get(username)
        if user and user["password"] == password:
            session.clear()
            session["username"] = username
            session["role"] = "admin" if username == "admin" else "user"
            return redirect("/profile")
        return render_template_string(HTML_LOGIN, error="Invalid credentials")
    return render_template_string(HTML_LOGIN, error=None)


@app.route("/profile")
def profile():
    if not session.get("username"):
        return redirect("/login")
    return render_template_string(
        HTML_PROFILE,
        username=session["username"],
        role=session.get("role", "user")
    )


def _profile_info_response():
    """Core profile info logic — same for /profile/info and /profile/info.css"""
    username = session.get("username")
    if not username:
        return jsonify({"error": "Not authenticated", "redirect": "/login"}), 401

    user = USERS.get(username, {})
    data = {
        "username": username,
        "role": session.get("role", "user"),
        "email": f"{username}@corp.internal",
    }
    if username == "admin":
        data["flag"] = FLAG
        data["admin_token"] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.admin"
        data["db_password"] = "Pr0d_DB_sup3rs3cr3t"

    resp = make_response(jsonify(data))
    resp.headers["Content-Type"] = "application/json"
    # No Cache-Control headers set — nginx decides to cache based on extension
    return resp


@app.route("/profile/info")
def profile_info():
    return _profile_info_response()


@app.route("/profile/info.css")
def profile_info_css():
    """
    VULNERABILITY: Flask serves this route identically to /profile/info.
    When the admin bot visits this URL (authenticated), nginx caches the
    response (keyed by URI, not by session). An unauthenticated attacker
    then fetches /profile/info.css and gets the cached admin response.
    """
    return _profile_info_response()


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    print("[*] Corp webapp starting on :5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
