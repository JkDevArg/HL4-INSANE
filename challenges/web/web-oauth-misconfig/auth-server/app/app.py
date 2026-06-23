import os
import time
import secrets
import hashlib
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response
import requests as http_requests

app = Flask(__name__)
app.secret_key = os.urandom(32)

FLAG = os.environ.get("FLAG", "HL4{EJEMPLO_LOCAL}")
RESOURCE_URL = os.environ.get("RESOURCE_SERVER_URL", "http://resource-server:9000")

# ---------------------------------------------------------------------------
# Registered OAuth2 clients
# The admin client secret is visible in HTML source as a "debug comment"
# ---------------------------------------------------------------------------
CLIENTS = {
    "client_reader": {
        "client_secret": "reader_secret_xyz",
        "redirect_uris": ["http://localhost:3000/callback", "http://localhost:3000"],
        "allowed_scopes": ["read", "profile"],
        "name": "Reader App",
        "description": "Aplicación de solo lectura para reportes.",
        "public": True,
    },
    "client_admin": {
        "client_secret": "admin_secret_abc",
        "redirect_uris": ["http://internal-app.corp/callback"],
        "allowed_scopes": ["read", "admin", "write"],
        "name": "Admin Panel",
        "description": "Panel de administración interno.",
        "public": False,
    },
}

USERS = {
    "alice": {"password": "alice123", "email": "alice@corp.local", "name": "Alice"},
    "admin": {"password": "adminpass", "email": "admin@corp.local", "name": "Administrator"},
    "bob":   {"password": "bob456",   "email": "bob@corp.local",   "name": "Bob"},
}

# auth_code -> {client_id, user, scope, redirect_uri, expires}
AUTH_CODES: dict[str, dict] = {}

# access_token -> {client_id, user, scope, issued_at, expires}
ACCESS_TOKENS: dict[str, dict] = {}


def generate_token(prefix="tok"):
    return f"{prefix}_{secrets.token_hex(24)}"


# ---------------------------------------------------------------------------
# OAuth2 endpoints
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/authorize", methods=["GET", "POST"])
def authorize():
    client_id = request.args.get("client_id") or request.form.get("client_id")
    redirect_uri = request.args.get("redirect_uri") or request.form.get("redirect_uri", "")
    response_type = request.args.get("response_type") or request.form.get("response_type", "code")
    scope = request.args.get("scope") or request.form.get("scope", "read")
    state = request.args.get("state") or request.form.get("state", "")

    # Validate client
    client = CLIENTS.get(client_id)
    if not client:
        return jsonify({"error": "invalid_client", "error_description": "Unknown client_id"}), 400

    # VULNERABILITY: redirect_uri validation for client_reader is NOT enforced
    # For client_admin, we do a strict check, but for client_reader it's skipped
    # to allow "flexibility for development". This comment remains as a TODO.
    if client_id == "client_admin":
        if redirect_uri not in client["redirect_uris"]:
            return jsonify({"error": "invalid_redirect_uri",
                            "error_description": "Redirect URI not registered for this client"}), 400
    # For client_reader: redirect_uri is accepted as-is (no validation) — intentional vuln

    # Validate scope
    requested_scopes = scope.split()
    allowed = all(s in client["allowed_scopes"] for s in requested_scopes)
    if not allowed:
        requested_scopes = [s for s in requested_scopes if s in client["allowed_scopes"]]
        if not requested_scopes:
            requested_scopes = ["read"]

    if request.method == "GET":
        return render_template("authorize.html",
                               client=client,
                               client_id=client_id,
                               redirect_uri=redirect_uri,
                               scope=" ".join(requested_scopes),
                               state=state,
                               response_type=response_type)

    # POST: user approved
    action = request.form.get("action")
    if action == "deny":
        if redirect_uri:
            return redirect(f"{redirect_uri}?error=access_denied&state={state}")
        return jsonify({"error": "access_denied"}), 400

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    user = USERS.get(username)
    if not user or user["password"] != password:
        return render_template("authorize.html",
                               client=client,
                               client_id=client_id,
                               redirect_uri=redirect_uri,
                               scope=" ".join(requested_scopes),
                               state=state,
                               response_type=response_type,
                               error="Credenciales inválidas.")

    # Issue auth code
    code = generate_token("code")
    AUTH_CODES[code] = {
        "client_id": client_id,
        "user": username,
        "scope": " ".join(requested_scopes),
        "redirect_uri": redirect_uri,
        "expires": time.time() + 300,
    }

    if redirect_uri:
        separator = "&" if "?" in redirect_uri else "?"
        return redirect(f"{redirect_uri}{separator}code={code}&state={state}")
    return jsonify({"code": code, "state": state})


@app.route("/token", methods=["POST"])
def token():
    grant_type = request.form.get("grant_type", "authorization_code")
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")

    client = CLIENTS.get(client_id)
    if not client:
        return jsonify({"error": "invalid_client"}), 401
    if client["client_secret"] != client_secret:
        return jsonify({"error": "invalid_client", "error_description": "Bad client credentials"}), 401

    if grant_type == "authorization_code":
        code = request.form.get("code")
        code_data = AUTH_CODES.pop(code, None)
        if not code_data:
            return jsonify({"error": "invalid_grant", "error_description": "Code not found or expired"}), 400
        if code_data["expires"] < time.time():
            return jsonify({"error": "invalid_grant", "error_description": "Code expired"}), 400
        if code_data["client_id"] != client_id:
            return jsonify({"error": "invalid_grant", "error_description": "Code was issued to different client"}), 400

        token_val = generate_token("access")
        ACCESS_TOKENS[token_val] = {
            "client_id": client_id,
            "user": code_data["user"],
            "scope": code_data["scope"],
            "issued_at": time.time(),
            "expires": time.time() + 3600,
        }
        return jsonify({
            "access_token": token_val,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": code_data["scope"],
        })

    elif grant_type == "client_credentials":
        # Client credentials flow: grant scopes from client's allowed list
        requested_scope = request.form.get("scope", "")
        requested_scopes = requested_scope.split() if requested_scope else client["allowed_scopes"]
        granted_scopes = [s for s in requested_scopes if s in client["allowed_scopes"]]
        if not granted_scopes:
            return jsonify({"error": "invalid_scope"}), 400

        token_val = generate_token("cc")
        ACCESS_TOKENS[token_val] = {
            "client_id": client_id,
            "user": None,
            "scope": " ".join(granted_scopes),
            "issued_at": time.time(),
            "expires": time.time() + 3600,
        }
        return jsonify({
            "access_token": token_val,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": " ".join(granted_scopes),
        })

    return jsonify({"error": "unsupported_grant_type"}), 400


@app.route("/token/introspect", methods=["POST"])
def introspect():
    token_val = request.form.get("token")
    data = ACCESS_TOKENS.get(token_val)
    if not data or data["expires"] < time.time():
        return jsonify({"active": False})
    return jsonify({
        "active": True,
        "client_id": data["client_id"],
        "username": data["user"],
        "scope": data["scope"],
        "exp": int(data["expires"]),
        "iat": int(data["issued_at"]),
    })


@app.route("/clients")
def clients_public():
    """Public endpoint listing registered clients (public info only)."""
    public_clients = []
    for cid, c in CLIENTS.items():
        public_clients.append({
            "client_id": cid,
            "name": c["name"],
            "description": c["description"],
            "scopes": c["allowed_scopes"],
            "public": c["public"],
        })
    return jsonify({"clients": public_clients})


@app.route("/admin/resource")
def admin_resource_proxy():
    """
    Internal proxy to resource-server for testing.
    Proxies the request with the provided token to the resource server.
    """
    token_val = request.args.get("token")
    path = request.args.get("path", "/api/data")
    if not token_val:
        return jsonify({"error": "token required"}), 400
    try:
        resp = http_requests.get(
            f"{RESOURCE_URL}{path}",
            headers={"Authorization": f"Bearer {token_val}"},
            timeout=5
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
