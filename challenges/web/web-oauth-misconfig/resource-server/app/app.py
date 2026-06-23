import os
import requests as http_requests
from flask import Flask, request, jsonify

app = Flask(__name__)

FLAG = os.environ.get("FLAG", "HL4{EJEMPLO_LOCAL}")
AUTH_SERVER_URL = os.environ.get("AUTH_SERVER_URL", "http://auth-server:8080")


def validate_token(token: str) -> dict | None:
    """
    Validates an access token via auth-server introspection endpoint.
    Returns token info dict if active, None otherwise.
    """
    try:
        resp = http_requests.post(
            f"{AUTH_SERVER_URL}/token/introspect",
            data={"token": token},
            timeout=5
        )
        data = resp.json()
        if data.get("active"):
            return data
        return None
    except Exception:
        return None


def require_scope(required_scope: str):
    """Check bearer token has the required scope."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None, jsonify({"error": "unauthorized", "message": "Bearer token required"}), 401

    token = auth_header[7:]
    token_info = validate_token(token)
    if not token_info:
        return None, jsonify({"error": "invalid_token", "message": "Token is invalid or expired"}), 401

    scopes = token_info.get("scope", "").split()
    if required_scope not in scopes:
        return None, jsonify({
            "error": "insufficient_scope",
            "message": f"Required scope: {required_scope}",
            "granted_scopes": scopes
        }), 403

    return token_info, None, None


@app.route("/")
def index():
    return jsonify({
        "service": "Resource Server",
        "version": "1.0",
        "endpoints": {
            "GET /api/data": "Public data (requires 'read' scope)",
            "GET /api/profile": "User profile (requires 'read' scope)",
            "GET /api/admin/users": "User list (requires 'admin' scope)",
            "GET /api/flag": "Confidential flag (requires 'admin' scope)",
        }
    })


@app.route("/api/data")
def api_data():
    token_info, error_response, status = require_scope("read")
    if error_response:
        return error_response, status

    return jsonify({
        "data": [
            {"id": 1, "type": "report", "title": "Q4 2024 Revenue Report", "status": "published"},
            {"id": 2, "type": "report", "title": "Annual Security Audit", "status": "draft"},
            {"id": 3, "type": "document", "title": "Corporate Policies v3", "status": "published"},
        ],
        "user": token_info.get("username"),
        "scope": token_info.get("scope"),
    })


@app.route("/api/profile")
def api_profile():
    token_info, error_response, status = require_scope("read")
    if error_response:
        return error_response, status

    return jsonify({
        "client_id": token_info.get("client_id"),
        "username": token_info.get("username"),
        "scope": token_info.get("scope"),
        "token_expires": token_info.get("exp"),
    })


@app.route("/api/admin/users")
def api_admin_users():
    token_info, error_response, status = require_scope("admin")
    if error_response:
        return error_response, status

    return jsonify({
        "users": [
            {"id": 1, "username": "alice", "email": "alice@corp.local", "role": "user"},
            {"id": 2, "username": "admin", "email": "admin@corp.local", "role": "admin"},
            {"id": 3, "username": "bob",   "email": "bob@corp.local",   "role": "user"},
        ]
    })


@app.route("/api/flag")
def api_flag():
    token_info, error_response, status = require_scope("admin")
    if error_response:
        return error_response, status

    return jsonify({
        "flag": FLAG,
        "message": "Acceso autorizado al recurso confidencial",
        "authorized_client": token_info.get("client_id"),
        "scope": token_info.get("scope"),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000, debug=False)
