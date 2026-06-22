"""MetricStream Infrastructure API — api-metricstream (header injection auth bypass).

Cadena de vulnerabilidades:

  1) DEBUG ENDPOINT con IP spoofing via X-Forwarded-For:
     GET /api/v1/openapi.json con X-Forwarded-For: 127.0.0.1 y X-Debug: 1
     El servidor confía en X-Forwarded-For para determinar si el cliente es
     "local". Si cree que es 127.0.0.1, devuelve el spec OpenAPI COMPLETO,
     incluyendo el endpoint interno /api/v1/internal/flag.

  2) BYPASS DE AUTH con X-Internal-Service header:
     El middleware de autenticación tiene un bug de orden de verificación:
     si X-Internal-Service: true está presente, salta la validación JWT.
     Se asume que Nginx elimina esta cabecera antes de llegar a Flask,
     pero no hay Nginx — el tráfico llega directamente al contenedor.

Flujo de explotación:
  1. GET /api/v1/openapi.json (sin headers especiales) → spec básico, sin internos
  2. GET /api/v1/openapi.json + X-Forwarded-For: 127.0.0.1 + X-Debug: 1 → spec completo
  3. Descubrir /api/v1/internal/flag en el spec completo
  4. GET /api/v1/internal/flag + X-Internal-Service: true → FLAG
"""
import os
import time
import secrets

import jwt
from flask import Flask, jsonify, request

from siem import emit
from reqlog import reqlog_http

app = Flask(__name__)

FLAG = os.environ.get("FLAG", "flag{EJEMPLO_LOCAL}")
JWT_SECRET = secrets.token_hex(32)  # Secreto HS256 por instancia

# ---------------------------------------------------------------------------
# Helpers JWT
# ---------------------------------------------------------------------------
USERS = {
    "monitor": {"password": "m0nitor2024!", "role": "viewer"},
    "ops": {"password": "0ps3cur3#Pass", "role": "operator"},
}


def _make_jwt(username: str, role: str) -> str:
    payload = {
        "sub": username,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def _verify_jwt(token: str) -> dict | None:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return None


def _get_client_ip() -> str:
    """IP del cliente — lee X-Forwarded-For tal cual (sin validar). VULN #1."""
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        # Toma la primera IP de la lista (supuestamente el cliente real)
        return xff.split(",")[0].strip()
    return request.remote_addr or "?"


def _is_debug_trusted() -> bool:
    """Comprueba si el cliente es 'local' para habilitar debug.

    VULN: usa X-Forwarded-For para determinar la IP, que el cliente puede
    falsificar. Si parece 127.0.0.1 y envía X-Debug: 1, tiene acceso debug.
    """
    client_ip = _get_client_ip()
    debug_header = request.headers.get("X-Debug", "")
    return client_ip == "127.0.0.1" and debug_header == "1"


def _auth_required(f):
    """Decorador de autenticación con bug de orden de verificación.

    VULN #2: si X-Internal-Service: true está presente, salta la validación JWT.
    En producción real, Nginx debería eliminar esta cabecera. Aquí no hay Nginx.
    """
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        # VULN: comprobación de servicio interno PRIMERO, sin verificar JWT
        if request.headers.get("X-Internal-Service") == "true":
            # Se asume que viene de un servicio interno de confianza
            return f(*args, **kwargs)

        # Verificación JWT normal
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "unauthorized", "message": "Bearer token required"}), 401

        payload = _verify_jwt(auth[7:])
        if not payload:
            return jsonify({"error": "invalid_token"}), 401

        request.jwt_payload = payload
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Request logging
# ---------------------------------------------------------------------------
@app.before_request
def _log_request():
    try:
        src_ip = _get_client_ip()
        body = request.get_data(cache=True, as_text=True)
        reqlog_http(
            src_ip=src_ip, method=request.method, path=request.path,
            query=request.query_string.decode("utf-8", "replace"),
            headers=dict(request.headers), body=body,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Endpoints públicos
# ---------------------------------------------------------------------------
@app.get("/")
def index():
    return jsonify({
        "api": "MetricStream Infrastructure API",
        "version": "4.2.0",
        "docs": "GET /api/v1/openapi.json",
        "auth": "POST /auth/login",
        "note": "Infrastructure monitoring and metrics collection platform.",
    })


@app.get("/health")
def health():
    return jsonify({"status": "ok", "metrics_collected": 482910})


@app.post("/auth/login")
def auth_login():
    src_ip = _get_client_ip()
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    user = USERS.get(username)
    if not user or user["password"] != password:
        emit("auth_failed", "warn", src_ip=src_ip, detail={"username": username})
        return jsonify({"error": "invalid_credentials"}), 401

    token = _make_jwt(username, user["role"])
    emit("auth_success", "info", src_ip=src_ip, detail={"username": username})
    return jsonify({"access_token": token, "token_type": "Bearer", "expires_in": 3600})


@app.get("/api/v1/openapi.json")
def openapi_spec():
    """Devuelve la especificación OpenAPI.

    VULN #1: Si el cliente parece ser 127.0.0.1 (vía X-Forwarded-For) y envía
    X-Debug: 1, devuelve el spec COMPLETO incluyendo endpoints internos.
    Sin esos headers, devuelve solo los endpoints públicos.
    """
    src_ip = _get_client_ip()
    is_debug = _is_debug_trusted()

    if is_debug:
        emit("debug_spec_accessed", "warn", src_ip=src_ip,
             detail={"xff": request.headers.get("X-Forwarded-For"), "x_debug": "1"})

    base_paths = {
        "/health": {"get": {"summary": "Health check", "tags": ["system"]}},
        "/auth/login": {
            "post": {
                "summary": "Authenticate and get JWT token",
                "tags": ["auth"],
                "requestBody": {
                    "content": {"application/json": {"schema": {
                        "type": "object",
                        "properties": {
                            "username": {"type": "string"},
                            "password": {"type": "string"},
                        },
                    }}},
                },
            }
        },
        "/api/v1/metrics/stream": {
            "get": {"summary": "Stream live metrics", "tags": ["metrics"], "security": [{"bearerAuth": []}]}
        },
        "/api/v1/metrics/collect": {
            "post": {"summary": "Submit metric datapoint", "tags": ["metrics"], "security": [{"bearerAuth": []}]}
        },
        "/api/v1/admin/config": {
            "get": {"summary": "Get admin configuration", "tags": ["admin"], "security": [{"bearerAuth": []}]}
        },
    }

    # Endpoints internos — solo visibles en modo debug (127.0.0.1 + X-Debug: 1)
    internal_paths = {
        "/api/v1/internal/flag": {
            "get": {
                "summary": "Internal flag retrieval endpoint",
                "description": "Internal service endpoint. Requires X-Internal-Service: true header. NOT for external access.",
                "tags": ["internal"],
                "security": [{"internalService": []}],
                "responses": {
                    "200": {"description": "Flag value for internal service verification"},
                    "403": {"description": "Forbidden — internal access only"},
                },
            }
        },
        "/api/v1/internal/health-deep": {
            "get": {
                "summary": "Deep health check (internal only)",
                "tags": ["internal"],
                "security": [{"internalService": []}],
            }
        },
    }

    paths = {**base_paths, **(internal_paths if is_debug else {})}

    return jsonify({
        "openapi": "3.0.3",
        "info": {"title": "MetricStream API", "version": "4.2.0"},
        "debug_mode": is_debug,
        "security_note": "Internal endpoints require X-Internal-Service header (stripped by Nginx in production)",
        "paths": paths,
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
                "internalService": {"type": "apiKey", "in": "header", "name": "X-Internal-Service"},
            }
        },
    })


# ---------------------------------------------------------------------------
# Endpoints autenticados (normales)
# ---------------------------------------------------------------------------
@app.get("/api/v1/metrics/stream")
@_auth_required
def metrics_stream():
    return jsonify({
        "stream": "live",
        "metrics": [
            {"host": "web-01", "cpu": 23.4, "mem": 67.2, "ts": int(time.time())},
            {"host": "web-02", "cpu": 45.1, "mem": 71.8, "ts": int(time.time())},
            {"host": "db-01", "cpu": 12.0, "mem": 89.3, "ts": int(time.time())},
        ],
    })


@app.post("/api/v1/metrics/collect")
@_auth_required
def metrics_collect():
    data = request.get_json(silent=True) or {}
    return jsonify({"status": "accepted", "metric_id": secrets.token_hex(8), "received": data})


@app.get("/api/v1/admin/config")
@_auth_required
def admin_config():
    role = getattr(request, "jwt_payload", {}).get("role", "unknown")
    if role not in ("operator", "admin"):
        return jsonify({"error": "forbidden"}), 403
    return jsonify({
        "retention_days": 90,
        "alert_thresholds": {"cpu": 85, "mem": 90, "disk": 95},
        "collectors": ["prometheus", "statsd", "telegraf"],
    })


# ---------------------------------------------------------------------------
# Endpoints internos (deberían ser inaccesibles desde exterior)
# ---------------------------------------------------------------------------
@app.get("/api/v1/internal/flag")
@_auth_required
def internal_flag():
    """Endpoint interno para verificación de flags entre servicios.

    DISEÑO INCORRECTO: el auth_required decorator permite bypasear con
    X-Internal-Service: true. En producción debería estar detrás de Nginx
    que elimine esa cabecera del tráfico externo.
    """
    src_ip = _get_client_ip()
    is_internal = request.headers.get("X-Internal-Service") == "true"

    emit("internal_flag_accessed", "alert", src_ip=src_ip,
         detail={"x_internal_service": is_internal, "vuln": "header-bypass"})

    return jsonify({
        "service": "metricstream",
        "flag": FLAG,
        "internal_verification_token": FLAG,
        "note": "This endpoint is for internal service health verification only.",
    })


@app.get("/api/v1/internal/health-deep")
@_auth_required
def internal_health_deep():
    return jsonify({
        "status": "ok",
        "db_connections": 12,
        "queue_depth": 0,
        "internal": True,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003, debug=False)
