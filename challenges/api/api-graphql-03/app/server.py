"""NebulaGraph — api-graphql-03 (API GraphQL INSANE).

Cadena de vulnerabilidades GraphQL:

  1) INTROSPECCIÓN "DESACTIVADA": una regla de validación bloquea cualquier
     campo `__schema` / `__type` (los meta-campos de introspección). No puedes
     volcar el esquema directamente.

  2) FIELD SUGGESTIONS (fuga de esquema): graphql-core, al fallar la validación
     de un campo inexistente, responde con "Did you mean 'X'?". Esos mensajes
     filtran nombres reales de campos y argumentos del esquema pese a la
     introspección bloqueada. Así descubres: el campo oculto `user`, el campo
     `secretNote(pin:)` del tipo `User`, etc.

  3) ALIAS BATCHING ABUSE: el resolver de `secretNote` aplica un "rate limit"
     ingenuo POR PETICIÓN HTTP (un contador por request). Pero GraphQL permite
     muchos campos con alias en UNA sola petición -> puedes lanzar cientos de
     intentos de `secretNote(pin: NNNN)` con alias distintos en un único POST y
     forzar el PIN de 4 dígitos del admin, evadiendo el límite por-petición.

Objetivo: leer `user(username:"admin"){ secretNote(pin: <PIN>) }`, que devuelve
la FLAG cuando el PIN es correcto.

La FLAG se inyecta por equipo vía env FLAG. NO hardcodeada. El PIN del admin es
aleatorio por instancia (no se puede adivinar leyendo el código).
"""
import os
import secrets

from flask import Flask, jsonify, request
from graphql import (
    GraphQLArgument,
    GraphQLField,
    GraphQLInt,
    GraphQLNonNull,
    GraphQLObjectType,
    GraphQLSchema,
    GraphQLString,
    parse,
    validate,
)
from graphql.execution import execute
from graphql.validation import NoSchemaIntrospectionCustomRule, specified_rules

# Reglas de validación: las ESTÁNDAR (que incluyen las "Did you mean" / field
# suggestions) MÁS la regla que bloquea la introspección. Al conservar las
# reglas estándar, las suggestions siguen filtrando nombres de campos aunque la
# introspección esté apagada (VULN #2).
VALIDATION_RULES = list(specified_rules) + [NoSchemaIntrospectionCustomRule]

from siem import emit
from reqlog import reqlog_http

app = Flask(__name__)


@app.before_request
def _log_request():
    """Loguea CADA petición entrante COMPLETA (método, ruta, query, headers,
    body) para el SIEM del stream. Captura íntegra la query GraphQL del POST."""
    try:
        src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        if src_ip and "," in src_ip:
            src_ip = src_ip.split(",")[0].strip()
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
        pass

FLAG = os.environ.get("FLAG", "flag{EJEMPLO_LOCAL}")
# PIN de 4 dígitos del admin, aleatorio por instancia/equipo.
ADMIN_PIN = os.environ.get("ADMIN_PIN") or f"{secrets.randbelow(10000):04d}"

# "Base de datos" de usuarios.
USERS = {
    "alice": {"username": "alice", "displayName": "Alice", "role": "user", "pin": "1111", "note": "mi nota privada"},
    "bob": {"username": "bob", "displayName": "Bob", "role": "user", "pin": "2222", "note": "todo: rotar credenciales"},
    "admin": {"username": "admin", "displayName": "Administrator", "role": "admin", "pin": ADMIN_PIN, "note": FLAG},
}


# --------------------------------------------------------------------------
# Resolvers
# --------------------------------------------------------------------------
def resolve_secret_note(user_obj, info, pin):
    """VULN #3 (objetivo): devuelve la nota privada del usuario si el PIN es
    correcto. Para el admin, la nota ES la flag.

    El "rate limit" se aplica POR PETICIÓN (en el contexto), no global -> alias
    batching lo evade: muchos `secretNote` aliased caben en 1 request.
    """
    ctx = info.context
    ctx["note_calls"] = ctx.get("note_calls", 0) + 1
    # Límite ingenuo por-petición: tras N intentos en ESTA request, frena. Pero
    # el atacante mete cientos de alias por request, repartiendo el bruteforce.
    if ctx["note_calls"] > 5000:
        return "rate limited"
    if str(pin) == str(user_obj["pin"]):
        return user_obj["note"]
    return None


def resolve_user(root, info, username):
    u = USERS.get(username)
    if u and username == "admin":
        emit("scan_detected", "warn", src_ip=info.context.get("src_ip"),
             detail={"event": "admin-user-queried"})
    return u


def resolve_me(root, info):
    # Usuario "actual" anónimo de demo.
    return USERS["alice"]


def resolve_server_info(root, info):
    return "NebulaGraph API v3.1 (introspection disabled in prod)"


# --------------------------------------------------------------------------
# Esquema (introspección bloqueada por regla de validación, ver abajo)
# --------------------------------------------------------------------------
UserType = GraphQLObjectType(
    "User",
    lambda: {
        "username": GraphQLField(GraphQLString),
        "displayName": GraphQLField(GraphQLString),
        "role": GraphQLField(GraphQLString),
        # Campo "oculto": solo descubrible por field suggestions. Requiere PIN.
        "secretNote": GraphQLField(
            GraphQLString,
            args={"pin": GraphQLArgument(GraphQLNonNull(GraphQLInt))},
            resolve=resolve_secret_note,
        ),
    },
)

QueryType = GraphQLObjectType(
    "Query",
    lambda: {
        "me": GraphQLField(UserType, resolve=resolve_me),
        "serverInfo": GraphQLField(GraphQLString, resolve=resolve_server_info),
        # Campo "oculto" descubrible por suggestions (p.ej. consultando `usr`).
        "user": GraphQLField(
            UserType,
            args={"username": GraphQLArgument(GraphQLNonNull(GraphQLString))},
            resolve=resolve_user,
        ),
    },
)

SCHEMA = GraphQLSchema(query=QueryType)


@app.get("/")
def index():
    return jsonify({
        "api": "NebulaGraph",
        "graphql": "POST /graphql",
        "note": "introspection disabled in production",
    })


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/graphql")
def graphql_endpoint():
    src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    data = request.get_json(silent=True) or {}
    query = data.get("query")
    variables = data.get("variables") or {}
    if not query:
        return jsonify({"errors": [{"message": "falta 'query'"}]}), 400

    try:
        document = parse(query)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"errors": [{"message": f"syntax error: {exc}"}]})

    # VULN #1: introspección bloqueada... pero las suggestions de validación
    # (VULN #2) siguen filtrando nombres de campos en los mensajes de error.
    validation_errors = validate(SCHEMA, document, VALIDATION_RULES)
    if validation_errors:
        # Telemetría: muchos errores de validación seguidos = enumeración.
        if any("Did you mean" in str(e) for e in validation_errors):
            emit("scan_detected", "info", src_ip=src_ip,
                 detail={"event": "field-suggestion-leak"})
        return jsonify({"errors": [{"message": e.message} for e in validation_errors]})

    # Detección de alias batching abuse (cientos de campos en una request).
    field_count = query.count("secretNote")
    if field_count >= 50:
        emit("scan_detected", "alert", src_ip=src_ip,
             detail={"vuln": "graphql-alias-batching", "secretNote_aliases": field_count})

    context = {"src_ip": src_ip, "note_calls": 0}
    result = execute(SCHEMA, document, context_value=context, variable_values=variables)

    out = {}
    if result.errors:
        out["errors"] = [{"message": e.message} for e in result.errors]
    if result.data is not None:
        out["data"] = result.data
    return jsonify(out)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
