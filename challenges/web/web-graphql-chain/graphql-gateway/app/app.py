import os
import time
import json
import requests
from ariadne import QueryType, MutationType, make_executable_schema, graphql_sync
from ariadne.wsgi import GraphQL
from flask import Flask, request, jsonify, Response

app = Flask(__name__)

USERS_URL = os.environ.get("USERS_SUBGRAPH_URL", "http://users-subgraph:4001")
SECRETS_URL = os.environ.get("SECRETS_SUBGRAPH_URL", "http://secrets-subgraph:4002")

# ---------------------------------------------------------------------------
# Rate limiting: 5 requests per minute per IP
# BYPASS: batch queries (array) count as a single request
# ---------------------------------------------------------------------------
RATE_LIMIT = 5
RATE_WINDOW = 60
rate_store: dict[str, list[float]] = {}


def check_rate_limit(ip: str) -> bool:
    """Returns True if request is allowed, False if rate limited."""
    now = time.time()
    timestamps = rate_store.get(ip, [])
    # Clean expired
    timestamps = [t for t in timestamps if now - t < RATE_WINDOW]
    if len(timestamps) >= RATE_LIMIT:
        rate_store[ip] = timestamps
        return False
    timestamps.append(now)
    rate_store[ip] = timestamps
    return True


def proxy_to_subgraph(url: str, payload: dict, token: str = None) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        resp = requests.post(f"{url}/graphql", json=payload, headers=headers, timeout=10)
        return resp.json()
    except Exception as e:
        return {"errors": [{"message": str(e)}]}


# ---------------------------------------------------------------------------
# Unified GraphQL schema (gateway)
# ---------------------------------------------------------------------------
type_defs = """
    type Query {
        me: User
        users: [User!]!
        secrets: [Secret!]!
        secretById(id: ID!): Secret
        ping: String!
    }

    type Mutation {
        login(username: String!, password: String!): AuthPayload!
        register(username: String!, email: String!, password: String!): AuthPayload!
        updateUser(id: ID!, input: UserInput!): User!
    }

    type AuthPayload {
        token: String!
        user: User!
    }

    input UserInput {
        email: String
        username: String
        role: String
        password: String
    }

    type User {
        id: ID!
        username: String!
        email: String!
        role: String!
        internalToken: String
    }

    type Secret {
        id: ID!
        name: String!
        value: String!
    }
"""

query = QueryType()
mutation = MutationType()


def get_bearer_token():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None


@query.field("ping")
def resolve_ping(_, info):
    return "pong"


@query.field("me")
def resolve_me(_, info):
    token = get_bearer_token()
    if not token:
        raise Exception("Authentication required")
    result = proxy_to_subgraph(
        USERS_URL,
        {"query": f'query {{ me(token: "{token}") {{ id username email role internalToken }} }}'}
    )
    data = result.get("data", {})
    if data and data.get("me"):
        return data["me"]
    raise Exception("Invalid token or user not found")


@query.field("users")
def resolve_users(_, info):
    result = proxy_to_subgraph(
        USERS_URL,
        {"query": "query { users { id username email role } }"}
    )
    data = result.get("data", {})
    return data.get("users", [])


@query.field("secrets")
def resolve_secrets(_, info):
    token = get_bearer_token()
    if not token:
        raise Exception("Authentication required")

    # First verify user is admin via users-subgraph
    user_result = proxy_to_subgraph(
        USERS_URL,
        {"query": f'query {{ me(token: "{token}") {{ id role internalToken }} }}'}
    )
    user_data = user_result.get("data", {}).get("me")
    if not user_data:
        raise Exception("Authentication failed")
    if user_data.get("role") != "admin":
        raise Exception("Access denied: admin role required")

    # Forward to secrets subgraph with the token
    result = proxy_to_subgraph(
        SECRETS_URL,
        {"query": f'query {{ secrets(auth_token: "{token}") {{ id name value }} }}'}
    )
    data = result.get("data", {})
    if "errors" in result and not data.get("secrets"):
        errors = result["errors"]
        raise Exception(errors[0]["message"] if errors else "Secrets subgraph error")
    return data.get("secrets", [])


@query.field("secretById")
def resolve_secret_by_id(_, info, id):
    token = get_bearer_token()
    if not token:
        raise Exception("Authentication required")

    user_result = proxy_to_subgraph(
        USERS_URL,
        {"query": f'query {{ me(token: "{token}") {{ id role }} }}'}
    )
    user_data = user_result.get("data", {}).get("me")
    if not user_data or user_data.get("role") != "admin":
        raise Exception("Access denied: admin role required")

    result = proxy_to_subgraph(
        SECRETS_URL,
        {"query": f'query {{ secretById(id: "{id}", auth_token: "{token}") {{ id name value }} }}'}
    )
    data = result.get("data", {})
    return data.get("secretById")


@mutation.field("login")
def resolve_login(_, info, username, password):
    result = proxy_to_subgraph(
        USERS_URL,
        {
            "query": """
                mutation Login($u: String!, $p: String!) {
                    login(username: $u, password: $p) {
                        token
                        user { id username email role internalToken }
                    }
                }
            """,
            "variables": {"u": username, "p": password}
        }
    )
    if "errors" in result:
        raise Exception(result["errors"][0]["message"])
    data = result.get("data", {}).get("login")
    if not data:
        raise Exception("Login failed")
    return data


@mutation.field("register")
def resolve_register(_, info, username, email, password):
    result = proxy_to_subgraph(
        USERS_URL,
        {
            "query": """
                mutation Reg($u: String!, $e: String!, $p: String!) {
                    register(username: $u, email: $e, password: $p) {
                        token
                        user { id username email role }
                    }
                }
            """,
            "variables": {"u": username, "e": email, "p": password}
        }
    )
    if "errors" in result:
        raise Exception(result["errors"][0]["message"])
    data = result.get("data", {}).get("register")
    if not data:
        raise Exception("Registration failed")
    return data


@mutation.field("updateUser")
def resolve_update_user(_, info, id, input):
    """
    Proxies updateUser to users-subgraph.
    Mass assignment vulnerability: the 'role' field in UserInput is accepted
    and applied without authorization checks.
    """
    # Build input fields string for GraphQL query
    input_fields = []
    if input.get("email"):
        input_fields.append(f'email: "{input["email"]}"')
    if input.get("username"):
        input_fields.append(f'username: "{input["username"]}"')
    if input.get("role"):
        input_fields.append(f'role: "{input["role"]}"')
    if input.get("password"):
        input_fields.append(f'password: "{input["password"]}"')

    input_str = ", ".join(input_fields)
    result = proxy_to_subgraph(
        USERS_URL,
        {
            "query": f"""
                mutation {{
                    updateUser(id: "{id}", input: {{ {input_str} }}) {{
                        id username email role internalToken
                    }}
                }}
            """
        }
    )
    if "errors" in result:
        raise Exception(result["errors"][0]["message"])
    data = result.get("data", {}).get("updateUser")
    if not data:
        raise Exception("Update failed")
    return data


schema = make_executable_schema(type_defs, query, mutation)
graphql_app = GraphQL(schema, debug=True)


@app.route("/graphql", methods=["GET", "POST"])
def graphql_endpoint():
    ip = request.remote_addr

    # Batch queries: if body is a JSON array, process as batch
    # RATE LIMIT BYPASS: the entire batch counts as ONE request
    if request.method == "POST" and request.is_json:
        body = request.get_json(silent=True)
        if isinstance(body, list):
            # Batch mode - count as single request (RATE LIMIT BYPASS)
            if not check_rate_limit(ip):
                return jsonify({"errors": [{"message": "Rate limit exceeded. Try again later."}]}), 429

            results = []
            for operation in body:
                query_str = operation.get("query", "")
                variables = operation.get("variables")
                op_name = operation.get("operationName")
                success, result = graphql_sync(
                    schema,
                    query_str,
                    variable_values=variables,
                    operation_name=op_name,
                    context_value={"request": request},
                )
                results.append(result)
            return jsonify(results)

    # Single request - apply rate limiting
    if not check_rate_limit(ip):
        return jsonify({"errors": [{"message": "Rate limit exceeded (5 req/min). Use batch queries to bypass."}]}), 429

    return graphql_app(request.environ, lambda s, h: None)


@app.route("/")
def index():
    return """<!DOCTYPE html>
<html><head><title>GraphQL API Gateway</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head><body class="bg-dark text-light p-4">
<div class="container">
  <h2 class="mb-3"><i>&#9881;</i> GraphQL Federation Gateway</h2>
  <p class="text-muted">API Gateway unificando microservicios via GraphQL Federation.</p>
  <div class="card bg-secondary mb-3">
    <div class="card-body">
      <h5>Endpoints</h5>
      <ul>
        <li><code>POST /graphql</code> — GraphQL API (introspection habilitada)</li>
        <li><code>GET /graphql</code> — GraphiQL Playground</li>
      </ul>
      <h5 class="mt-3">Rate Limiting</h5>
      <p>5 peticiones/minuto por IP. Las batch queries cuentan como 1 peticion.</p>
      <h5 class="mt-3">Autenticacion</h5>
      <p>Use <code>Authorization: Bearer &lt;token&gt;</code></p>
    </div>
  </div>
  <a href="/graphql" class="btn btn-success">Abrir GraphiQL Playground</a>
</div>
</body></html>"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
