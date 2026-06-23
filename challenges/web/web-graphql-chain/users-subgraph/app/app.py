import time
import secrets
from ariadne import QueryType, MutationType, make_executable_schema
from ariadne.wsgi import GraphQL
from flask import Flask, request, jsonify

app = Flask(__name__)

# ---------------------------------------------------------------------------
# In-memory user store
# ---------------------------------------------------------------------------
USERS = {
    "1": {
        "id": "1",
        "username": "alice",
        "email": "alice@corp.local",
        "password": "alice_pass_123",
        "role": "user",
        "internal_token": None,
    },
    "2": {
        "id": "2",
        "username": "bob",
        "email": "bob@corp.local",
        "password": "bob_secure_456",
        "role": "user",
        "internal_token": None,
    },
    "3": {
        "id": "3",
        "username": "admin",
        "email": "admin@corp.local",
        "password": "h4rdT0Gu3ss!Admin",
        "role": "admin",
        "internal_token": "admin-secret-jwt-token-xyz",
    },
}

# token -> user_id
TOKENS: dict[str, str] = {
    "admin-secret-jwt-token-xyz": "3",
}


def get_user_by_token(token: str):
    uid = TOKENS.get(token)
    if uid:
        return USERS.get(uid)
    return None


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
type_defs = """
    type Query {
        me(token: String!): User
        users: [User!]!
        userById(id: ID!): User
    }

    type Mutation {
        login(username: String!, password: String!): AuthPayload
        updateUser(id: ID!, input: UserInput!): User
        register(username: String!, email: String!, password: String!): AuthPayload
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
"""

query = QueryType()
mutation = MutationType()


@query.field("me")
def resolve_me(_, info, token):
    user = get_user_by_token(token)
    if not user:
        return None
    u = dict(user)
    # Only expose internalToken if admin
    if u["role"] != "admin":
        u["internal_token"] = None
    return _format_user(u)


@query.field("users")
def resolve_users(_, info):
    return [_format_user(u) for u in USERS.values()]


@query.field("userById")
def resolve_user_by_id(_, info, id):
    u = USERS.get(id)
    return _format_user(u) if u else None


@mutation.field("login")
def resolve_login(_, info, username, password):
    for uid, u in USERS.items():
        if u["username"] == username and u["password"] == password:
            token = u["internal_token"]
            if not token:
                token = f"token-{uid}-{secrets.token_hex(12)}"
                u["internal_token"] = token
                TOKENS[token] = uid
            return {"token": token, "user": _format_user(u)}
    raise Exception("Invalid credentials")


@mutation.field("register")
def resolve_register(_, info, username, email, password):
    for u in USERS.values():
        if u["username"] == username:
            raise Exception("Username already taken")
    new_id = str(max(int(k) for k in USERS) + 1)
    token = f"token-{new_id}-{secrets.token_hex(12)}"
    new_user = {
        "id": new_id,
        "username": username,
        "email": email,
        "password": password,
        "role": "user",
        "internal_token": token,
    }
    USERS[new_id] = new_user
    TOKENS[token] = new_id
    return {"token": token, "user": _format_user(new_user)}


@mutation.field("updateUser")
def resolve_update_user(_, info, id, input):
    """
    VULNERABLE: Mass Assignment
    The 'role' field is accepted in UserInput, allowing privilege escalation.
    Any authenticated user can update any other user's role to 'admin'.
    """
    user = USERS.get(id)
    if not user:
        raise Exception("User not found")

    # Apply all fields from input — including 'role' (mass assignment vuln)
    allowed_fields = {"email", "username", "role", "password"}
    for field, value in input.items():
        if field in allowed_fields and value is not None:
            user[field] = value

    # If role changed to admin, ensure internal token exists
    if user["role"] == "admin" and not user["internal_token"]:
        token = f"admin-token-{id}-{secrets.token_hex(16)}"
        user["internal_token"] = token
        TOKENS[token] = id

    return _format_user(user)


def _format_user(u):
    if u is None:
        return None
    return {
        "id": u["id"],
        "username": u["username"],
        "email": u["email"],
        "role": u["role"],
        "internalToken": u.get("internal_token"),
    }


schema = make_executable_schema(type_defs, query, mutation)
graphql_app = GraphQL(schema, debug=True)


@app.route("/graphql", methods=["GET", "POST"])
def graphql_server():
    return graphql_app(request.environ, lambda s, h: None)


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "users-subgraph"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=4001, debug=False)
