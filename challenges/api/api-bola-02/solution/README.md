# Solución — api-bola-02 · Mass Assignment Heist

**Categoría:** api · **Dificultad:** insane · **Puntos:** 550
**Vuln central:** Mass Assignment encadenado (2 saltos) + escalada de privilegios sobre el flujo de facturación de "LedgerPay".

## Resumen

LedgerPay es una API de facturación B2B. Cada cuenta tiene:

- `tier`: `free` < `pro` < `enterprise` (gate de funcionalidades).
- `org_role`: `member` < `org_admin` (gate del secreto).

El objetivo es `GET /api/v1/org/secrets`, que exige `org_role=org_admin`. La
clave maestra del ledger (`ledger_master_key`) es la flag. Una cuenta recién
registrada nace `free` / `member`, sin forma "legítima" de subir.

No basta con un solo campo `role=admin`: hay que encadenar **dos** mass
assignments y entender el flujo de negocio que los conecta.

| # | Vuln | Endpoint | Efecto |
|---|------|----------|--------|
| 1 | Mass assignment en perfil (Pydantic `extra=allow` + `model_dump()` volcado) | `PATCH /api/v1/accounts/me` | Inyectar `tier=enterprise` (campo no editable por diseño) |
| 2 | Gate de negocio + mass assignment en aprobación | `POST /api/v1/invoices/{id}/approve` | `enterprise` abre el endpoint; el body inyecta `approver_role=org_admin`, que promueve la cuenta a `org_admin` |
| 3 | Autorización por `org_role` | `GET /api/v1/org/secrets` | Devuelve la flag |

## Cadena paso a paso

1. **Alta**: `POST /api/v1/accounts/register {email,name}` → te dan `token` y
   un `pending_invoice_id`. Tu cuenta es `tier=free`, `org_role=member`.

2. **Recon**: `GET /api/v1/accounts/me` revela los campos del registro
   (`tier`, `credit_limit`, `org_role`, `verified`). El root `/` insinúa que
   el PATCH "solo" acepta `name`/`email` — pista de que algo más cuela.

3. **Mass assignment #1 — subir tier**:
   ```
   PATCH /api/v1/accounts/me   (Bearer <token>)
   {"tier":"enterprise"}
   ```
   El handler hace `body.model_dump(exclude_unset=True)` sobre un modelo
   `extra="allow"` y vuelca **todo** sobre el registro. Quedas `enterprise`.

4. **Mass assignment #2 — aprobar como org_admin**: el endpoint de aprobación
   solo responde a `enterprise` (gate ya superado). Su body también es
   mass-assignable:
   ```
   POST /api/v1/invoices/<pending_invoice_id>/approve   (Bearer <token>)
   {"comment":"ok","approver_role":"org_admin"}
   ```
   La regla de negocio insegura: quien sella la aprobación como `org_admin`
   queda reconocido como `org_admin` → tu `org_role` se promueve.

5. **Leer la flag**:
   ```
   GET /api/v1/org/secrets   (Bearer <token>)
   -> {"org_secrets":{"ledger_master_key":"flag{...}", ...}}
   ```

Exploit completo: `python solution/exploit.py http://<host>:8080`.

> Atajo: `PATCH /api/v1/accounts/me {"org_role":"org_admin"}` también funciona
> (el perfil es totalmente mass-assignable). La cadena enterprise→approve es el
> camino "narrativo" y demuestra entender el flujo; ambos cuentan. La dificultad
> real está en **descubrir los nombres de campo** ocultos (`tier`, `org_role`,
> `approver_role`), no documentados, y en encadenar el gate de negocio.

## Por qué es INSANE

- Dos mass assignments **encadenados**: el primero (tier) es prerequisito para
  alcanzar el segundo (approve), que es donde ocurre la escalada a org_admin.
- Ningún campo se llama `admin`/`role` a secas: hay que inferir `tier`,
  `org_role` y `approver_role` desde el modelo de respuesta y el flujo.
- El gate `tier=enterprise` obliga a entender la lógica de facturación: sin él,
  `/approve` devuelve 403 y no se ve el segundo punto de inyección.

## Mitigaciones (didáctico)

- Pydantic con `extra="forbid"` y allow-list explícita de campos editables
  (`name`, `email`). Nunca volcar `model_dump()` crudo sobre el dominio.
- Separar el DTO de entrada del modelo de dominio; `tier`, `org_role`,
  `credit_limit` solo mutables por procesos internos autorizados.
- La aprobación no debe aceptar el rol del aprobador desde el cliente: el rol
  se deriva del servidor a partir de la sesión, jamás del body.
- Autorización por capacidad verificada en backend, no por campos
  auto-asignables.

## Nota anti-cheat

La flag (`ledger_master_key`) es **dinámica y única por equipo** (HMAC del
flag-service, `ARCHITECTURE §4`), inyectada por env `FLAG` en esta instancia.
Cada equipo explota SU propia API para SU flag; compartir el método no da
puntos. Enviar la flag de otro equipo dispara `cheat_flag_share`
(`/whose-flag`). Además, ambos mass assignments y la lectura del secreto emiten
eventos SIEM (`scan_detected` alert: `mass-assignment-profile`,
`mass-assignment-approve`, `org-secrets-read`) al collector.
