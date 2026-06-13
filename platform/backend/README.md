# platform-api — CTFHL4-INSANE

Backend de la plataforma del CTF. **FastAPI + SQLAlchemy (async) + PostgreSQL + Redis + JWT** (Python 3.12).

Implementa el contrato de `docs/ARCHITECTURE.md`: gate VPN-only, validacion de flags via `flag-service`, eventos al `collector` SIEM (esquema seccion 5), anti-cheat de flag-share (seccion 6.3) y check de ban (seccion 6.2).

## Componentes

| Archivo | Rol |
|---|---|
| `app/main.py` | App FastAPI, routers, CORS, healthcheck |
| `app/config.py` | Settings por entorno (sin MASTER_SECRET) |
| `app/db.py` | Engine async + sesion + cliente Redis |
| `app/models.py` | ORM: `teams`, `challenges`, `solves` |
| `app/auth.py` | bcrypt, JWT, sesiones Redis (limite 4) |
| `app/deps.py` | Gate VPN + ban check + `current_team` |
| `app/siem.py` | Emision fire-and-forget al collector |
| `app/flagclient.py` | Cliente flag-service (`/validate`, `/whose-flag`) |
| `app/routers/` | `auth`, `challenges`, `scoreboard` |
| `seed.py` | Crea 10 equipos + 15 retos; imprime credenciales |

## Variables sensibles

El `MASTER_SECRET` **no** vive aqui: toda flag se valida contra `flag-service`. Ver `.env.example`.

## Como correr

### Con Docker (esperado, integrado a docker-compose)

Hosts Docker usados: `postgres`, `redis`, `flag-service`, `collector`.

```bash
# build
docker build -t platform-api ./platform/backend

# sembrar DB (una vez): crea equipos + retos e imprime credenciales
docker compose run --rm platform-api python seed.py
#   --reset para borrar y resembrar

# la API arranca con el CMD por defecto (uvicorn en :8000)
```

### Local (desarrollo)

```bash
cd platform/backend
python -m venv .venv && source .venv/bin/activate   # o .venv\Scripts\activate en Windows
pip install -r requirements.txt
cp .env.example .env        # ajusta hosts a localhost si corres servicios sueltos
python seed.py
uvicorn app.main:app --reload --port 8000
```

Docs interactivas: `http://localhost:8000/docs`.

## Capas de seguridad aplicadas

1. **Gate VPN** (`require_vpn`): toda ruta de juego exige `src_ip ∈ VPN_CIDR` (`10.10.0.0/16`), si no → 403. Detras de nginx se usa `X-Forwarded-For`.
2. **JWT + sesion**: el token lleva `team_id` + `sid`; el `sid` debe seguir vivo en Redis.
3. **Limite 4 sesiones/equipo**: sorted set `sessions:team_NN`; la 5ª login → 429.
4. **Ban**: si existe `ban:team_NN` en Redis (puesto por el sistema VPN) → 403 en login y API.
5. **Rate-limit submits**: `submit_rl:team_NN`, 10 / 60s por defecto → 429.
6. **Anti-cheat flag-share**: ver `/challenges/{id}/submit` abajo.

---

## Contrato de la API (para el frontend)

Base URL: `http://<host-VPN>/api` (o `:8000` directo). Auth: `Authorization: Bearer <token>`.

Todas las rutas excepto `POST /auth/login` y `GET /health` exigen Bearer token **y** origen VPN.

### `GET /health`
Sin auth. `200 → { "status": "ok" }`.

### `POST /auth/login`
Request:
```json
{ "username": "team_03", "password": "..." }
```
Response `200`:
```json
{
  "access_token": "<jwt>",
  "token_type": "bearer",
  "team_id": "team_03",
  "display_name": "Equipo 03"
}
```
Errores: `401` credenciales invalidas · `403` fuera de VPN o equipo baneado · `429` limite de 4 sesiones.

### `GET /auth/me`
Response `200`:
```json
{ "team_id": "team_03", "display_name": "Equipo 03" }
```
Errores: `401` token invalido/expirado/sesion cerrada · `403` VPN/ban.

### `POST /auth/logout`
Cierra la sesion actual (libera un cupo). Response `204`.

### `GET /challenges`
Lista de retos visibles. **Nunca** expone la flag.
Response `200`:
```json
[
  {
    "id": "web-supply-01",
    "category": "web",
    "name": "Poisoned Pipeline",
    "difficulty": "insane",
    "points": 500,
    "description": "...",
    "connection_info": "http://web-supply-01.team-N:8080",
    "solved": false
  }
]
```
`category ∈ {web, api, crypto}`. `solved` = si el equipo autenticado ya lo resolvio.

### `POST /challenges/{challenge_id}/submit`
Request:
```json
{ "flag": "flag{0123456789abcdef0123}" }
```
Response `200` (correcta):
```json
{ "correct": true, "already_solved": false, "points_awarded": 500, "message": "Correcto! +500 puntos." }
```
Response `200` (ya resuelto, idempotente, sin puntos extra):
```json
{ "correct": true, "already_solved": true, "points_awarded": 0, "message": "Reto ya resuelto anteriormente." }
```
Response `200` (incorrecta):
```json
{ "correct": false, "already_solved": false, "points_awarded": 0, "message": "Flag incorrecta." }
```
Errores:
- `403` **flag-share**: la flag pertenece a otro equipo. No da puntos, se emite `cheat_flag_share` (critical) y se marca red flag. `detail`: `"Flag perteneciente a otro equipo. Incidente registrado."`
- `404` reto inexistente · `429` rate-limit superado · `401/403` auth/VPN/ban.

### `GET /scoreboard`
Response `200`:
```json
{
  "entries": [
    {
      "rank": 1,
      "team_id": "team_03",
      "display_name": "Equipo 03",
      "points": 1500,
      "solves": 3,
      "last_solve": "2026-06-13T18:00:00Z"
    }
  ]
}
```
Orden: puntos desc; desempate por `last_solve` ascendente (quien llego antes gana). Equipos sin solves van al final.

---

## Eventos SIEM emitidos

Esquema exacto de `ARCHITECTURE.md` seccion 5, `source: "platform"`, POST a `COLLECTOR_URL/event` (fire-and-forget):

| Evento | Cuando | severity |
|---|---|---|
| `login` | login ok / fail / max_sessions | `info` / `warn` |
| `submit` | cada intento de flag (y rate_limited) | `info` / `warn` |
| `flag_ok` | flag correcta, solve registrado | `info` |
| `flag_fail` | flag incorrecta | `warn` |
| `cheat_flag_share` | flag de otro equipo | `critical` |

## Anti-cheat de flag-share — detalle

En cada submit, antes de dar puntos, la API consulta `POST flag-service/whose-flag {flag, challenge_id}`. Si el dueño difiere del equipo que envia:
- No se otorgan puntos (403).
- Se emite `cheat_flag_share` (critical) con `submitter_team` y `owner_team`.
- Se marca red flag en Redis: `teams_red_flag` (set), `red_flag:<team>` (contador), `flag_share:<team>` (set de equipos cuya flag uso) — consumible por el sistema de ban v2.

Si `flag-service` no expone `/whose-flag`, el cliente **deriva** el dueño probando la flag con `/validate` contra `team_01..team_N` fijando el `challenge_id` (la flag es HMAC por `team+challenge`, asi que solo un equipo valida).
