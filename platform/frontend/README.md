# platform-web — Frontend del CTFHL4-INSANE

Frontend de la plataforma del CTF HackL4bs. **Next.js 14 (App Router) + TypeScript + Tailwind**.
Tema oscuro estilo hacker/HackTheBox (negro + verde-neón / cian). Español (Perú).

Sirve tres vistas detrás de la VPN del CTF:

- **`/login`** — autenticación por equipo (usuario/contraseña).
- **`/`** — retos agrupados por categoría (web / api / crypto) con envío de flag inline.
- **`/scoreboard`** — ranking de equipos en vivo.

> El acceso real es **solo vía VPN del CTF**. Un nginx hace de proxy `/api` → `platform-api:8000`.

---

## Requisitos

- Node.js 20+
- La `platform-api` accesible en la ruta configurada por `NEXT_PUBLIC_API_BASE`.

## Variables de entorno

| Variable | Default | Descripción |
|---|---|---|
| `NEXT_PUBLIC_API_BASE` | `/api` | Base de la API. En prod, nginx hace proxy `/api` → backend. Para dev directo: `http://localhost:8000`. |

Copia el ejemplo:

```bash
cp .env.example .env.local
```

## Desarrollo local

```bash
npm install
npm run dev        # http://localhost:3000
```

Para apuntar directo al backend (sin nginx) durante desarrollo, en `.env.local`:

```env
NEXT_PUBLIC_API_BASE=http://localhost:8000
```

> Nota: `NEXT_PUBLIC_*` se inyecta en build/arranque. En el contenedor se pasa como `ARG`/`ENV` en build.

## Build de producción (sin Docker)

```bash
npm run build
npm run start      # next start en :3000
```

## Docker

Imagen multi-stage con salida `standalone` (`next build` + `node server.js` en el puerto 3000).

```bash
# Build (la base de API por defecto es /api, ideal tras nginx)
docker build -t ctfhl4/platform-web .

# Para fijar otra base de API en build-time:
docker build --build-arg NEXT_PUBLIC_API_BASE=/api -t ctfhl4/platform-web .

# Run
docker run --rm -p 3000:3000 ctfhl4/platform-web
```

---

## Contrato de API consumido

Base: `NEXT_PUBLIC_API_BASE` (default `/api`). Todas (salvo login) van con `Authorization: Bearer <jwt>`.

| Método | Ruta | Notas |
|---|---|---|
| `POST` | `/auth/login` | `{username, password}` → `{access_token, token_type, team_id, display_name}`. 401 credenciales · 403 VPN/ban · 429 (>4 sesiones). |
| `GET` | `/auth/me` | Verifica sesión → `{team_id, display_name}`. |
| `POST` | `/auth/logout` | 204. |
| `GET` | `/challenges` | Lista de retos del equipo (incluye `solved` y `connection_info`). |
| `POST` | `/challenges/{id}/submit` | `{flag}` → `{correct, already_solved, points_awarded, message}`. 403 = flag de otro equipo (**incidente**) · 404 · 429. |
| `GET` | `/scoreboard` | `{entries:[{rank, team_id, display_name, points, solves, last_solve}]}`. |

### Manejo de errores (cliente central `src/lib/api.ts`)

- **401** → limpia sesión y redirige a `/login`.
- **403** (en endpoints protegidos) → redirige a `/blocked` ("Equipo baneado / fuera de VPN").
- **403** en `submit` → NO redirige: la card muestra **"Incidente registrado"** (flag de otro equipo).
- **429** → mensaje de rate-limit / límite de sesiones.
- **Fallo de red (status 0)** → "Verifica tu conexión a la VPN del CTF".

La sesión (JWT) se guarda en `localStorage` (aceptable para el MVP). Para migrar a cookie httpOnly,
solo hay que cambiar `src/lib/storage.ts`.

---

## Estructura

```
src/
  app/
    layout.tsx                 # layout raíz (fuentes, estilos globales)
    globals.css                # tema Tailwind + componentes (.btn-neon, .card, .input-term)
    login/page.tsx             # /login
    blocked/page.tsx           # /blocked (pantalla de 403: ban / fuera de VPN)
    not-found.tsx              # 404
    (protected)/
      layout.tsx               # SessionProvider (verifica /auth/me) + Header
      page.tsx                 # / (retos por categoría + puntaje del equipo)
      scoreboard/page.tsx      # /scoreboard
  components/
    SessionProvider.tsx        # contexto de sesión + guard + logout
    Header.tsx                 # cabecera (nav, identidad de equipo, logout)
    ChallengeCard.tsx          # card de reto + envío de flag inline
    Badge.tsx                  # badges de categoría y dificultad (INSANE)
    Spinner.tsx                # indicador de carga
  lib/
    api.ts                     # cliente API central (Bearer, manejo de errores)
    types.ts                   # tipos del contrato
    storage.ts                 # sesión en localStorage
```
