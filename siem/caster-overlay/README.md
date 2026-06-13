# caster-overlay

Overlay **PÚBLICO** para comentaristas / stream (OBS) del CTFHL4-INSANE.
Muestra la actividad en vivo de los equipos — **siempre anonimizada**.

> ⚠️ **Regla crítica de privacidad:** este overlay es de cara al público.
> **Nunca** debe salir al aire una IP real. Toda IP se traduce a una etiqueta
> anónima (`Equipo NN`, `plataforma`, `siem`, `reto(Equipo NN)`, `interno`,
> `externo`) en `app/anonymize.py`, que envuelve **toda** la salida.
> Los tests de `anonymize.py` se ejecutan también durante el build de Docker:
> si fallan, la imagen no se construye.

## Arquitectura

- **Stack:** FastAPI (Python 3.12) + httpx async.
- **Fuente de datos:** Loki (`/loki/api/v1/query_range`, ventana de `WINDOW_MIN`).
  - Eventos del collector: labels `source`, `team_id`, `event_type`, `severity` (+ JSON completo en la línea).
  - dnsmasq via Promtail: `job=dns` (labels `domain`, `src_ip`, `qtype`).
  - suricata via Promtail: `job=suricata` (labels `signature`, `src_ip`, `dest_ip`, `category`).
  - `job=vpn-events`, `job=firewall`.
- Si Loki está caído, los endpoints degradan a vacío (no crashean).

## Anonimización (`app/anonymize.py`)

| IP real | Etiqueta pública |
|---|---|
| `10.10.N.M` (N=1..10) | `Equipo NN` |
| `10.10.100.x` | `plataforma` |
| `10.10.200.x` | `siem` |
| `10.10.0.x` / resto `10.10.x.x` | `interno` |
| `172.30.N.x` (N=1..10) | `reto(Equipo NN)` |
| otra privada (10.x, 172.x, 192.168.x) | `interno` |
| cualquier IP pública | `externo` |

En DNS el **dominio sí se muestra** (no es dato personal); la IP origen se
traduce a `Equipo NN`. Ej: `Equipo 03 intentó resolver chat.openai.com (BLOQUEADO - IA)`.

Probar la anonimización:
```bash
python app/anonymize.py   # ejecuta los tests; sale != 0 si algo falla
```

## Endpoints

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/` | Sirve `static/index.html` (el overlay). |
| GET | `/api/feed?limit=80` | Feed fusionado y anonimizado, más reciente primero: `[{ts, team, kind, severity, text, icon}]`. `kind ∈ {submit, flag_ok, flag_fail, cheat, vpn, ban, ids/scan, ai_block, dns}`. |
| GET | `/api/scoreboard` | Puntos y solves por equipo (suma `detail.points` de los `flag_ok`), desc: `[{team, points, solves}]`. |
| GET | `/api/stats` | `{total_events, alerts, ai_blocked, scans, window_min, ctf_name}`. |
| GET | `/api/health` | Estado del servicio + si Loki responde. |

## Configuración (env)

| Variable | Default | Uso |
|---|---|---|
| `LOKI_URL` | `http://loki:3100` | Endpoint de Loki. |
| `WINDOW_MIN` | `15` | Ventana temporal (minutos) de las queries. |
| `CTF_NAME` | `CTFHL4-INSANE` | Título mostrado en el overlay. |

## Ejecución local

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8090
# Overlay: http://localhost:8090/
```

## Docker

```bash
docker build -t caster-overlay .
docker run --rm -p 8090:8090 \
  -e LOKI_URL=http://loki:3100 \
  -e WINDOW_MIN=15 \
  -e CTF_NAME="CTFHL4-INSANE" \
  caster-overlay
```

Expone el puerto **8090**.

## Uso en OBS

Añade una **fuente de navegador** apuntando a `http://<host>:8090/`,
resolución 1920x1080. La página es oscura, de alto contraste y se
auto-actualiza cada 4s (polling a `/api/feed`, `/api/scoreboard`, `/api/stats`).
No requiere autenticación (es público por diseño, pero solo emite datos
anonimizados).
