# CTFHL4-INSANE — Plataforma CTF Privada con VPN por Equipo

Plataforma CTF estilo HackTheBox con infraestructura propia: VPN por equipo,
flags dinámicas, retos HARD/INSANE y SIEM de monitoreo en tiempo real.

---

## 🚀 Despliegue en 1 comando

En un servidor Ubuntu 22.04 / 24.04 limpio (con la IP/dominio público apuntando a él):

```bash
git clone <URL_DEL_REPO> ctfhl4 && cd ctfhl4
sudo ./bootstrap.sh <IP_O_DOMINIO_PUBLICO>
```

Eso instala Docker, levanta la plataforma + SIEM, configura la VPN (con DNS
interno y bloqueo de IA), el firewall (aislamiento por equipo, internet
permitido pero IA/chatbots bloqueados), Suricata, el dashboard público
anonimizado, genera los certificados (4 por equipo) y lanza los retos.

Opciones: `--teams N` · `--no-challenges` · `--vpn-proto tcp` · `--vpn-port N`.
Al terminar imprime las URLs, credenciales y dónde están los `.ovpn`.

Detalle paso a paso y verificación: ver `docs/DESPLIEGUE-VM.md` e
`docs/INTEGRACION-Y-PRUEBA.md`. Endpoints/gotchas de red: `docs/ARCHITECTURE.md`.

### Tras un reinicio o al recrear contenedores
Docker reescribe la tabla `raw`; reaplica el firewall para que la VPN siga
alcanzando los retos:
```bash
sudo bash infra/firewall/setup-nftables.sh
```

---

## Arquitectura General

```
                        ┌─────────────────────────────────────┐
                        │           VPS / Ubuntu VM            │
                        │                                      │
  Equipo 01 ──ovpn──►  │  OpenVPN Server                      │
  Equipo 02 ──ovpn──►  │  ├── team_01 → 10.10.1.0/24         │
  Equipo 03 ──ovpn──►  │  ├── team_02 → 10.10.2.0/24         │
                        │  └── team_N  → 10.10.N.0/24         │
                        │                                      │
                        │  Challenge Network (10.10.100.0/24)  │
                        │  ├── web-01   :8080                  │
                        │  ├── pwn-01   :4444                  │
                        │  └── rev-01   :9999                  │
                        │                                      │
                        │  Flag Service (interno)              │
                        │  └── HMAC(secret+team+challenge)     │
                        │                                      │
                        │  SIEM Stack                          │
                        │  ├── Promtail (recolección)          │
                        │  ├── Loki (almacenamiento)           │
                        │  ├── Suricata (IDS)                  │
                        │  └── Grafana (dashboards)            │
                        └─────────────────────────────────────┘
```

---

## Flujo de un Jugador

```
1. Registro en plataforma → se genera cert OpenVPN único para su equipo
2. Descarga team_XX.ovpn  → conecta VPN
3. VPN le asigna IP fija  → 10.10.X.Y (identificador de equipo)
4. Accede al reto         → el reto lee su IP y genera su flag dinámica
5. Explota el reto        → obtiene flag{<hash único>}
6. Submitea en plataforma → Flag Service valida contra HMAC(secret+team+challenge)
7. SIEM registra todo     → admin ve en Grafana qué hizo cada equipo
```

---

## Stack Tecnológico

| Capa | Tecnología |
|---|---|
| OS Servidor | Ubuntu 22.04 LTS |
| VPN | OpenVPN 2.6 + EasyRSA 3 |
| Retos | Docker + Docker Compose |
| Flag Service | FastAPI (Python) |
| Platform/API | FastAPI + SQLite/PostgreSQL |
| Frontend | Next.js |
| Firewall | nftables |
| SIEM Collect | Promtail |
| SIEM Storage | Loki |
| SIEM IDS | Suricata |
| SIEM Viz | Grafana |

---

## Estructura del Repositorio

```
CTFHL4-INSANE/
├── README.md
│
├── vpn/                        # Capa VPN
│   ├── scripts/
│   │   ├── setup-server.sh     # Instala y configura OpenVPN + EasyRSA
│   │   ├── gen-team-cert.sh    # Genera cert + .ovpn para un equipo
│   │   └── revoke-team.sh      # Revoca acceso de un equipo
│   ├── configs/
│   │   ├── server.conf         # Config OpenVPN servidor
│   │   └── client-template.ovpn # Template para generar .ovpn por equipo
│   └── keys/                   # PKI (NO commitear en producción)
│
├── challenges/                 # Retos del CTF
│   ├── web/
│   │   └── challenge-template/ # Template base para reto web
│   ├── pwn/
│   │   └── challenge-template/
│   ├── reversing/
│   │   └── challenge-template/
│   └── misc/
│
├── flag-service/               # Microservicio de flags dinámicas
│   ├── app/
│   │   ├── main.py             # FastAPI: genera y valida flags
│   │   └── models.py
│   ├── Dockerfile
│   └── requirements.txt
│
├── platform/                   # Plataforma web del CTF
│   ├── backend/                # API (FastAPI): equipos, scoring, submissions
│   └── frontend/               # Next.js: UI del CTF
│
├── siem/                       # Stack de monitoreo
│   ├── loki/
│   │   └── loki-config.yaml
│   ├── promtail/
│   │   └── promtail-config.yaml
│   ├── grafana/
│   │   └── dashboards/
│   │       ├── vpn-activity.json
│   │       ├── challenge-traffic.json
│   │       └── flag-submissions.json
│   └── suricata/
│       └── custom.rules
│
├── infra/
│   ├── docker-compose.yml      # Levanta todos los servicios
│   ├── docker-compose.siem.yml # Solo el stack SIEM
│   └── firewall/
│       ├── setup-nftables.sh   # Reglas de aislamiento por equipo
│       └── nftables.conf
│
└── docs/
    ├── setup-vm.md             # Guía: configurar la VM Ubuntu
    ├── setup-vpn.md            # Guía: OpenVPN paso a paso
    ├── flags-dinamicas.md      # Cómo funciona el Flag Service
    ├── siem.md                 # Guía del SIEM
    └── add-challenge.md        # Cómo agregar un nuevo reto
```

---

## Roadmap — Fases de Construcción

### Fase 1 — VPN Base (ACTUAL)
- [ ] Instalar OpenVPN + EasyRSA en VM Ubuntu
- [ ] Configurar servidor OpenVPN con subnets por equipo
- [ ] Script para generar `.ovpn` por equipo
- [ ] Script para revocar acceso
- [ ] Prueba: conectar desde Windows con 2 equipos simulados

### Fase 2 — Flag Service
- [ ] Microservicio FastAPI para generación de flags con HMAC
- [ ] Endpoint: `GET /flag?team_id=X&challenge_id=Y`
- [ ] Endpoint: `POST /validate` con team + challenge + flag_input
- [ ] Dockerizar el servicio

### Fase 3 — Primer Reto (Template)
- [ ] Reto web básico (HARD) dockerizado
- [ ] El reto consulta Flag Service según IP del cliente
- [ ] Accesible solo desde la VPN (nftables)
- [ ] Prueba end-to-end: conectar VPN → explotar → obtener flag

### Fase 4 — Firewall + Aislamiento
- [ ] nftables: cada equipo solo accede a su subnet de retos
- [ ] Bloquear tráfico entre equipos
- [ ] Logging de tráfico por equipo hacia retos

### Fase 5 — SIEM Base
- [ ] Loki + Promtail + Grafana en docker-compose
- [ ] Dashboard: conexiones VPN en tiempo real
- [ ] Dashboard: tráfico por equipo a retos
- [ ] Dashboard: submissions de flags (OK / FAIL)

### Fase 6 — Suricata (IDS)
- [ ] Suricata monitoreando tráfico de la VPN
- [ ] Reglas: detectar nmap, exploits conocidos, fuerza bruta
- [ ] Alertas en Grafana

### Fase 7 — Platform Web
- [ ] Backend API: registro de equipos, scoreboard, submissions
- [ ] Frontend Next.js: UI del CTF
- [ ] Integración con Flag Service

### Fase 8 — Retos HARD/INSANE
- [ ] Mínimo 3 retos por categoría (web, pwn, rev, misc)
- [ ] Documentación interna de solución (writeups privados)

### Fase 9 — VPS en Producción
- [ ] Migrar de VM local a VPS real
- [ ] Dominio + SSL para la plataforma
- [ ] Backup automatizado de flags y scoring

---

## Convenciones

### Subnets VPN por Equipo

| Equipo | Subnet VPN | IP típica |
|---|---|---|
| team_01 | 10.10.1.0/24 | 10.10.1.2 |
| team_02 | 10.10.2.0/24 | 10.10.2.2 |
| team_N | 10.10.N.0/24 | 10.10.N.2 |

### Red de Retos

| Red | Uso |
|---|---|
| 10.10.100.0/24 | Contenedores de retos |
| 10.10.200.0/24 | Servicios internos (flag-service, platform) |

### Formato de Flags

```
flag{<20 chars hex>}
Ejemplo: flag{a3f9c1b2e4d0781200ab}
Generada por: HMAC-SHA256(MASTER_SECRET + team_id + challenge_id)[:20]
```

---

## Seguridad

- `vpn/keys/` nunca se commitea (agregado a `.gitignore`)
- `MASTER_SECRET` del Flag Service solo existe como variable de entorno
- Cada `.ovpn` contiene el cert embebido — si se filtra, se revoca
- Tráfico entre equipos bloqueado a nivel nftables
- SIEM solo accesible desde IP del admin

---

## Estado Actual

> **Entorno de pruebas**: Ubuntu VM local (reemplazará con VPS)
> **Fecha inicio**: 2026-05-28
> **Fase actual**: 1 — VPN Base
