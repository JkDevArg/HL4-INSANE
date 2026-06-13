# CTFHL4-INSANE — Arquitectura y Convenciones (CONTRATO)

> Este documento es el **contrato** que todos los componentes respetan.
> Si cambias algo aquí, todos los servicios deben actualizarse.
> Construcción desde 0. No reutiliza CTFd/Whaley/ctf-siem (esos son del evento del 20-jun).

---

## 1. Modelo del CTF

- **10 equipos** (`team_01` … `team_10`), máx **4 integrantes** por equipo.
- Cada equipo recibe **1 credencial** (usuario + contraseña) y **1 archivo `.ovpn`**.
- Acceso **solo vía VPN**. La plataforma y los retos NO son alcanzables sin VPN.
- **Aislamiento total entre equipos**: `team_01` solo ve sus propias instancias de reto.
- **15 retos** por equipo (web / api / crypto), dificultad INSANE.
- Flags **dinámicas y únicas por equipo** → compartir flag = trampa detectable.

---

## 2. Plan de Red (fuente de verdad)

| Rango | Uso |
|---|---|
| `10.10.0.0/16` | Pool VPN (asignado por OpenVPN, topology subnet) |
| `10.10.N.0/24` | Subnet del `team_N` (N = 1..10). Ej: team_03 → `10.10.3.0/24` |
| `10.10.100.0/24` | Plataforma + servicios internos (platform, flag-service, api) |
| `10.10.200.0/24` | Stack SIEM (solo admin) |
| `172.30.N.0/24` | Red Docker de retos del `team_N` (aislada por equipo) |

**Regla de oro nftables:** `team_N` (10.10.N.0/24) → solo puede hablar con:
- Plataforma `10.10.100.10`
- Sus propios contenedores de reto `172.30.N.0/24`
- DNS interno `10.10.100.2`
Todo lo demás (otros equipos, internet directo, IA) → **DROP + LOG**.

---

## 3. Inventario de Servicios y Puertos

| Servicio | IP interna | Puerto | Expuesto a |
|---|---|---|---|
| OpenVPN | host | 1194/udp | Internet (único puerto público) |
| platform-api (FastAPI) | 10.10.100.10 | 8000 | VPN (vía nginx) |
| platform-web (Next.js) | 10.10.100.10 | 80/443 | VPN (vía nginx) |
| flag-service | 10.10.100.20 | 8001 | Solo red interna (retos + api) |
| postgres | 10.10.100.30 | 5432 | Solo api |
| redis | 10.10.100.31 | 6379 | Solo api + ban-counter |
| siem-collector | 10.10.200.10 | 9000 | Recibe eventos de api/vpn/retos |
| loki | 10.10.200.20 | 3100 | Solo SIEM |
| grafana | 10.10.200.30 | 3000 | Solo admin (SSH tunnel) |
| suricata | host (tun0) | — | IDS pasivo sobre VPN |

---

## 4. Formato de Flag (contrato flag-service)

```
flag{<20 hex>}
HMAC-SHA256(MASTER_SECRET, "MASTER_SECRET:team_id:challenge_id")[:20]
```

- `GET  /flag?team_id=team_03&challenge_id=web-supply-01` → genera (solo red interna).
- `POST /validate {team_id, challenge_id, flag}` → `{valid: bool}`.
- La plataforma valida SIEMPRE contra flag-service; nunca guarda flags en claro.
- **Anti-cheat:** la plataforma también consulta `POST /whose-flag {flag}` →
  devuelve el `team_id` dueño. Si el que la envía ≠ dueño → trampa.

---

## 5. Esquema de Evento SIEM (contrato collector)

Todos los componentes emiten eventos JSON a `POST http://10.10.200.10:9000/event`:

```json
{
  "ts": "2026-06-13T18:00:00Z",
  "source": "platform|vpn|suricata|challenge",
  "team_id": "team_03",
  "user": "team_03",
  "src_ip": "10.10.3.4",
  "event_type": "login|submit|flag_ok|flag_fail|cheat_flag_share|vpn_connect|vpn_disconnect|vpn_ban|ids_alert|scan_detected",
  "severity": "info|warn|alert|critical",
  "challenge_id": "web-supply-01",
  "detail": { "free": "form" }
}
```

Suricata → eve.json → Promtail → Loki (etiqueta `job=suricata`).
El collector normaliza a este esquema y los reenvía a Loki + dispara alertas.

---

## 6. Políticas

### 6.1 Bloqueo de IA (capa de red)
- VPN es gateway total (`redirect-gateway def1`) → todo el tráfico pasa por el server.
- DNS interno (dnsmasq) con **sinkhole** de dominios IA → resuelven a `0.0.0.0`.
- nftables **DROP + LOG** a rangos de IP de proveedores IA (ver `infra/firewall/ai-blocklist.txt`).
- Limitación honesta: NO impide IA desde otro dispositivo/datos móviles. Es disuasión de red + log.

### 6.2 Ban por 3 desconexiones
- `client-connect` / `client-disconnect` de OpenVPN → contador por CN en Redis.
- Ventana: solo cuenta desconexiones "limpias" del cliente (no timeouts del server).
- Al 3er evento → revoca cert (CRL) + evento SIEM `vpn_ban` + bloquea login en plataforma.
- Reversible solo por admin (`infra/firewall/unban.sh`).

### 6.3 Anti-cheat de retos
- **Crypto / pwn:** servir por red (`nc host port`), NO binario descargable cuando se pueda.
- Si hay binario: build **por equipo** con clave embebida (watermark) → delata al filtrador.
- Flag dinámica por equipo (sección 4) → compartir flag dispara `cheat_flag_share`.

---

## 7. Convenciones de Nombres

- Equipos: `team_01` … `team_10`.
- Retos: `<cat>-<slug>-<NN>` → `web-supply-01`, `api-bola-02`, `crypto-oracle-03`.
- Cada reto vive en `challenges/<cat>/<challenge_id>/` con `challenge.yaml` + `docker-compose.yml` + `solution/`.
- Contenedores de reto por equipo: `<challenge_id>__team_03`.

---

## 8. challenge.yaml (contrato de reto)

```yaml
id: web-supply-01
category: web
name: "Poisoned Pipeline"
difficulty: insane
type: per-team        # per-team | shared
serve: http           # http | tcp
flag_via: flag-service # la flag la inyecta el flag-service en build/runtime
points: 500
ports: [8080]
siem: true            # emite eventos al collector
description: "..."
```
