# CTFHL4 - FINAL · Guía de Despliegue en VPS

> **Última actualización:** junio 2026  
> **Plataforma objetivo:** Ubuntu 24.04 LTS (x86\_64)  
> **Tiempo estimado desde cero:** ~45 minutos

---

## Índice

1. [Arquitectura general](#1-arquitectura-general)
2. [Requisitos del servidor](#2-requisitos-del-servidor)
3. [Paso 0 — Preparar el servidor](#paso-0--preparar-el-servidor)
4. [Paso 1 — Clonar el repositorio](#paso-1--clonar-el-repositorio)
5. [Paso 2 — Configurar secretos (.env)](#paso-2--configurar-secretos-env)
6. [Paso 3 — Instalar OpenVPN y generar PKI](#paso-3--instalar-openvpn-y-generar-pki)
7. [Paso 4 — Levantar la plataforma (Docker)](#paso-4--levantar-la-plataforma-docker)
8. [Paso 5 — Sembrar la base de datos](#paso-5--sembrar-la-base-de-datos)
9. [Paso 6 — Instalar hooks VPN y firewall](#paso-6--instalar-hooks-vpn-y-firewall)
10. [Paso 7 — Distribuir archivos .ovpn](#paso-7--distribuir-archivos-ovpn)
11. [URLs y credenciales](#urls-y-credenciales)
12. [Checklist pre-CTF](#checklist-pre-ctf)
13. [Operaciones durante el CTF](#operaciones-durante-el-ctf)
14. [Emergencias y procedimientos](#emergencias-y-procedimientos)

---

## 1. Arquitectura general

```
Internet
    │
    ├── :80/443  ──► nginx ──► platform (Next.js + FastAPI)
    ├── :1194/UDP ──► OpenVPN ──► jugadores (10.10.N.0/24)
    └── :8090    ──► caster-overlay (SIEM público, anonimizado)

Jugadores (via VPN)
    ├── 10.10.100.0/24  ──► Platform CTF (login, retos, scoreboard)
    └── 172.30.N.0/24   ──► Retos del equipo N (aislados)

Admin (solo por túnel SSH)
    ├── localhost:3000  ──► Grafana (dashboards SIEM)
    └── localhost:8091  ──► Admin panel (control en vivo)
```

**Equipos y subredes:**

| Equipo | Nombre | Subred VPN | Red de retos |
|--------|--------|------------|--------------|
| team\_01 | Bytreach | 10.10.1.0/24 | 172.30.1.0/24 |
| team\_02 | MoodySploiters | 10.10.2.0/24 | 172.30.2.0/24 |
| team\_03 | DARKHIVE | 10.10.3.0/24 | 172.30.3.0/24 |
| team\_04 | Threat Hunters | 10.10.4.0/24 | 172.30.4.0/24 |
| team\_05 | Capa 8 | 10.10.5.0/24 | 172.30.5.0/24 |

**Redes Docker internas:**

| Red | Subred | Propósito |
|-----|--------|-----------|
| net\_platform | 10.10.100.0/24 | Plataforma CTF (API, web, DB, Redis) |
| net\_siem | 10.10.200.0/24 | SIEM (Loki, Grafana, Collector) |
| net\_teamNN | 172.30.N.0/24 | Retos de cada equipo (aislados) |

---

## 2. Requisitos del servidor

| Recurso | Mínimo | Recomendado |
|---------|--------|-------------|
| CPU | 2 vCPU | 4 vCPU |
| RAM | 4 GB | 8 GB |
| Disco | 40 GB SSD | 80 GB SSD |
| SO | Ubuntu 24.04 LTS | Ubuntu 24.04 LTS |

**Puertos que deben estar abiertos al público:**

| Puerto | Protocolo | Servicio |
|--------|-----------|---------|
| 22 | TCP | SSH (administración) |
| 80 | TCP | Plataforma CTF |
| 443 | TCP | Plataforma CTF (TLS, si aplica) |
| 1194 | UDP | OpenVPN |
| 8090 | TCP | SIEM público (casters/espectadores) |

> Los puertos 3000 (Grafana) y 8091 (Admin panel) son **solo por túnel SSH**. No abrir al público.

---

## Paso 0 — Preparar el servidor

Conectarse al VPS y ejecutar como usuario con sudo:

```bash
# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar dependencias
sudo apt install -y \
    git curl wget \
    docker.io docker-compose-plugin \
    openvpn easy-rsa \
    nftables \
    redis-tools \
    python3 python3-pip \
    dnsmasq \
    netcat-openbsd

# Agregar usuario al grupo docker
sudo usermod -aG docker $USER
newgrp docker

# Habilitar ip_forward (necesario para enrutar tráfico VPN)
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Directorio de logs OpenVPN
sudo mkdir -p /var/log/openvpn
sudo chmod 755 /var/log/openvpn
```

---

## Paso 1 — Clonar el repositorio

```bash
cd /opt
sudo git clone <URL_DEL_REPO> HL4-INSANE
sudo chown -R $USER:$USER /opt/HL4-INSANE
cd /opt/HL4-INSANE
```

> Si no hay repositorio remoto, copia los archivos con SCP desde tu máquina local:
> ```bash
> scp -r ./CTFHL4-INSANE user@VPS_IP:/opt/HL4-INSANE
> ```

---

## Paso 2 — Configurar secretos (.env)

```bash
cd /opt/HL4-INSANE/infra
cp .env.example .env
nano .env
```

Genera secretos seguros antes de editar:

```bash
echo "MASTER_SECRET=$(openssl rand -hex 32)"
echo "JWT_SECRET=$(openssl rand -hex 32)"
echo "POSTGRES_PASSWORD=$(openssl rand -hex 16)"
echo "GRAFANA_PASSWORD=$(openssl rand -hex 12)"
echo "ADMIN_PASSWORD=$(openssl rand -hex 24)"
```

Contenido del `.env`:

```env
# ── Secretos críticos ─────────────────────────────────────────────────────
MASTER_SECRET=<valor generado>
JWT_SECRET=<valor generado>
POSTGRES_PASSWORD=<valor generado>

# ── SIEM ─────────────────────────────────────────────────────────────────
GRAFANA_PASSWORD=<valor generado>
ADMIN_PASSWORD=<valor generado>

# ── CTF ──────────────────────────────────────────────────────────────────
CTF_NAME=CTFHL4 - FINAL

# ── Alertas (opcional) ───────────────────────────────────────────────────
DISCORD_WEBHOOK_URL=
```

> **Nunca subas el `.env` a Git.** El `.gitignore` ya lo excluye.

---

## Paso 3 — Instalar OpenVPN y generar PKI

### 3.1 Configurar el servidor OpenVPN

```bash
# Reemplaza con la IP pública del VPS
export SERVER_IP="<IP_PUBLICA_DEL_VPS>"

sudo bash /opt/HL4-INSANE/vpn/scripts/setup-server.sh "$SERVER_IP"
```

Esto genera:
- PKI completo en `/etc/openvpn/easy-rsa/`
- `/etc/openvpn/server.conf`
- Claves: `ca.crt`, `server.crt/key`, `dh.pem`, `ta.key`

### 3.2 Añadir directivas del CTF al servidor

```bash
sudo bash -c 'cat /opt/HL4-INSANE/vpn/configs/server-additions.conf >> /etc/openvpn/server.conf'
sudo bash -c 'cat /opt/HL4-INSANE/vpn/configs/server-ban-additions.conf >> /etc/openvpn/server.conf'
```

Estas directivas incluyen:
- `push "redirect-gateway def1"` — fuerza TODO el tráfico del jugador por el VPN
- `push "dhcp-option DNS 10.10.0.1"` — DNS propio (sinkhole de IA)
- `push "block-outside-dns"` — impide DNS leaks
- Management interface en `127.0.0.1:7505` (para ban en vivo)

### 3.3 Generar los 20 certificados de jugadores

```bash
export SERVER_IP="<IP_PUBLICA_DEL_VPS>"

for team in 01 02 03 04 05; do
    for player in 1 2 3 4; do
        sudo bash /opt/HL4-INSANE/vpn/scripts/gen-team-cert.sh \
            "team_${team}" "$player" "$SERVER_IP"
    done
done
```

Los archivos `.ovpn` quedan en `/etc/openvpn/clients/`.

### 3.4 Asignar IPs estáticas por jugador

```bash
sudo bash /opt/HL4-INSANE/vpn/scripts/setup-ccd.sh
```

Asignaciones resultantes:

```
team_01_p1 → 10.10.1.11    team_02_p1 → 10.10.2.11    ...
team_01_p2 → 10.10.1.12    team_02_p2 → 10.10.2.12
team_01_p3 → 10.10.1.13    ...
team_01_p4 → 10.10.1.14
```

### 3.5 Iniciar OpenVPN

```bash
sudo systemctl enable openvpn@server
sudo systemctl start openvpn@server
sudo systemctl status openvpn@server
```

### 3.6 Empaquetar .ovpn para distribución

```bash
cd /etc/openvpn/clients
sudo zip -r /home/$USER/ovpn-jugadores.zip *.ovpn
sudo chown $USER:$USER /home/$USER/ovpn-jugadores.zip
ls -lh /home/$USER/ovpn-jugadores.zip
```

---

## Paso 4 — Levantar la plataforma (Docker)

```bash
cd /opt/HL4-INSANE/infra

# Primera vez: construir imágenes y levantar todos los contenedores
docker compose up -d --build

# Verificar estado
docker compose ps
```

**Salida esperada** (todos `Up` o `healthy`):

```
NAME                STATUS
ctf-nginx           Up
ctf-web             Up
ctf-api             Up (healthy)
ctf-postgres        Up (healthy)
ctf-redis           Up
ctf-flag-service    Up
ctf-loki            Up
ctf-promtail        Up
ctf-caster          Up (healthy)
ctf-grafana         Up
ctf-collector       Up (healthy)
ctf-admin-panel     Up (healthy)
ctf-prometheus      Up
ctf-cadvisor        Up (healthy)
```

> **Loki en restart loop** (`mkdir /loki/index: permission denied`):
> ```bash
> docker stop ctf-loki
> docker run --rm -v infra_loki-data:/loki alpine chown -R 10001:10001 /loki
> docker compose start loki
> ```
> Esto pasa cuando el volumen fue creado con permisos de root. Loki corre como UID 10001.

---

## Paso 5 — Sembrar la base de datos

```bash
docker exec ctf-api python seed.py --reset
```

**Salida esperada:**

```
Equipo: Bytreach       | usuario: team_01 | pass: <generado>
Equipo: MoodySploiters | usuario: team_02 | pass: <generado>
Equipo: DARKHIVE       | usuario: team_03 | pass: <generado>
Equipo: Threat Hunters | usuario: team_04 | pass: <generado>
Equipo: Capa 8         | usuario: team_05 | pass: <generado>
```

> **Guarda estas credenciales.** Son las que entregas a los capitanes de equipo.

---

## Paso 6 — Instalar hooks VPN y firewall

### 6.1 Instalar scripts en el servidor OpenVPN

```bash
sudo mkdir -p /etc/openvpn/scripts
sudo cp /opt/HL4-INSANE/vpn/scripts/on-connect.sh    /etc/openvpn/scripts/
sudo cp /opt/HL4-INSANE/vpn/scripts/on-disconnect.sh /etc/openvpn/scripts/
sudo cp /opt/HL4-INSANE/vpn/scripts/ban-team.sh       /etc/openvpn/scripts/
sudo cp /opt/HL4-INSANE/vpn/scripts/revoke-team.sh    /etc/openvpn/scripts/
sudo cp /opt/HL4-INSANE/vpn/scripts/apply-firewall.sh /etc/openvpn/scripts/
sudo cp /opt/HL4-INSANE/vpn/scripts/unban.sh          /etc/openvpn/scripts/
sudo chmod +x /etc/openvpn/scripts/*.sh
```

**Comportamiento de `on-connect.sh`:**
- Verifica si el equipo está baneado (Redis `ban:{team}`)
- Aplica política **1 cert = 1 conexión activa** (Redis `vpn:connected:{CN}`)
- Permite reconexión si hay **grace period activo** (Redis `vpn:grace:{CN}`, TTL 120s)
- Si dos personas usan el mismo `.ovpn` simultáneamente, la segunda es rechazada
- Emite evento SIEM y log de conexión

**Comportamiento de `on-disconnect.sh`:**
- Borra `vpn:connected:{CN}` inmediatamente
- Crea `vpn:grace:{CN}` con TTL de 120 segundos
- Cuenta desconexiones "limpias" para el sistema de ban automático

### 6.2 Aplicar reglas de firewall (bloquea internet a jugadores)

```bash
sudo bash /etc/openvpn/scripts/apply-firewall.sh
```

**Verificar que las reglas están activas:**

```bash
sudo nft list chain ip filter DOCKER-USER
```

Salida esperada:

```nft
chain DOCKER-USER {
    ip saddr 10.10.0.0/16 ip daddr 10.10.100.0/24 accept  # platform CTF
    ip saddr 10.10.1.0/24 ip daddr 172.30.1.0/24  accept  # team_01 challenges
    ip saddr 10.10.2.0/24 ip daddr 172.30.2.0/24  accept  # team_02 challenges
    ip saddr 10.10.3.0/24 ip daddr 172.30.3.0/24  accept  # team_03 challenges
    ip saddr 10.10.4.0/24 ip daddr 172.30.4.0/24  accept  # team_04 challenges
    ip saddr 10.10.5.0/24 ip daddr 172.30.5.0/24  accept  # team_05 challenges
    ip saddr 10.10.0.0/16 drop                             # bloquea internet/IA
}
```

> **Por qué esto funciona aunque el jugador use un proxy:**  
> `redirect-gateway def1` en el servidor fuerza TODO el tráfico del cliente por el túnel VPN.
> El proxy del jugador también tiene que salir por el VPN, y su tráfico a internet es bloqueado
> por la regla `drop`. Los jugadores no pueden alcanzar ChatGPT, Claude, proxies web, Tor ni
> DNS-over-HTTPS.

### 6.3 Persistir el firewall tras reinicios

```bash
sudo tee /etc/systemd/system/ctf-firewall.service << 'EOF'
[Unit]
Description=CTF VPN firewall rules
After=docker.service openvpn@server.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/etc/openvpn/scripts/apply-firewall.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable ctf-firewall.service
```

### 6.4 DNS sinkhole para dominios de IA

```bash
sudo mkdir -p /etc/dnsmasq.d
sudo tee /etc/dnsmasq.d/ctf-sinkhole.conf << 'EOF'
# Escuchar en interfaz VPN
interface=tun0
bind-interfaces

# Dominios de IA → 0.0.0.0 (bloqueo DNS)
address=/openai.com/0.0.0.0
address=/chatgpt.com/0.0.0.0
address=/claude.ai/0.0.0.0
address=/anthropic.com/0.0.0.0
address=/gemini.google.com/0.0.0.0
address=/copilot.microsoft.com/0.0.0.0
address=/huggingface.co/0.0.0.0
address=/perplexity.ai/0.0.0.0
address=/bard.google.com/0.0.0.0

# Bloquear DNS-over-HTTPS conocidos
address=/cloudflare-dns.com/0.0.0.0
address=/dns.google/0.0.0.0
address=/dns64.dns.google/0.0.0.0
address=/doh.opendns.com/0.0.0.0
EOF

sudo systemctl restart dnsmasq
sudo systemctl enable dnsmasq
```

---

## Paso 7 — Distribuir archivos .ovpn

Los archivos `.ovpn` están en `/etc/openvpn/clients/`. Distribución por equipo:

| Equipo | p1 | p2 | p3 | p4 |
|--------|-----|-----|-----|-----|
| Bytreach | sh4dowxz | gorje | AlarmW | kincito |
| MoodySploiters | quimichin | Aulloaal | Marinex | NA787 |
| DARKHIVE | ast4x | NoTtrebor | Italo | Onhubxx |
| Threat Hunters | vulc4nx | APT404 | m4thv | K4w0rU2 |
| Capa 8 | SonyB0t | rafooo\_6 | Fetuccini | Michi |

> Cada jugador recibe **su propio archivo** (ej: `team_01_p1.ovpn` para sh4dowxz de Bytreach).
> No compartir archivos entre jugadores — el certificado identifica al jugador en el SIEM.

**Instrucciones para jugadores:**
1. **Windows:** Instalar OpenVPN GUI → importar el `.ovpn` → conectar
2. **macOS:** Instalar Tunnelblick → importar el `.ovpn` → conectar
3. **Linux:** `sudo openvpn --config team_XX_pY.ovpn`
4. Una vez conectado, la plataforma CTF estará en `http://10.10.100.10`

---

## URLs y credenciales

### Acceso público

| URL | Descripción |
|-----|-------------|
| `http://VPS_IP` | Plataforma CTF (jugadores con VPN activa) |
| `http://VPS_IP:8090` | SIEM público — scoreboard, actividad en vivo |
| `http://VPS_IP:8090/streams` | Vista SIEM para casters/OBS |

### Acceso admin (requiere túnel SSH)

Abrir el túnel antes de acceder:
```bash
ssh -L 3000:localhost:3000 -L 8091:localhost:8091 user@VPS_IP
```

| URL local | Descripción | Credenciales |
|-----------|-------------|--------------|
| `http://localhost:3000` | Grafana | `admin / <GRAFANA_PASSWORD>` |
| `http://localhost:8091` | Admin panel | `admin / <ADMIN_PASSWORD>` |

### Dashboards Grafana

| Dashboard | Contenido |
|-----------|-----------|
| VPN Activity | Conexiones, desconexiones, rechazos, bans |
| Challenge Traffic | Peticiones HTTP a retos por equipo, en tiempo real |
| IDS Alerts | Alertas Suricata, bloqueos nftables, intentos de IA |
| Resource Monitor | CPU/RAM/red por contenedor (cAdvisor + Prometheus) |

---

## Checklist pre-CTF

Ejecutar 30 minutos antes de abrir el evento:

```bash
# 1. Todos los contenedores corriendo
docker ps --format "table {{.Names}}\t{{.Status}}" | grep ctf-

# 2. Loki responde (debe decir "ready")
docker exec ctf-loki wget -qO- http://localhost:3100/ready

# 3. API de equipos en el SIEM (deben aparecer 5 equipos)
curl -s http://localhost:8090/api/teams | python3 -m json.tool

# 4. Stats del SIEM (events debe ser ~0 en el inicio)
curl -s http://localhost:8090/api/stats

# 5. OpenVPN activo
sudo systemctl status openvpn@server --no-pager

# 6. Firewall VPN activo (debe mostrar la regla drop)
sudo nft list chain ip filter DOCKER-USER | grep drop

# 7. Equipos en DB
docker exec ctf-postgres psql -U ctf -d ctf -c \
    "SELECT team_id, display_name FROM teams ORDER BY team_id;"

# 8. Conectarse con un .ovpn de prueba y verificar:
#    - http://10.10.100.10 → debe cargar la plataforma
#    - curl -s https://google.com → debe fallar (bloqueado)
```

---

## Operaciones durante el CTF

### Ver actividad en vivo

```bash
# Conexiones VPN activas ahora mismo
sudo cat /var/log/openvpn/status.log

# Feed de eventos en tiempo real
sudo tail -f /var/log/openvpn/events.log

# Sesiones Redis activas
docker exec ctf-redis redis-cli KEYS 'vpn:connected:*'
docker exec ctf-redis redis-cli KEYS 'vpn:grace:*'
```

### Lanzar retos de un equipo

```bash
cd /opt/HL4-INSANE/infra
make launch-team TEAM=team_01   # lanza los 12 retos del equipo 01
```

### Banear un equipo (manual)

```bash
sudo bash /etc/openvpn/scripts/ban-team.sh team_03
# Bloquea login en plataforma + revoca cert VPN + mata sesión activa
```

### Desbanear un equipo

```bash
sudo bash /etc/openvpn/scripts/unban.sh team_03
```

### Reiniciar un servicio

```bash
cd /opt/HL4-INSANE/infra
docker compose restart caster-overlay   # SIEM público
docker compose restart grafana          # Dashboards
docker compose restart promtail         # Recolector de logs
docker compose restart platform-api    # Backend CTF
```

---

## Emergencias y procedimientos

### SIEM muestra avalancha de datos históricos

Ocurre cuando promtail se reinicia con un volumen de posiciones vacío.

```bash
# 1. Parar promtail
docker stop ctf-promtail

# 2. Generar positions.yaml con posición ACTUAL de cada log (marca como "ya leídos")
python3 << 'EOF'
import os, glob
with open("/tmp/positions_new.yaml", "w") as f:
    f.write("positions:\n")
    for p in [
        "/var/log/openvpn/openvpn.log", "/var/log/openvpn/status.log",
        "/var/log/openvpn/events.log",  "/var/log/syslog",
        "/var/log/suricata/eve.json",   "/var/log/dnsmasq/queries.log",
        "/var/log/kern.log"
    ]:
        for fn in glob.glob(p):
            try:
                sz = os.path.getsize(fn)
                f.write(f'  {fn}: "{sz}"\n')
            except: pass
print("OK - /tmp/positions_new.yaml generado")
EOF

# 3. Copiar al volumen de promtail
docker run --rm \
    -v infra_promtail-positions:/pos \
    -v /tmp/positions_new.yaml:/src/positions.yaml:ro \
    alpine cp /src/positions.yaml /pos/positions.yaml

# 4. Limpiar Loki (borrar datos históricos inyectados)
docker stop ctf-loki
docker run --rm -v infra_loki-data:/loki alpine sh -c \
    "rm -rf /loki/chunks/* /loki/index/* /loki/wal/* /loki/compactor/* 2>/dev/null; \
     chown -R 10001:10001 /loki"
docker compose start loki

# 5. Reiniciar promtail
docker compose start promtail
```

### Loki no arranca (permission denied)

```bash
docker stop ctf-loki
docker run --rm -v infra_loki-data:/loki alpine chown -R 10001:10001 /loki
docker compose start loki
```

### Firewall VPN perdido tras reinicio del servidor

```bash
sudo systemctl start ctf-firewall.service
# O directamente:
sudo bash /etc/openvpn/scripts/apply-firewall.sh
```

### Verificar que el bloqueo de internet funciona

```bash
# Desde un cliente conectado a la VPN, estos comandos deben FALLAR:
curl -v https://google.com           # timeout o connection refused
curl -v https://chat.openai.com      # timeout
nslookup openai.com 10.10.0.1        # debe devolver 0.0.0.0 (sinkhole)
```

### Resetear todo para una nueva ronda

```bash
cd /opt/HL4-INSANE/infra

# 1. Limpiar SIEM
docker stop ctf-loki ctf-promtail
docker run --rm -v infra_loki-data:/loki alpine sh -c \
    "rm -rf /loki/chunks/* /loki/index/* /loki/wal/*; chown -R 10001:10001 /loki"

# 2. Limpiar Redis (sesiones activas, contadores ban, grace periods)
docker exec ctf-redis redis-cli FLUSHDB

# 3. Resetear DB (nuevas flags, limpiar puntos)
docker exec ctf-api python seed.py --reset

# 4. Reiniciar SIEM
docker compose start loki
docker compose up -d --force-recreate promtail

# 5. Reaplicar firewall
sudo bash /etc/openvpn/scripts/apply-firewall.sh
```

---

## Notas de seguridad

- **1 cert = 1 conexión simultánea.** Si alguien intenta compartir su `.ovpn`, la segunda conexión es rechazada. El jugador tiene 2 minutos de gracia para reconectar tras una caída de internet.
- **Internet bloqueado a nivel de kernel.** Las reglas nftables en `DOCKER-USER` bloquean todo el tráfico VPN que no sea hacia la plataforma o los retos del equipo. No hay bypass posible desde el cliente.
- **DNS sinkhole.** Dominios de IA y DoH resuelven a `0.0.0.0` via dnsmasq. Es una segunda barrera redundante junto con nftables.
- **Aislamiento inter-equipo.** `team_01` solo puede llegar a `172.30.1.0/24`. Cruzar subredes de retos de otros equipos está bloqueado.
- **Los `.ovpn` son identidades criptográficas.** El CN del certificado identifica al jugador en el SIEM. No es posible cambiar el nombre del certificado sin revocar y regenerar.
