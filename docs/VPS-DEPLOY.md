# CTFHL4-INSANE — Guía de Despliegue en VPS

> Estado auditado: 23 Jun 2026. IP de prueba: 192.168.200.196 → reemplazar por IP del VPS real.

---

## 0. Resumen ejecutivo

El servidor de prueba tiene todos los contenedores corriendo pero requiere 5 fixes antes de estar listo para el CTF:

| # | Problema | Estado | Acción |
|---|---|---|---|
| 1 | DB sin equipos (teams table vacía) | BLOQUEANTE | `seed.py --reset` |
| 2 | SIEM muestra historial ficticio | BLOQUEANTE | Limpiar Loki + fix promtail |
| 3 | `on-connect.sh` versión vieja (team_id incorrecto en Loki) | CRÍTICO | Copiar desde repo |
| 4 | Contenedores ctf_team_06-10 activos (9 días) | LIMPIEZA | `docker stop` + `rm` |
| 5 | Git pull pendiente (cambios locales no están en servidor) | REQUERIDO | `git pull` |

---

## 1. Prerequisitos del VPS

```bash
# Sistema operativo
Ubuntu 22.04 o 24.04 LTS (x86_64)

# Paquetes
sudo apt install -y docker.io docker-compose-plugin git redis-tools curl

# Docker sin sudo (opcional pero cómodo)
sudo usermod -aG docker $USER && newgrp docker

# OpenVPN
sudo apt install -y openvpn easy-rsa

# Python (para el seed)
sudo apt install -y python3-pip
```

---

## 2. Estructura de directorios esperada

```
/home/hackl4bs/Descargas/HL4-INSANE/    ← raíz del repo
├── infra/
│   ├── docker-compose.yml
│   ├── .env                             ← SECRETOS (no subir a git)
│   ├── nginx/nginx.conf
│   └── monitoring/prometheus.yml
├── platform/
│   ├── backend/
│   └── frontend/
├── siem/
│   ├── caster-overlay/
│   ├── collector/
│   ├── admin-panel/
│   ├── grafana/
│   ├── loki/
│   └── promtail/
├── vpn/
│   ├── scripts/
│   └── configs/
├── challenges/
│   ├── web/
│   ├── api/
│   ├── crypto/
│   ├── pwn/
│   └── reversing/
└── flag-service/
```

---

## 3. Primer deploy (VPS limpio)

### 3.1 Clonar repo

```bash
cd /home/$USER/Descargas
git clone <URL-REPO> HL4-INSANE
cd HL4-INSANE
```

### 3.2 Crear archivo .env

```bash
cat > infra/.env << 'EOF'
MASTER_SECRET=$(openssl rand -hex 32)
JWT_SECRET=$(openssl rand -hex 32)
GRAFANA_PASSWORD=$(openssl rand -hex 12)
POSTGRES_PASSWORD=$(openssl rand -hex 16)
ADMIN_PASSWORD=$(openssl rand -hex 24)
DISCORD_WEBHOOK_URL=
CTF_NAME=CTFHL4-INSANE
EOF
```

> Las credenciales del servidor de prueba están guardadas. En VPS nuevo generar nuevas.

### 3.3 Configurar OpenVPN

```bash
cd vpn/

# Generar PKI y certificados del servidor
sudo bash scripts/setup-server.sh

# Aplicar directivas adicionales (gateway total, DNS, hooks SIEM)
sudo bash -c 'cat configs/server-additions.conf >> /etc/openvpn/server.conf'

# Copiar scripts de cliente a OpenVPN
sudo mkdir -p /etc/openvpn/scripts
sudo cp scripts/on-connect.sh scripts/on-disconnect.sh \
       scripts/ban-team.sh scripts/unban.sh \
       scripts/revoke-team.sh /etc/openvpn/scripts/
sudo chmod +x /etc/openvpn/scripts/*.sh

# Generar certificados por equipo (25 archivos .ovpn: 5 equipos × 5 certs)
for team in 01 02 03 04 05; do
    sudo bash scripts/gen-team-cert.sh $team 4   # 4 jugadores
done

# Generar directorios CCD (IPs fijas por equipo)
sudo bash scripts/setup-ccd.sh

# Crear directorio de logs
sudo mkdir -p /var/log/openvpn
sudo touch /var/log/openvpn/events.log

# Iniciar OpenVPN
sudo systemctl enable openvpn@server
sudo systemctl start openvpn@server
sudo systemctl status openvpn@server
```

### 3.4 Levantar la plataforma

```bash
cd infra/
docker compose up -d --build
```

> Primera vez tarda 3-5 minutos (descarga imágenes + build).

### 3.5 Poblar la base de datos

```bash
# Esperar a que postgres esté listo
docker exec ctf-postgres pg_isready -U ctf

# Seed: crea 5 equipos + 60 retos + assignments anti-cheat
docker exec ctf-api python seed.py --reset

# Verificar
docker exec ctf-postgres psql -U ctf -d ctf -c "SELECT team_id, display_name FROM teams;"
docker exec ctf-postgres psql -U ctf -d ctf -c "SELECT COUNT(*) FROM challenges;"
```

### 3.6 Distribuir archivos .ovpn a los equipos

```bash
# Crear el tar (los .ovpn están en /etc/openvpn/clients/)
sudo tar -czf ~/ovpn-ctf-teams.tar.gz -C /etc/openvpn/clients \
    team_01_p1.ovpn team_01_p2.ovpn team_01_p3.ovpn team_01_p4.ovpn \
    team_02_p1.ovpn team_02_p2.ovpn team_02_p3.ovpn team_02_p4.ovpn \
    team_03_p1.ovpn team_03_p1.ovpn team_03_p3.ovpn team_03_p4.ovpn \
    team_04_p1.ovpn team_04_p2.ovpn team_04_p3.ovpn team_04_p4.ovpn \
    team_05_p1.ovpn team_05_p2.ovpn team_05_p3.ovpn team_05_p4.ovpn

# Descargar desde tu máquina
scp hackl4bs@VPS_IP:~/ovpn-ctf-teams.tar.gz .
```

**Distribución por equipo:**

| Equipo | Archivos .ovpn | Capitán |
|---|---|---|
| Bytreach | `team_01_p1` (cap), `team_01_p2`, `p3`, `p4` | sh4dowxz |
| MoodySploiters | `team_02_p1` (cap), `p2`, `p3`, `p4` | quimichin |
| DARKHIVE | `team_03_p1` (cap), `p2`, `p3`, `p4` | ast4x |
| Threat Hunters | `team_04_p1` (cap), `p2`, `p3`, `p4` | vulc4nx |
| Capa 8 | `team_05_p1` (cap), `p2`, `p3`, `p4` | SonyB0t |

---

## 4. URLs y credenciales del sistema

### URLs públicas (accesibles desde internet / VPN)

| Servicio | URL | Notas |
|---|---|---|
| **Plataforma CTF** | `http://VPS_IP/` | Frontend Next.js |
| **SIEM Caster (stream)** | `http://VPS_IP:8090/` | Vista comentaristas |
| **SIEM Streams (OBS)** | `http://VPS_IP:8090/streams` | Para OBS browser source |

### URLs privadas (solo con túnel SSH)

```bash
# Grafana
ssh -L 3000:localhost:3000 hackl4bs@VPS_IP
# → http://localhost:3000   usuario: admin   contraseña: ver .env GRAFANA_PASSWORD

# Admin Panel
ssh -L 8091:localhost:8091 hackl4bs@VPS_IP
# → http://localhost:8091   contraseña: ver .env ADMIN_PASSWORD

# Prometheus (debug)
ssh -L 9090:localhost:9090 hackl4bs@VPS_IP
# → http://localhost:9090
```

### Credenciales del servidor de prueba (CAMBIAR EN VPS REAL)

```
Grafana:     admin / 173d88244f9ec811631063c3
Admin panel: c6ab5c8c0dd6bea159b4d1988e5bcd44397fc85b297ba9fc
```

---

## 5. FIXES INMEDIATOS (servidor de prueba 192.168.200.196)

Ejecutar en orden en el servidor:

### Fix 1 — Copiar on-connect.sh correcto

```bash
# El script en /etc/openvpn/scripts/ es una versión antigua que no extrae
# el team_id del CN: escribe team=team_01_p1 en lugar de team=team_01.
# Esto rompe los dashboards de Grafana VPN.

sudo cp /home/hackl4bs/Descargas/HL4-INSANE/vpn/scripts/on-connect.sh \
        /etc/openvpn/scripts/on-connect.sh
sudo cp /home/hackl4bs/Descargas/HL4-INSANE/vpn/scripts/on-disconnect.sh \
        /etc/openvpn/scripts/on-disconnect.sh
sudo chmod +x /etc/openvpn/scripts/on-connect.sh \
              /etc/openvpn/scripts/on-disconnect.sh

# Verificar que ahora tiene la extracción del team_id
grep -A3 'Extrae team_id' /etc/openvpn/scripts/on-connect.sh
```

### Fix 2 — Seed de la base de datos (BLOQUEANTE: equipos vacíos)

```bash
docker exec ctf-api python seed.py --reset
# Salida esperada: "Seeded 5 teams, 60 challenges, 60 assignments"

# Verificar
docker exec ctf-postgres psql -U ctf -d ctf -tAc \
    "SELECT team_id, display_name FROM teams ORDER BY id;"
```

### Fix 3 — Limpiar historial SIEM (Loki + promtail)

```bash
# PROBLEMA: promtail guardaba positions.yaml en /tmp (borrado en cada restart),
# así que en cada reinicio re-lee TODOS los logs históricos y los empuja a Loki
# como eventos nuevos. El caster los muestra como actividad "actual".

# SOLUCIÓN: parar, limpiar datos Loki, reiniciar con el nuevo compose
# (que ya monta promtail-positions en un volumen persistente).

# Paso 1: parar loki y promtail
sudo docker stop ctf-loki ctf-promtail

# Paso 2: limpiar datos históricos de Loki
# (conserva la configuración, solo borra los datos de logs)
sudo docker run --rm -v infra_loki-data:/loki alpine \
    sh -c 'rm -rf /loki/chunks /loki/index /loki/boltdb-shipper-active /loki/wal; \
           mkdir -p /loki/chunks /loki/index; echo "Loki limpio"'

# Paso 3: hacer git pull para traer los cambios de código
cd /home/hackl4bs/Descargas/HL4-INSANE
git pull

# Paso 4: rebuild y reiniciar (aplica el nuevo promtail-config con posición persistente)
cd infra/
docker compose up -d --build loki promtail caster-overlay

# Verificar que loki está vacío
curl -s http://localhost:3100/loki/api/v1/labels
# Debe devolver: {"status":"success","data":[]}

# Verificar que el caster ahora muestra 0 eventos
curl -s http://localhost:8090/api/stats
# "total_events":0 o muy pocos (solo conexiones recientes)
```

### Fix 4 — Limpiar contenedores y redes de equipos 06-10

```bash
# Detener y eliminar contenedores de equipos 06-10
for n in 06 07 08 09 10; do
    docker ps -q --filter "name=ctf_team_${n}_" | xargs -r docker stop
    docker ps -aq --filter "name=ctf_team_${n}_" | xargs -r docker rm
    echo "team_$n: cleaned"
done

# También limpiar team_01 stopped (de la sesión de prueba)
docker ps -aq --filter "name=ctf_team_01_" --filter "status=exited" | xargs -r docker rm

# Eliminar redes de equipos 06-10 (ya no existen)
for n in 06 07 08 09 10; do
    docker network rm ctf_team_$n 2>/dev/null && echo "network $n removed" || true
done

# También limpiar ctf_team_01 si existe (se recreará cuando un jugador lo pida)
docker network rm ctf_team_01 2>/dev/null || true
```

### Fix 5 — Limpiar Redis (sesiones viejas)

```bash
docker exec ctf-redis redis-cli DEL sessions:team_01
docker exec ctf-redis redis-cli DEL vpn:disc:team_01
docker exec ctf-redis redis-cli KEYS '*'
# Debe devolver (empty list or set)
```

---

## 6. Flujo de actualización (cuando hay cambios de código)

```bash
cd /home/hackl4bs/Descargas/HL4-INSANE

# 1. Traer cambios
git pull

# 2. Rebuildar solo los servicios que cambiaron
cd infra/
docker compose up -d --build

# 3. Si hubo cambios en la DB (modelos/seed):
docker exec ctf-api python seed.py --reset

# 4. Si se modificó el server.conf de OpenVPN:
sudo systemctl restart openvpn@server
```

---

## 7. Monitoreo durante el CTF

### Verificar estado general

```bash
# Todos los contenedores deben estar "Up"
docker ps --format 'table {{.Names}}\t{{.Status}}'

# Redis: no debe haber bans inesperados
docker exec ctf-redis redis-cli KEYS 'ban:*'

# Logs VPN en tiempo real
sudo tail -f /var/log/openvpn/events.log

# Logs del collector (eventos SIEM entrantes)
docker logs ctf-collector -f

# Logs del caster overlay
docker logs ctf-caster -f
```

### Dashboards Grafana (túnel SSH al :3000)

| Dashboard | Qué muestra |
|---|---|
| VPN Activity | Conexiones/desconexiones/bans por equipo |
| Flag Submissions | OK vs FAIL + anti-cheat flag-share |
| Challenge Traffic | Peticiones a retos por equipo |
| Recursos (cAdvisor) | CPU/RAM de contenedores por equipo |

### Banear un equipo manualmente

```bash
# Ver estado
docker exec ctf-redis redis-cli KEYS 'vpn:disc:*'

# Banear equipo 3 (DARKHIVE)
sudo /etc/openvpn/scripts/ban-team.sh team_03

# Desbanear
sudo /etc/openvpn/scripts/unban.sh team_03
```

---

## 8. Resolución de problemas comunes

### "Los jugadores no pueden iniciar instancias"

```bash
# 1. Verificar que /challenges está montado correctamente
docker exec ctf-api ls /challenges/

# 2. Verificar que el equipo tiene retos asignados
docker exec ctf-postgres psql -U ctf -d ctf -c \
    "SELECT challenge_id FROM team_challenge_assignments WHERE team_id='team_01';"

# 3. Ver logs de la API al hacer start
docker logs ctf-api --tail 30
```

### "El SIEM vuelve a mostrar historial viejo"

Causa: Se reinició el contenedor de promtail y el volumen `promtail-positions` fue borrado o no está montado.

```bash
# Verificar que el volumen existe
docker volume ls | grep promtail-positions

# Si no existe, docker compose lo crea automáticamente en el siguiente up
docker compose up -d promtail
```

### "Grafana no muestra datos de VPN"

Verificar en orden:
1. `sudo systemctl status openvpn@server` — debe estar active
2. `sudo tail -5 /var/log/openvpn/events.log` — deben aparecer connects al conectar un cliente
3. `docker logs ctf-collector --tail 10` — deben verse los POSTs de eventos
4. `curl http://localhost:3100/loki/api/v1/label/source/values` — debe incluir "vpn"

### "La plataforma muestra 404 en /api/teams"

La plataforma no tiene endpoint `/teams` — el frontend usa `/scoreboard` para ver puntuaciones. El error 404 puede ser una llamada legacy del frontend. No afecta el funcionamiento.

### "seed.py falla con error de migración"

```bash
# Resetear la DB completamente
docker exec ctf-postgres psql -U ctf -c "DROP DATABASE ctf;"
docker exec ctf-postgres psql -U ctf -c "CREATE DATABASE ctf;"
docker restart ctf-api   # init_db() crea las tablas en el lifespan
sleep 5
docker exec ctf-api python seed.py --reset
```

---

## 9. Checklist pre-CTF

```
[ ] git pull en el servidor con los últimos cambios
[ ] docker compose up -d --build (rebuild completo)
[ ] docker exec ctf-api python seed.py --reset
[ ] Verificar 5 equipos en DB
[ ] Verificar 60 retos en DB
[ ] Verificar /challenges montado en ctf-api
[ ] sudo systemctl status openvpn@server → active
[ ] grep 'client-connect' /etc/openvpn/server.conf → debe existir
[ ] Conectar un .ovpn de prueba → ver entrada en /var/log/openvpn/events.log
[ ] Abrir http://VPS_IP:8090/ → caster overlay visible
[ ] Abrir http://VPS_IP:8090/streams → página de OBS visible
[ ] Túnel SSH a :3000 → Grafana login ok
[ ] Túnel SSH a :8091 → Admin panel login ok
[ ] Loki limpio (events_total ~ 0)
[ ] Redis sin bans ni sesiones viejas
[ ] Distribuir .ovpn a capitanes de equipo
[ ] Confirmar que cada equipo puede hacer login en la plataforma
[ ] Confirmar que cada equipo ve SUS retos (no los de otros)
```

---

## 10. Arquitectura de red

```
Internet / Jugadores
    │
    ▼
VPS IP pública
    ├── :80/443 → nginx → platform frontend + API
    ├── :1194/UDP → OpenVPN
    └── :8090 → caster-overlay (SIEM público)

Dentro del VPS (subnets Docker):
    10.10.N.0/24 (N=1..5)  ← jugadores por equipo vía VPN tun0
    10.10.100.0/24          ← plataforma (nginx, api, postgres, redis, flag-svc)
    10.10.200.0/24          ← SIEM privado (loki, grafana, collector, admin-panel)

Redes Docker de retos (on-demand):
    172.30.N.0/24           ← containers del equipo N (creados al hacer "Start")
    ctf_team_0N             ← nombre de la red Docker
```
