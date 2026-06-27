#!/usr/bin/env bash
# deploy-vps.sh — Despliegue completo de CTFHL4 - FINAL en VPS limpio
#
# USO: sudo bash deploy-vps.sh <IP_PUBLICA_DEL_VPS>
#
# Este script asume:
#   - Ubuntu 24.04 LTS fresco
#   - Ejecutado como root o con sudo
#   - El repo ya está en /opt/HL4-INSANE (o se clona aquí)
#   - El .env ya tiene los secretos configurados

set -euo pipefail

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
SERVER_IP="${1:-}"
REPO_DIR="${REPO_DIR:-/opt/HL4-INSANE}"
LOG_FILE="/var/log/ctf-deploy.log"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; BLU='\033[0;34m'; NC='\033[0m'

log()  { echo -e "${BLU}[$(date +%H:%M:%S)]${NC} $*" | tee -a "$LOG_FILE"; }
ok()   { echo -e "${GRN}  ✓ $*${NC}" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YLW}  ⚠ $*${NC}" | tee -a "$LOG_FILE"; }
fail() { echo -e "${RED}  ✗ $*${NC}" | tee -a "$LOG_FILE"; exit 1; }

separator() {
    echo "" | tee -a "$LOG_FILE"
    echo -e "${YLW}════════════════════════════════════════════════════════${NC}" | tee -a "$LOG_FILE"
    echo -e "${YLW}  $*${NC}" | tee -a "$LOG_FILE"
    echo -e "${YLW}════════════════════════════════════════════════════════${NC}" | tee -a "$LOG_FILE"
}

# ---------------------------------------------------------------------------
# VALIDACIONES
# ---------------------------------------------------------------------------
if [[ -z "$SERVER_IP" ]]; then
    fail "Uso: sudo bash deploy-vps.sh <IP_PUBLICA_DEL_VPS>"
fi

if [[ ! -f "$REPO_DIR/infra/docker-compose.yml" ]]; then
    fail "Repositorio no encontrado en $REPO_DIR. Clona el repo primero."
fi

if [[ ! -f "$REPO_DIR/infra/.env" ]]; then
    fail ".env no encontrado en $REPO_DIR/infra/. Copia .env.example y configura los secretos."
fi

if [[ "$EUID" -ne 0 ]]; then
    fail "Este script requiere privilegios de root (sudo bash deploy-vps.sh ...)"
fi

echo "" | tee "$LOG_FILE"
echo -e "${GRN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GRN}║     CTFHL4 - FINAL · Deploy automático      ║${NC}"
echo -e "${GRN}║     IP servidor: $SERVER_IP${NC}"
echo -e "${GRN}╚══════════════════════════════════════════════╝${NC}"
echo ""

# ---------------------------------------------------------------------------
# PASO 0: Sistema
# ---------------------------------------------------------------------------
separator "PASO 0 — Dependencias del sistema"

log "Actualizando apt..."
apt update -qq && apt upgrade -y -qq
ok "Sistema actualizado"

log "Instalando dependencias..."
apt install -y -qq \
    git curl wget \
    docker.io docker-compose-plugin \
    openvpn easy-rsa \
    nftables \
    redis-tools \
    python3 python3-pip \
    dnsmasq \
    netcat-openbsd
ok "Dependencias instaladas"

# ip_forward
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
sysctl -p -q
ok "ip_forward habilitado"

# Directorio de logs OpenVPN
mkdir -p /var/log/openvpn
chmod 755 /var/log/openvpn
ok "Directorios de logs creados"

# Docker socket accesible sin sudo para el usuario que ejecutó sudo
SUDO_USER_NAME="${SUDO_USER:-$USER}"
if id "$SUDO_USER_NAME" &>/dev/null; then
    usermod -aG docker "$SUDO_USER_NAME" 2>/dev/null || true
fi
ok "Usuario en grupo docker"

# ---------------------------------------------------------------------------
# PASO 1: OpenVPN PKI
# ---------------------------------------------------------------------------
separator "PASO 1 — OpenVPN: PKI y certificados"

if [[ -f /etc/openvpn/server.conf ]]; then
    warn "server.conf ya existe — saltando setup del servidor (no se sobreescribe)"
else
    log "Inicializando servidor OpenVPN con IP $SERVER_IP..."
    bash "$REPO_DIR/vpn/scripts/setup-server.sh" "$SERVER_IP"
    ok "Servidor OpenVPN configurado"
fi

# Añadir directivas adicionales si no están ya
if ! grep -q "redirect-gateway" /etc/openvpn/server.conf 2>/dev/null; then
    cat "$REPO_DIR/vpn/configs/server-additions.conf" >> /etc/openvpn/server.conf
    ok "Directivas adicionales (redirect-gateway, DNS, ban-socket) añadidas"
else
    warn "Directivas ya presentes en server.conf — saltando"
fi

# Generar certificados (5 equipos × 4 jugadores)
mkdir -p /etc/openvpn/clients
CERTS_NEEDED=0
for team in 01 02 03 04 05; do
    for player in 1 2 3 4; do
        [[ ! -f "/etc/openvpn/clients/team_${team}_p${player}.ovpn" ]] && CERTS_NEEDED=1
    done
done

if [[ "$CERTS_NEEDED" -eq 1 ]]; then
    log "Generando 20 certificados de jugadores..."
    for team in 01 02 03 04 05; do
        for player in 1 2 3 4; do
            bash "$REPO_DIR/vpn/scripts/gen-team-cert.sh" "team_${team}" "$player" "$SERVER_IP"
        done
    done
    ok "20 certificados .ovpn generados en /etc/openvpn/clients/"
else
    warn "Certificados ya existen — saltando generación"
fi

# CCD (IPs estáticas)
if [[ ! -d /etc/openvpn/ccd ]] || [[ -z "$(ls /etc/openvpn/ccd 2>/dev/null)" ]]; then
    log "Configurando IPs estáticas (CCD)..."
    bash "$REPO_DIR/vpn/scripts/setup-ccd.sh"
    ok "IPs estáticas configuradas"
else
    warn "CCD ya configurado — saltando"
fi

# Iniciar OpenVPN
log "Habilitando e iniciando OpenVPN..."
systemctl enable openvpn@server
systemctl start openvpn@server || warn "OpenVPN no pudo iniciar — revisa: systemctl status openvpn@server"
sleep 2
if systemctl is-active --quiet openvpn@server; then
    ok "OpenVPN activo"
else
    warn "OpenVPN no está activo. Continúa y verifica manualmente."
fi

# Comprimir .ovpn
OVPN_ZIP="/root/ovpn-jugadores.zip"
cd /etc/openvpn/clients
zip -q -r "$OVPN_ZIP" *.ovpn
ok "Archivos .ovpn comprimidos: $OVPN_ZIP"
cd -

# ---------------------------------------------------------------------------
# PASO 2: Docker Compose
# ---------------------------------------------------------------------------
separator "PASO 2 — Plataforma CTF (Docker Compose)"

log "Construyendo imágenes y levantando contenedores..."
cd "$REPO_DIR/infra"
docker compose up -d --build 2>&1 | tee -a "$LOG_FILE" | tail -5

log "Esperando que los contenedores estén listos (30s)..."
sleep 30

# Verificar Loki permisos
LOKI_STATUS=$(docker inspect ctf-loki --format='{{.State.Status}}' 2>/dev/null || echo "missing")
if [[ "$LOKI_STATUS" == "restarting" ]]; then
    warn "Loki en restart loop — corrigiendo permisos..."
    docker stop ctf-loki 2>/dev/null || true
    docker run --rm -v infra_loki-data:/loki alpine chown -R 10001:10001 /loki
    docker compose start loki
    sleep 10
fi

# Estado final
RUNNING=$(docker ps --filter "name=ctf-" --format "{{.Names}}" | wc -l)
ok "$RUNNING contenedores CTF corriendo"

# ---------------------------------------------------------------------------
# PASO 3: Seed de base de datos
# ---------------------------------------------------------------------------
separator "PASO 3 — Seed de base de datos"

log "Esperando que ctf-api esté healthy..."
for i in $(seq 1 12); do
    HEALTH=$(docker inspect ctf-api --format='{{.State.Health.Status}}' 2>/dev/null || echo "unknown")
    [[ "$HEALTH" == "healthy" ]] && break
    sleep 5
done

log "Ejecutando seed.py --reset..."
docker exec ctf-api python seed.py --reset | tee -a "$LOG_FILE"
ok "Base de datos sembrada con 5 equipos y 60 retos"

# ---------------------------------------------------------------------------
# PASO 4: Scripts VPN y Firewall
# ---------------------------------------------------------------------------
separator "PASO 4 — Scripts VPN y reglas de firewall"

log "Instalando scripts en /etc/openvpn/scripts/..."
mkdir -p /etc/openvpn/scripts
for script in on-connect.sh on-disconnect.sh ban-team.sh revoke-team.sh apply-firewall.sh unban.sh; do
    if [[ -f "$REPO_DIR/vpn/scripts/$script" ]]; then
        cp "$REPO_DIR/vpn/scripts/$script" /etc/openvpn/scripts/
        chmod +x "/etc/openvpn/scripts/$script"
    fi
done
ok "Scripts VPN instalados"

log "Aplicando reglas nftables (bloqueo internet VPN)..."
bash /etc/openvpn/scripts/apply-firewall.sh
ok "Reglas nftables aplicadas"

log "Instalando servicio systemd ctf-firewall..."
cat > /etc/systemd/system/ctf-firewall.service << 'EOF'
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
systemctl daemon-reload
systemctl enable ctf-firewall.service
ok "ctf-firewall.service instalado y habilitado"

# ---------------------------------------------------------------------------
# PASO 5: DNS sinkhole de IA
# ---------------------------------------------------------------------------
separator "PASO 5 — DNS sinkhole (bloqueo IA)"

cat > /etc/dnsmasq.d/ctf-sinkhole.conf << 'EOF'
interface=tun0
bind-interfaces

address=/openai.com/0.0.0.0
address=/chatgpt.com/0.0.0.0
address=/claude.ai/0.0.0.0
address=/anthropic.com/0.0.0.0
address=/gemini.google.com/0.0.0.0
address=/copilot.microsoft.com/0.0.0.0
address=/huggingface.co/0.0.0.0
address=/perplexity.ai/0.0.0.0
address=/bard.google.com/0.0.0.0
address=/cloudflare-dns.com/0.0.0.0
address=/dns.google/0.0.0.0
address=/doh.opendns.com/0.0.0.0
EOF

systemctl restart dnsmasq 2>/dev/null || warn "dnsmasq no pudo reiniciar (revisar si está instalado)"
systemctl enable dnsmasq 2>/dev/null || true
ok "DNS sinkhole configurado"

# ---------------------------------------------------------------------------
# RESUMEN FINAL
# ---------------------------------------------------------------------------
separator "DEPLOY COMPLETADO"

echo ""
echo -e "${GRN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GRN}║                   DEPLOY EXITOSO                        ║${NC}"
echo -e "${GRN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BLU}Plataforma CTF:${NC}     http://${SERVER_IP}"
echo -e "  ${BLU}SIEM público:${NC}       http://${SERVER_IP}:8090"
echo -e "  ${BLU}Grafana (SSH):${NC}      ssh -L 3000:localhost:3000 user@${SERVER_IP}"
echo -e "  ${BLU}Admin panel (SSH):${NC}  ssh -L 8091:localhost:8091 user@${SERVER_IP}"
echo ""
echo -e "  ${YLW}Archivos .ovpn:${NC}     $OVPN_ZIP"
echo -e "  ${YLW}Log del deploy:${NC}     $LOG_FILE"
echo ""
echo -e "  ${GRN}Próximos pasos:${NC}"
echo -e "    1. Verificar credenciales de equipos en ctf-api logs"
echo -e "    2. Descargar ovpn-jugadores.zip y distribuir a los equipos"
echo -e "    3. Ejecutar el checklist pre-CTF (ver docs/VPS-DEPLOY.md)"
echo ""
