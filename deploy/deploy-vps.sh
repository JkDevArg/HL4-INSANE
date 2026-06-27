#!/usr/bin/env bash
# =============================================================================
#  deploy-vps.sh — Instalación completa de CTFHL4-INSANE en servidor limpio
#
#  USO:
#    sudo bash deploy-vps.sh <IP_PUBLICA_DEL_SERVIDOR>
#
#  QUÉ HACE (en orden):
#    0. Instala dependencias del sistema
#    1. Configura OpenVPN (PKI, server.conf, certificados por jugador, CCD)
#    2. Configura NAT + IP forwarding
#    3. Instala scripts VPN en /etc/openvpn/scripts/
#    4. Aplica reglas nftables (firewall CTF)
#    5. Configura dnsmasq (sinkhole DNS de IAs)
#    6. Levanta Docker Compose (plataforma + SIEM)
#    7. Siembra base de datos (equipos + retos)
#    8. Instala servicio systemd para persistir el firewall al reinicio
#    9. Imprime resumen con URLs y ubicación de los .ovpn
#
#  PRERREQUISITOS:
#    - Ubuntu 22.04 LTS
#    - Ejecutado como root (o sudo)
#    - Repo clonado (el script lo clona si no existe)
#    - infra/.env configurado (se genera interactivamente si no existe)
#
#  IDEMPOTENTE: cada paso verifica si ya está hecho antes de ejecutar.
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# CONFIG GLOBAL
# -----------------------------------------------------------------------------
SERVER_IP="${1:-}"
VPN_PORT="${VPN_PORT:-1194}"
VPN_PROTO="${VPN_PROTO:-udp}"
REPO_URL="https://github.com/JkDevArg/HL4-INSANE.git"
# Auto-detecta el repo: el script vive en <repo>/deploy/deploy-vps.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
LOG_FILE="/var/log/ctf-deploy.log"
OVPN_DIR="/etc/openvpn/clients"
SCRIPTS_DIR="/etc/openvpn/scripts"
CCD_DIR="/etc/openvpn/ccd"

# Colores
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
BLU='\033[0;34m'; CYN='\033[0;36m'; NC='\033[0m'

# -----------------------------------------------------------------------------
# HELPERS
# -----------------------------------------------------------------------------
log()  { echo -e "${BLU}[$(date +%H:%M:%S)]${NC} $*" | tee -a "$LOG_FILE"; }
ok()   { echo -e "${GRN}  ✓ $*${NC}" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YLW}  ⚠ $*${NC}" | tee -a "$LOG_FILE"; }
fail() { echo -e "${RED}  ✗ $*${NC}" | tee -a "$LOG_FILE"; exit 1; }
step() {
    echo "" | tee -a "$LOG_FILE"
    echo -e "${CYN}══════════════════════════════════════════════════════${NC}" | tee -a "$LOG_FILE"
    echo -e "${CYN}  $*${NC}" | tee -a "$LOG_FILE"
    echo -e "${CYN}══════════════════════════════════════════════════════${NC}" | tee -a "$LOG_FILE"
}

# Sanitiza un nombre para usarlo como CN de certificado (sin espacios ni chars especiales)
sanitize_cn() {
    echo "$1" | tr '[:upper:]' '[:lower:]' \
              | sed 's/[^a-z0-9_-]/_/g' \
              | sed 's/__*/_/g' \
              | sed 's/^_//;s/_$//'
}

# -----------------------------------------------------------------------------
# VALIDACIONES PREVIAS
# -----------------------------------------------------------------------------
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

echo "" | tee "$LOG_FILE"
echo -e "${GRN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GRN}║      CTFHL4-INSANE · Deploy automático      ║${NC}"
echo -e "${GRN}╚══════════════════════════════════════════════╝${NC}"
echo ""

[[ -z "$SERVER_IP" ]] && fail "Uso: sudo bash deploy-vps.sh <IP_PUBLICA_DEL_SERVIDOR>"
[[ "$EUID" -ne 0 ]]   && fail "Ejecutar como root: sudo bash deploy-vps.sh $SERVER_IP"

# Verificar Ubuntu 22.04
if ! grep -q "22.04\|24.04" /etc/os-release 2>/dev/null; then
    warn "Este script está probado en Ubuntu 22.04/24.04. Continúa bajo tu responsabilidad."
fi

log "Servidor: $SERVER_IP | Repo: $REPO_DIR | Log: $LOG_FILE"

# =============================================================================
# PASO 0 — Dependencias del sistema
# =============================================================================
step "PASO 0 — Dependencias del sistema"

log "Actualizando apt..."
apt-get update -qq
apt-get upgrade -y -qq 2>/dev/null | tail -1

log "Instalando paquetes necesarios..."
# Instalar en bloques: si uno falla, el error es visible (sin -qq aquí)
apt-get install -y git curl wget unzip jq zip nftables redis-tools dnsmasq netcat-openbsd
ok "Herramientas base instaladas"

# OpenVPN + EasyRSA
apt-get install -y openvpn easy-rsa
ok "OpenVPN + EasyRSA instalados"

# Docker: intentar docker.io + plugin; si falla instalar solo docker.io
if apt-get install -y docker.io docker-compose-plugin 2>/dev/null; then
    ok "Docker + docker compose plugin instalados"
elif apt-get install -y docker.io docker-compose 2>/dev/null; then
    ok "Docker + docker-compose (legacy) instalados"
    # Crear alias para que 'docker compose' funcione con el binario legacy
    ln -sf /usr/bin/docker-compose /usr/local/bin/docker-compose 2>/dev/null || true
else
    fail "No se pudo instalar Docker. Instálalo manualmente y vuelve a ejecutar."
fi
ok "Todas las dependencias instaladas"

# IP forwarding
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
sysctl -w net.ipv4.ip_forward=1 -q
ok "IP forwarding habilitado"

# Logs OpenVPN
mkdir -p /var/log/openvpn /var/log/dnsmasq
chmod 755 /var/log/openvpn /var/log/dnsmasq

# Usuario en grupo docker
SUDO_USER_NAME="${SUDO_USER:-}"
if [[ -n "$SUDO_USER_NAME" ]] && id "$SUDO_USER_NAME" &>/dev/null; then
    usermod -aG docker "$SUDO_USER_NAME" 2>/dev/null || true
fi
ok "Entorno preparado"

# =============================================================================
# PASO 1 — Clonar / actualizar repositorio
# =============================================================================
step "PASO 1 — Repositorio"

if [[ -d "$REPO_DIR/.git" ]]; then
    log "Repositorio existente en $REPO_DIR — actualizando..."
    git -C "$REPO_DIR" pull --ff-only 2>/dev/null || warn "No se pudo actualizar el repo (puede haber cambios locales)"
    ok "Repo actualizado"
else
    log "Clonando $REPO_URL en $REPO_DIR..."
    git clone "$REPO_URL" "$REPO_DIR"
    ok "Repo clonado"
fi

# Configurar .env si no existe
if [[ ! -f "$REPO_DIR/infra/.env" ]]; then
    log "Generando infra/.env con secretos aleatorios..."
    cp "$REPO_DIR/infra/.env.example" "$REPO_DIR/infra/.env"
    # Reemplazar placeholders con valores aleatorios
    MASTER_SECRET=$(openssl rand -hex 32)
    JWT_SECRET=$(openssl rand -hex 32)
    POSTGRES_PASSWORD=$(openssl rand -hex 16)
    GRAFANA_PASSWORD=$(openssl rand -hex 12)
    ADMIN_PASSWORD=$(openssl rand -hex 12)
    sed -i "s|cambia_esto_por_string_aleatorio_de_64_chars|${MASTER_SECRET}|g" "$REPO_DIR/infra/.env"
    sed -i "s|cambia_esto_por_otro_secreto_largo|${JWT_SECRET}|g"              "$REPO_DIR/infra/.env"
    sed -i "s|cambia_esta_password_de_db|${POSTGRES_PASSWORD}|g"               "$REPO_DIR/infra/.env"
    sed -i "s|pon_password_seguro_aqui|${GRAFANA_PASSWORD}|g"                  "$REPO_DIR/infra/.env"
    sed -i "s|pon_password_admin_del_panel_aqui|${ADMIN_PASSWORD}|g"           "$REPO_DIR/infra/.env"
    ok ".env generado con secretos aleatorios"
    warn "Guarda los secretos: cat $REPO_DIR/infra/.env"
else
    ok ".env ya existe — no se sobreescribe"
fi

# =============================================================================
# PASO 2 — OpenVPN: PKI y servidor
# =============================================================================
step "PASO 2 — OpenVPN: PKI y servidor"

if [[ -f /etc/openvpn/server.conf ]]; then
    warn "server.conf ya existe — saltando inicialización de PKI"
else
    log "Inicializando servidor OpenVPN (IP: $SERVER_IP, puerto: $VPN_PORT/$VPN_PROTO)..."
    bash "$REPO_DIR/vpn/scripts/setup-server.sh" "$SERVER_IP" "$VPN_PORT" "$VPN_PROTO"
    ok "Servidor OpenVPN configurado"
fi

# Añadir directivas adicionales (redirect-gateway, DNS, hooks SIEM)
if ! grep -q "redirect-gateway" /etc/openvpn/server.conf 2>/dev/null; then
    log "Añadiendo directivas adicionales al server.conf..."
    cat "$REPO_DIR/vpn/configs/server-additions.conf" >> /etc/openvpn/server.conf
    ok "Directivas añadidas (redirect-gateway, DNS sinkhole, ban-socket)"
else
    ok "Directivas ya presentes en server.conf"
fi

# =============================================================================
# PASO 3 — OpenVPN: certificados por jugador
# =============================================================================
step "PASO 3 — Certificados VPN por jugador"

mkdir -p "$OVPN_DIR"
TEAMS_JSON="$REPO_DIR/vpn/teams.json"

if [[ -f "$TEAMS_JSON" ]]; then
    log "Generando certificados desde $TEAMS_JSON..."
    N_TEAMS=$(jq '.teams | length' "$TEAMS_JSON")
    for idx in $(seq 0 $((N_TEAMS-1))); do
        TEAM_ID=$(jq -r ".teams[$idx].id" "$TEAMS_JSON")
        TEAM_TAG="team_$(printf '%02d' "$TEAM_ID")"
        N_PLAYERS=$(jq ".teams[$idx].players | length" "$TEAMS_JSON")
        for pidx in $(seq 0 $((N_PLAYERS-1))); do
            RAW_PLAYER=$(jq -r ".teams[$idx].players[$pidx]" "$TEAMS_JSON")
            PLAYER_CN=$(sanitize_cn "$RAW_PLAYER")
            CN="${TEAM_TAG}_${PLAYER_CN}"
            OVPN_FILE="$OVPN_DIR/${CN}.ovpn"
            if [[ -f "$OVPN_FILE" ]]; then
                ok "  $CN — ya existe, saltando"
                continue
            fi
            log "  Generando cert para $CN..."
            bash "$REPO_DIR/vpn/scripts/gen-team-cert.sh" "$CN" "$SERVER_IP" "$VPN_PORT" "$VPN_PROTO" "$OVPN_DIR"
            ok "  $CN.ovpn generado"
        done
    done
else
    warn "teams.json no encontrado — generando certs genéricos (team_NN_pM)"
    for team in 01 02 03 04 05; do
        for player in 1 2 3 4; do
            CN="team_${team}_p${player}"
            OVPN_FILE="$OVPN_DIR/${CN}.ovpn"
            [[ -f "$OVPN_FILE" ]] && continue
            log "  Generando cert para $CN..."
            bash "$REPO_DIR/vpn/scripts/gen-team-cert.sh" "$CN" "$SERVER_IP" "$VPN_PORT" "$VPN_PROTO" "$OVPN_DIR"
        done
    done
fi

# Comprimir todos los .ovpn para distribuir
OVPN_ZIP="/root/ovpn-jugadores-${SERVER_IP}.zip"
cd "$OVPN_DIR" && zip -q -r "$OVPN_ZIP" *.ovpn 2>/dev/null && cd -
ok "Certificados comprimidos en $OVPN_ZIP"

# =============================================================================
# PASO 3.5 — Scripts VPN (instalados ANTES de iniciar OpenVPN para que
#            server.conf pueda referenciarlos al arranque)
# =============================================================================
log "Pre-instalando scripts VPN en $SCRIPTS_DIR (requeridos por server.conf)..."
mkdir -p "$SCRIPTS_DIR"
for script in on-connect.sh on-disconnect.sh ban-team.sh unban.sh revoke-team.sh apply-firewall.sh gen-team-cert.sh; do
    SRC="$REPO_DIR/vpn/scripts/$script"
    [[ -f "$SRC" ]] || continue
    cp "$SRC" "$SCRIPTS_DIR/$script"
    chmod +x "$SCRIPTS_DIR/$script"
done
ok "Scripts VPN pre-instalados en $SCRIPTS_DIR"

# =============================================================================
# PASO 4 — OpenVPN: IPs estáticas por equipo/jugador (CCD)
# =============================================================================
step "PASO 4 — CCD: IPs estáticas por jugador"

if [[ -d "$CCD_DIR" ]] && [[ -n "$(ls "$CCD_DIR" 2>/dev/null)" ]]; then
    warn "CCD ya configurado en $CCD_DIR — saltando (borra el dir para regenerar)"
else
    log "Configurando IPs estáticas (CCD)..."
    if [[ -f "$TEAMS_JSON" ]]; then
        bash "$REPO_DIR/vpn/scripts/setup-ccd.sh" --config "$TEAMS_JSON"
    else
        bash "$REPO_DIR/vpn/scripts/setup-ccd.sh"
    fi
    ok "CCD configurado — IPs estáticas asignadas"
fi

# Iniciar OpenVPN
log "Habilitando e iniciando OpenVPN..."
systemctl enable openvpn@server 2>/dev/null || true
systemctl restart openvpn@server || warn "OpenVPN no pudo iniciar — revisa: journalctl -u openvpn@server"
sleep 3
if systemctl is-active --quiet openvpn@server; then
    ok "OpenVPN activo"
else
    warn "OpenVPN no activo. Continúa y verifica con: systemctl status openvpn@server"
fi

# =============================================================================
# PASO 5 — NAT (iptables-nft)
# =============================================================================
step "PASO 5 — NAT para clientes VPN"

IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
log "Interfaz de salida: $IFACE"

# Ubuntu 22.04 usa iptables-nft como backend.
# La regla MASQUERADE de setup-server.sh es suficiente; solo nos aseguramos.
if ! iptables -t nat -C POSTROUTING -s 10.10.0.0/16 -o "$IFACE" -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -s 10.10.0.0/16 -o "$IFACE" -j MASQUERADE
    ok "Regla MASQUERADE añadida"
else
    ok "MASQUERADE ya estaba configurado"
fi

# Persistir
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save 2>/dev/null || true
fi

# =============================================================================
# PASO 6 — Scripts VPN y firewall CTF
# =============================================================================
step "PASO 6 — Scripts VPN y reglas de firewall"

log "Actualizando scripts en $SCRIPTS_DIR (por si el repo cambió desde PASO 3.5)..."
mkdir -p "$SCRIPTS_DIR"
for script in on-connect.sh on-disconnect.sh ban-team.sh unban.sh revoke-team.sh apply-firewall.sh gen-team-cert.sh; do
    SRC="$REPO_DIR/vpn/scripts/$script"
    [[ -f "$SRC" ]] || continue
    cp "$SRC" "$SCRIPTS_DIR/$script"
    chmod +x "$SCRIPTS_DIR/$script"
    ok "  $script actualizado"
done

log "Aplicando reglas de firewall CTF..."
bash "$SCRIPTS_DIR/apply-firewall.sh"

# Servicio systemd para persistir el firewall al reinicio
cat > /etc/systemd/system/ctf-firewall.service <<'EOF'
[Unit]
Description=CTF VPN firewall (aislamiento inter-equipo + SIEM)
After=docker.service openvpn@server.service network-online.target
Requires=docker.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/openvpn/scripts/apply-firewall.sh
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable ctf-firewall.service
ok "ctf-firewall.service instalado y habilitado al arranque"

# Si OpenVPN no está activo (falló en PASO 4), intentar de nuevo ahora que
# los scripts ya están instalados y el firewall está listo.
if ! systemctl is-active --quiet openvpn@server; then
    log "OpenVPN no estaba activo — reintentando ahora que los scripts están en su lugar..."
    systemctl restart openvpn@server || warn "OpenVPN sigue fallando — revisa: journalctl -xeu openvpn@server"
    sleep 3
    if systemctl is-active --quiet openvpn@server; then
        ok "OpenVPN activo (segundo intento)"
    else
        warn "OpenVPN no pudo iniciar. Diagnóstico: journalctl -xeu openvpn@server --no-pager | tail -40"
    fi
fi

# =============================================================================
# PASO 7 — DNS sinkhole de IAs (dnsmasq)
# =============================================================================
step "PASO 7 — DNS sinkhole (bloqueo de IAs)"

DNSMASQ_CONF_SRC="$REPO_DIR/infra/firewall/dnsmasq.conf"
DNSMASQ_CONF_DST="/etc/dnsmasq.d/ctf.conf"
BLOCKLIST_SRC="$REPO_DIR/infra/firewall/ai-blocklist.txt"
BLOCKLIST_SCRIPT="$REPO_DIR/infra/firewall/gen-dnsmasq-blocklist.sh"

# Deshabilitar dnsmasq del sistema en el puerto 53 si hay conflicto con systemd-resolved
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    log "Deshabilitando stub de systemd-resolved para liberar puerto 53..."
    sed -i 's/#DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf 2>/dev/null || true
    sed -i 's/DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf 2>/dev/null || true
    systemctl restart systemd-resolved 2>/dev/null || true
fi

if [[ -f "$DNSMASQ_CONF_SRC" ]] && [[ -f "$BLOCKLIST_SRC" ]]; then
    log "Copiando dnsmasq.conf y generando sinkhole desde ai-blocklist.txt..."
    cp "$DNSMASQ_CONF_SRC" "$DNSMASQ_CONF_DST"
    bash "$BLOCKLIST_SCRIPT" "$DNSMASQ_CONF_DST" "$BLOCKLIST_SRC"
    N_DOMAINS=$(grep -c "^address=" "$DNSMASQ_CONF_DST" 2>/dev/null || echo "?")
    ok "Sinkhole generado: $N_DOMAINS dominios de IA bloqueados"
else
    warn "dnsmasq.conf o ai-blocklist.txt no encontrados — usando sinkhole mínimo..."
    cat > "$DNSMASQ_CONF_DST" <<'EOF'
listen-address=127.0.0.1,10.10.0.1
no-resolv
server=1.1.1.1
server=1.0.0.1
log-queries=extra
log-facility=/var/log/dnsmasq/queries.log
log-async=25
# OpenAI / ChatGPT
address=/openai.com/0.0.0.0
address=/chatgpt.com/0.0.0.0
address=/oaistatic.com/0.0.0.0
# Anthropic / Claude
address=/anthropic.com/0.0.0.0
address=/claude.ai/0.0.0.0
# Google Gemini
address=/gemini.google.com/0.0.0.0
address=/bard.google.com/0.0.0.0
address=/generativelanguage.googleapis.com/0.0.0.0
# Microsoft Copilot
address=/copilot.microsoft.com/0.0.0.0
address=/githubcopilot.com/0.0.0.0
# Otros
address=/perplexity.ai/0.0.0.0
address=/huggingface.co/0.0.0.0
address=/mistral.ai/0.0.0.0
address=/deepseek.com/0.0.0.0
address=/x.ai/0.0.0.0
address=/grok.com/0.0.0.0
address=/cloudflare-dns.com/0.0.0.0
address=/dns.google/0.0.0.0
EOF
    ok "Sinkhole mínimo configurado"
fi

# Drop-in systemd para que dnsmasq arranque DESPUÉS de OpenVPN (tun0 debe existir
# antes de que dnsmasq intente bind en 10.10.0.1).
mkdir -p /etc/systemd/system/dnsmasq.service.d
cat > /etc/systemd/system/dnsmasq.service.d/after-openvpn.conf <<'EOF'
[Unit]
After=openvpn@server.service
Wants=openvpn@server.service
EOF
systemctl daemon-reload

systemctl enable dnsmasq 2>/dev/null || true
systemctl restart dnsmasq || warn "dnsmasq no pudo reiniciar — revisa: journalctl -u dnsmasq"
sleep 1
if systemctl is-active --quiet dnsmasq; then
    ok "dnsmasq activo — DNS sinkhole funcionando"
else
    warn "dnsmasq no activo — revisar: systemctl status dnsmasq"
fi

# =============================================================================
# PASO 8 — Docker Compose: plataforma + SIEM
# =============================================================================
step "PASO 8 — Docker Compose: plataforma + SIEM"

log "Construyendo imágenes y levantando contenedores..."
cd "$REPO_DIR/infra"
docker compose up -d --build 2>&1 | tee -a "$LOG_FILE" | tail -8

log "Esperando que los servicios estén listos (30s)..."
sleep 30

# Fix permisos Loki si está en restart loop
LOKI_STATUS=$(docker inspect ctf-loki --format='{{.State.Status}}' 2>/dev/null || echo "missing")
if [[ "$LOKI_STATUS" == "restarting" ]]; then
    warn "Loki en restart loop — corrigiendo permisos de volumen..."
    docker stop ctf-loki 2>/dev/null || true
    docker run --rm -v infra_loki-data:/loki alpine chown -R 10001:10001 /loki
    docker compose start loki
    sleep 10
fi

RUNNING=$(docker ps --filter "name=ctf-" --format "{{.Names}}" | wc -l)
ok "$RUNNING contenedores CTF corriendo"
docker compose ps --format "table {{.Name}}\t{{.Status}}" 2>/dev/null | tee -a "$LOG_FILE" | head -20

# =============================================================================
# PASO 9 — Seed de base de datos
# =============================================================================
step "PASO 9 — Seed: equipos y retos"

log "Esperando que ctf-api esté healthy (máx 60s)..."
for i in $(seq 1 12); do
    HEALTH=$(docker inspect ctf-api --format='{{.State.Health.Status}}' 2>/dev/null || echo "unknown")
    [[ "$HEALTH" == "healthy" ]] && break
    log "  ctf-api: $HEALTH — esperando... ($((i*5))s)"
    sleep 5
done

log "Ejecutando seed.py --reset..."
if docker exec ctf-api python seed.py --reset 2>&1 | tee -a "$LOG_FILE"; then
    ok "Base de datos sembrada"
else
    warn "seed.py falló — puede ejecutarse manualmente: docker exec ctf-api python seed.py --reset"
fi

# =============================================================================
# PASO 10 — Verificación final
# =============================================================================
step "PASO 10 — Verificación"

log "Probando acceso a 10.10.100.10 (nginx CTF)..."
if curl -s --max-time 5 -o /dev/null -w "%{http_code}" http://10.10.100.10 | grep -qE "200|301|302"; then
    ok "10.10.100.10 responde — plataforma accesible"
else
    warn "10.10.100.10 no responde — verificar: docker ps y docker logs ctf-nginx"
fi

log "Verificando dnsmasq sinkhole..."
if command -v dig &>/dev/null; then
    RESULT=$(dig +short @127.0.0.1 openai.com A 2>/dev/null | head -1 || true)
    if [[ "$RESULT" == "0.0.0.0" ]]; then
        ok "Sinkhole OK — openai.com → 0.0.0.0"
    else
        warn "Sinkhole posiblemente no activo (openai.com → $RESULT). Verificar: systemctl status dnsmasq"
    fi
fi

log "Estado del firewall CTF..."
nft list chain ip filter DOCKER-USER 2>/dev/null | grep -E 'saddr|return|drop' | head -8 | tee -a "$LOG_FILE" || true

# =============================================================================
# RESUMEN FINAL
# =============================================================================
echo ""
echo -e "${GRN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GRN}║                  DEPLOY COMPLETADO ✓                    ║${NC}"
echo -e "${GRN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BLU}Plataforma CTF:${NC}     http://${SERVER_IP}"
echo -e "  ${BLU}SIEM Live:${NC}          http://${SERVER_IP}:8090"
echo -e "  ${BLU}Grafana (SSH):${NC}      ssh -L 3000:localhost:3000 root@${SERVER_IP}"
echo -e "  ${BLU}Admin panel (SSH):${NC}  ssh -L 8091:localhost:8091 root@${SERVER_IP}"
echo ""
echo -e "  ${YLW}Archivos .ovpn:${NC}     $OVPN_ZIP"
echo -e "  ${YLW}Scripts VPN:${NC}        $SCRIPTS_DIR/"
echo -e "  ${YLW}Logs deploy:${NC}        $LOG_FILE"
echo -e "  ${YLW}Secretos (.env):${NC}    $REPO_DIR/infra/.env"
echo ""
echo -e "  ${CYN}Servicios systemd activos:${NC}"
echo -e "    • openvpn@server    — VPN"
echo -e "    • ctf-firewall      — reglas nftables (persiste al reinicio)"
echo -e "    • dnsmasq           — sinkhole DNS de IAs"
echo -e "    • docker            — plataforma + SIEM"
echo ""
echo -e "  ${CYN}Comandos útiles:${NC}"
echo -e "    docker compose -f $REPO_DIR/infra/docker-compose.yml ps"
echo -e "    systemctl status openvpn@server"
echo -e "    journalctl -u ctf-firewall -f"
echo -e "    cat /var/log/openvpn/events.log"
echo ""
echo -e "${YLW}  ► Descarga ovpn-jugadores.zip y distribúyelo a los equipos.${NC}"
echo ""
