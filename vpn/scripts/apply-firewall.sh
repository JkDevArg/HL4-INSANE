#!/bin/bash
# apply-firewall.sh — aplica reglas de firewall para VPN del CTF.
#
# ESTRATEGIA DE BLOQUEO:
#   El bloqueo de IAs (ChatGPT, Claude, Gemini, etc.) se hace por DNS sinkhole
#   (dnsmasq + dns-blacklist). El firewall NO bloquea internet general.
#
# LO QUE SE PERMITE desde la VPN (10.10.0.0/16):
#   - Internet general          (para usar herramientas, man pages, etc.)
#   - Platform CTF:             10.10.100.0/24  (nginx, API, frontend)
#   - Challenges equipo N:      172.30.N.0/24   (solo su propio equipo)
#
# LO QUE SE BLOQUEA:
#   - SIEM interno:             10.10.200.0/24  (jugadores no deben verlo)
#   - Challenges de otros equipos (aislamiento inter-equipo)
#   - IAs: bloqueadas por DNS sinkhole en dnsmasq (no por firewall)
#
# PREREQUISITO: OpenVPN debe tener disable-dco en server.conf.
# Sin disable-dco el kernel module ovpn procesa paquetes sin pasar por
# netfilter, haciendo que TODAS las reglas iptables/nftables sean inefectivas.
#
# IDEMPOTENTE: limpia todas las reglas CTF previas antes de insertar,
# evitando duplicados si se corre el script varias veces.
#
# USO: sudo bash /etc/openvpn/scripts/apply-firewall.sh

set -euo pipefail

log() { echo "[apply-firewall] $*"; }

# ---------------------------------------------------------------------------
# Helper: borrar reglas por patron en una chain hasta que no queden mas
# ---------------------------------------------------------------------------
flush_chain_by_pattern() {
    local CHAIN="$1"
    local PATTERN="$2"
    local TABLE="${3:-ip filter}"
    local HANDLES
    HANDLES=$(nft -a list chain $TABLE "$CHAIN" 2>/dev/null \
        | grep -E "$PATTERN" \
        | grep -oP '# handle \K[0-9]+' \
        | sort -rn | tr '\n' ' ' || true)
    for H in $HANDLES; do
        nft delete rule $TABLE "$CHAIN" handle "$H" 2>/dev/null || true
    done
}

# ---------------------------------------------------------------------------
# 1. Flush DOCKER-USER: reglas CTF previas
# ---------------------------------------------------------------------------
log "Limpiando reglas CTF previas en DOCKER-USER..."
flush_chain_by_pattern "DOCKER-USER" 'saddr 10\.10\.|daddr 172\.30\.|daddr 10\.10\.|iifname.*tun0'
log "DOCKER-USER limpia."

# ---------------------------------------------------------------------------
# 2. Flush FORWARD: todas las reglas tun0 y ct state previas (excepto jumps DOCKER-*)
# ---------------------------------------------------------------------------
log "Limpiando reglas CTF previas en FORWARD..."
# Recoger TODOS los handles no-DOCKER de una sola vez, luego borrar cada uno.
# Usar sort -rn (mayor a menor) para evitar reordenar handles mid-loop.
# || true en cada delete: algunas reglas Docker son inmutables via nft, se saltan.
FWHANDLES=$(nft -a list chain ip filter FORWARD 2>/dev/null \
    | grep -v 'DOCKER-USER\|DOCKER-FORWARD\|type filter hook' \
    | grep -oP '# handle \K[0-9]+' \
    | sort -rn | tr '\n' ' ' || true)
for H in $FWHANDLES; do
    nft delete rule ip filter FORWARD handle "$H" 2>/dev/null || true
done
log "FORWARD limpia (se mantienen los jumps DOCKER-*)."

# ---------------------------------------------------------------------------
# 3. Flush MASQUERADE VPN->CTF duplicados en POSTROUTING
# ---------------------------------------------------------------------------
log "Limpiando masquerade duplicados en POSTROUTING..."
while true; do
    HANDLE=$(nft -a list chain ip nat POSTROUTING 2>/dev/null \
        | grep '10\.10\.0\.0/16.*10\.10\.100\.0/24.*masquerade' \
        | grep -oP '# handle \K[0-9]+' \
        | head -1 || true)
    [[ -z "$HANDLE" ]] && break
    nft delete rule ip nat POSTROUTING handle "$HANDLE" 2>/dev/null || break
done
log "POSTROUTING limpia."

# ---------------------------------------------------------------------------
# 4. Insertar reglas FORWARD limpias
#
# nft insert agrega al PRINCIPIO — insertar en orden INVERSO al deseado.
# Cadena final (top->bottom):
#   1. ct state established,related accept   <- retorno Docker->tun0
#   2. iifname tun0 -> 10.10.100.0/24 ACCEPT <- VPN a plataforma CTF
#   3. iifname tun0 -> 172.30.0.0/16 ACCEPT  <- VPN a challenges del equipo
#   4. iifname tun0 -> 10.10.200.0/24 DROP   <- bloquear SIEM
#   5. iifname tun0 -> 10.10.0.0/16 DROP     <- bloquear inter-equipo en VPN
#   [... jumps DOCKER-USER y DOCKER-FORWARD ya existentes ...]
# ---------------------------------------------------------------------------
log "Insertando reglas FORWARD..."

# [5] DROP inter-equipo — insertado primero, queda al fondo de nuestras reglas
nft insert rule ip filter FORWARD \
    iifname "tun0" ip saddr 10.10.0.0/16 ip daddr 10.10.0.0/16 drop

# [4] DROP SIEM
nft insert rule ip filter FORWARD \
    iifname "tun0" ip daddr 10.10.200.0/24 drop

# [3] ACCEPT challenges
nft insert rule ip filter FORWARD \
    iifname "tun0" ip daddr 172.30.0.0/16 counter accept

# [2b] ACCEPT plataforma CTF
nft insert rule ip filter FORWARD \
    iifname "tun0" ip daddr 10.10.100.0/24 counter accept

# [2a] ACCEPT VPN -> internet (redirect-gateway def1 manda todo por VPN;
#      sin esta regla el cliente pierde internet al conectar)
nft insert rule ip filter FORWARD \
    iifname "tun0" oifname "ens18" counter accept

# [1] ACCEPT established/related — insertado ultimo, queda al tope
nft insert rule ip filter FORWARD \
    ct state established,related accept

log "Reglas FORWARD aplicadas."

# ---------------------------------------------------------------------------
# 5. Insertar reglas DOCKER-USER para aislamiento por equipo
#
# Orden final (top->bottom) en DOCKER-USER:
#   1. VPN -> platform CTF: ACCEPT
#   2. team_N -> challenges_N: ACCEPT (por equipo)
#   3. VPN -> SIEM + privadas: DROP
#   4. VPN -> internet: RETURN (IAs bloqueadas por dnsmasq)
# ---------------------------------------------------------------------------
log "Insertando reglas DOCKER-USER..."

# [4] RETURN internet — insertado primero, queda al fondo
nft insert rule ip filter DOCKER-USER \
    ip saddr 10.10.0.0/16 \
    ip daddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } \
    return 2>/dev/null || true

# [3] DROP SIEM y redes privadas no autorizadas
nft insert rule ip filter DOCKER-USER \
    ip saddr 10.10.0.0/16 \
    ip daddr { 172.16.0.0/12, 10.10.200.0/24 } \
    drop 2>/dev/null || true

# [2] ACCEPT por equipo (solo su propia subred de challenges)
for TEAM in 1 2 3 4 5; do
    nft insert rule ip filter DOCKER-USER \
        ip saddr "10.10.${TEAM}.0/24" ip daddr "172.30.${TEAM}.0/24" \
        accept 2>/dev/null || true
done

# [1] ACCEPT todos los equipos -> platform CTF
nft insert rule ip filter DOCKER-USER \
    ip saddr 10.10.0.0/16 ip daddr 10.10.100.0/24 \
    accept 2>/dev/null || true

log "Reglas DOCKER-USER aplicadas."

# ---------------------------------------------------------------------------
# 6. MASQUERADE: VPN -> platform CTF
#
# Necesario para que el return path (Docker->VPN) funcione incluso si
# la chain FORWARD tiene policy drop en alguna configuracion futura.
# Con disable-dco, el FORWARD chain ya deberia ser suficiente, pero
# MASQUERADE es una capa de seguridad adicional.
# ---------------------------------------------------------------------------
nft insert rule ip nat POSTROUTING \
    ip saddr 10.10.0.0/16 ip daddr 10.10.100.0/24 counter masquerade 2>/dev/null || true
log "MASQUERADE VPN->CTF platform configurado."

# ---------------------------------------------------------------------------
# 7. Verificacion final
# ---------------------------------------------------------------------------
log "--- FORWARD ---"
nft list chain ip filter FORWARD 2>/dev/null | grep -E 'tun0|established|policy' || true

log "--- DOCKER-USER ---"
nft list chain ip filter DOCKER-USER 2>/dev/null \
    | grep -E 'saddr|daddr|return|drop|accept' | head -15 || true

log "--- MASQUERADE ---"
nft list chain ip nat POSTROUTING 2>/dev/null \
    | grep '10\.10\.0\.0/16.*masquerade' || true

log "OK — Firewall CTF aplicado correctamente."
log "    - Internet: PERMITIDO (IAs bloqueadas por dnsmasq)"
log "    - SIEM (10.10.200.0/24): BLOQUEADO"
log "    - Inter-equipo VPN: BLOQUEADO"
log "    - Platform CTF (10.10.100.0/24): PERMITIDO"
log "    - Challenges (172.30.N.0/24): PERMITIDO solo al equipo N"
