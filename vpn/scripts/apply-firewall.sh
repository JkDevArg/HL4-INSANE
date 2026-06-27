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
# IDEMPOTENTE: limpia todas las reglas CTF previas antes de insertar,
# evitando duplicados si se corre el script varias veces.
#
# USO: sudo bash /etc/openvpn/scripts/apply-firewall.sh

set -euo pipefail

log() { echo "[apply-firewall] $*"; }

# ---------------------------------------------------------------------------
# 1. Flush: eliminar TODAS las reglas CTF existentes en DOCKER-USER para
#    evitar duplicados al correr el script más de una vez.
# ---------------------------------------------------------------------------
log "Limpiando reglas CTF previas en DOCKER-USER..."

flush_ctf_rules() {
    while true; do
        HANDLE=$(nft -a list chain ip filter DOCKER-USER 2>/dev/null \
            | grep -E 'saddr 10\.10\.|daddr 172\.30\.|daddr 10\.10\.' \
            | grep -oP '# handle \K[0-9]+' \
            | head -1 || true)
        if [[ -z "$HANDLE" ]]; then
            break
        fi
        nft delete rule ip filter DOCKER-USER handle "$HANDLE" 2>/dev/null || break
    done
}
flush_ctf_rules

# Quitar también la regla permisiva tun0 si existe (de instalaciones previas).
HANDLE=$(nft -a list chain ip filter DOCKER-USER 2>/dev/null \
    | grep 'iifname "tun0".*accept' \
    | grep -oP '# handle \K[0-9]+' \
    | head -1 || true)
if [[ -n "$HANDLE" ]]; then
    nft delete rule ip filter DOCKER-USER handle "$HANDLE"
    log "Regla permisiva tun0 eliminada (handle $HANDLE)"
fi

log "Limpieza completada."

# ---------------------------------------------------------------------------
# 2. Insertar reglas (nft insert agrega al PRINCIPIO; orden de inserción
#    es INVERSO al orden de evaluación deseado).
#
#    Orden final de evaluación (de arriba a abajo):
#      1. ACCEPT: VPN → platform CTF (10.10.100.0/24)
#      2. ACCEPT: team_N → sus challenges (172.30.N.0/24)
#      3. DROP:   VPN → SIEM (10.10.200.0/24) y otras redes Docker privadas
#      4. RETURN: todo lo demás (internet) pasa — IAs las bloquea dnsmasq
# ---------------------------------------------------------------------------

# [4] RETURN para internet: destinos fuera de redes privadas pasan libremente.
nft insert rule ip filter DOCKER-USER \
    ip saddr 10.10.0.0/16 \
    ip daddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } \
    return 2>/dev/null || true

# [3] DROP: VPN → SIEM y redes Docker privadas no autorizadas
nft insert rule ip filter DOCKER-USER \
    ip saddr 10.10.0.0/16 \
    ip daddr { 172.16.0.0/12, 10.10.200.0/24 } \
    drop 2>/dev/null || true

# [2] ACCEPT por equipo: solo su propia subred de challenges
nft insert rule ip filter DOCKER-USER \
    ip saddr 10.10.5.0/24 ip daddr 172.30.5.0/24 \
    accept 2>/dev/null || true

nft insert rule ip filter DOCKER-USER \
    ip saddr 10.10.4.0/24 ip daddr 172.30.4.0/24 \
    accept 2>/dev/null || true

nft insert rule ip filter DOCKER-USER \
    ip saddr 10.10.3.0/24 ip daddr 172.30.3.0/24 \
    accept 2>/dev/null || true

nft insert rule ip filter DOCKER-USER \
    ip saddr 10.10.2.0/24 ip daddr 172.30.2.0/24 \
    accept 2>/dev/null || true

nft insert rule ip filter DOCKER-USER \
    ip saddr 10.10.1.0/24 ip daddr 172.30.1.0/24 \
    accept 2>/dev/null || true

# [1] ACCEPT: todos los equipos → platform CTF
nft insert rule ip filter DOCKER-USER \
    ip saddr 10.10.0.0/16 ip daddr 10.10.100.0/24 \
    accept 2>/dev/null || true

log "Reglas DOCKER-USER aplicadas."

# ---------------------------------------------------------------------------
# 3. Aislamiento inter-equipo en tun0 (FORWARD chain).
#
# client-to-client en OpenVPN permite que 10.10.1.x alcance 10.10.2.x
# directamente por tun0, sin pasar por Docker. Hay que bloquearlo aquí.
#
# Se permite:
#   - Cualquier equipo → 10.10.100.0/24 (platform CTF)
#   - Cualquier equipo → 10.10.0.1      (gateway VPN / DNS dnsmasq)
#   - Tráfico de retorno (ESTABLISHED/RELATED)
# Se bloquea:
#   - Tráfico entre subredes de equipos distintos (10.10.N.x → 10.10.M.x)
# ---------------------------------------------------------------------------
log "Aplicando aislamiento inter-equipo en FORWARD/tun0..."

# Limpiar reglas tun0 previas para idempotencia.
while true; do
    HANDLE=$(nft -a list chain ip filter FORWARD 2>/dev/null \
        | grep 'iifname "tun0"' \
        | grep -oP '# handle \K[0-9]+' \
        | head -1 || true)
    [[ -z "$HANDLE" ]] && break
    nft delete rule ip filter FORWARD handle "$HANDLE" 2>/dev/null || break
done

# Permitir tráfico de retorno (conexiones ya establecidas).
nft insert rule ip filter FORWARD \
    iifname "tun0" ct state established,related accept 2>/dev/null || true

# Permitir VPN → platform CTF (10.10.100.0/24).
nft insert rule ip filter FORWARD \
    iifname "tun0" ip saddr 10.10.0.0/16 ip daddr 10.10.100.0/24 \
    accept 2>/dev/null || true

# Permitir VPN → gateway (DNS dnsmasq en 10.10.0.1).
nft insert rule ip filter FORWARD \
    iifname "tun0" ip saddr 10.10.0.0/16 ip daddr 10.10.0.1 \
    accept 2>/dev/null || true

# Bloquear tráfico entre clientes VPN (10.10.0.0/16 → 10.10.0.0/16).
# Esto cubre team_01 → team_02 y cualquier combinación inter-equipo.
nft insert rule ip filter FORWARD \
    iifname "tun0" ip saddr 10.10.0.0/16 ip daddr 10.10.0.0/16 \
    drop 2>/dev/null || true

log "Aislamiento inter-equipo aplicado."

# ---------------------------------------------------------------------------
# 4. Verificación
# ---------------------------------------------------------------------------
log "--- DOCKER-USER ---"
nft list chain ip filter DOCKER-USER 2>/dev/null \
    | grep -E 'saddr|daddr|tun0|return|drop|accept' || true

log "--- FORWARD (tun0) ---"
nft list chain ip filter FORWARD 2>/dev/null \
    | grep 'tun0' || true

log "OK — internet PERMITIDO. SIEM, inter-equipo e inter-VPN BLOQUEADOS. IAs bloqueadas por dnsmasq."
