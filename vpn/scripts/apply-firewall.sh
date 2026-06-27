#!/bin/bash
# apply-firewall.sh — aplica reglas de firewall para VPN del CTF.
#
# ESTRATEGIA DE BLOQUEO:
#   El bloqueo de IAs (ChatGPT, Claude, Gemini, etc.) se hace por DNS sinkhole
#   (dnsmasq + dns-blacklist). El firewall NO bloquea internet.
#
# LO QUE SE PERMITE desde la VPN (10.10.0.0/16):
#   - Internet general          (para usar herramientas, man pages, etc.)
#   - Platform CTF:             10.10.100.0/24  (nginx, API, frontend)
#   - Challenges equipo N:      172.30.N.0/24   (solo su propio equipo)
#
# LO QUE SE BLOQUEA:
#   - SIEM interno:             10.10.200.0/24  (jugadores no deben verlo)
#   - Challenges de otros equipos (inter-equipo)
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
#    evitar duplicados. Se identifican por saddr 10.10.0.0/16 o por ser
#    reglas de challenges (172.30.x.x). Se repite hasta que no quede ninguna.
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
#      2. ACCEPT: team_N → sus challenges (172.30.N.0/24) — aislamiento inter-equipo
#      3. DROP:   VPN → SIEM (10.10.200.0/24) — los jugadores no ven el SIEM
#      4. DROP:   VPN → cualquier otra red Docker (172.16/12, 10.10.200+)
#      5. RETURN: todo lo demás (internet) pasa — las IAs las bloquea dnsmasq
# ---------------------------------------------------------------------------

# [5] RETURN para internet: cualquier destino fuera de las redes internas pasa.
# nft RETURN en DOCKER-USER devuelve al FORWARD hook y el paquete sigue normal.
nft insert rule ip filter DOCKER-USER \
    ip saddr 10.10.0.0/16 \
    ip daddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } \
    return 2>/dev/null || true

# [4] DROP: VPN → cualquier otra subred privada Docker no autorizada
nft insert rule ip filter DOCKER-USER \
    ip saddr 10.10.0.0/16 \
    ip daddr { 172.16.0.0/12, 10.10.200.0/24 } \
    drop 2>/dev/null || true

# [3] ya cubierto por [4]: 10.10.200.0/24 está en el bloque anterior

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

log "Reglas VPN aplicadas."

# ---------------------------------------------------------------------------
# 3. Verificación
# ---------------------------------------------------------------------------
log "Estado actual de DOCKER-USER:"
nft list chain ip filter DOCKER-USER 2>/dev/null \
    | grep -E 'saddr|daddr|tun0|return|drop|accept' || true

log "OK — internet PERMITIDO para jugadores VPN. IAs bloqueadas por dnsmasq."
