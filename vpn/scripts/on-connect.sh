#!/bin/bash
# on-connect.sh — script client-connect de OpenVPN.
#
# OpenVPN lo invoca cada vez que un cliente completa el handshake TLS,
# ANTES de habilitarle tráfico. Si este script sale con codigo != 0,
# OpenVPN ABORTA la conexion del cliente (lo desconecta).
#
# Responsabilidades:
#   1. Registrar sesion activa en Redis (permite reconexion con el mismo cert).
#   2. Loguear la conexion (CN, IP asignada VPN, IP real) en formato parseable.
#   3. Emitir evento SIEM vpn_connect (fire-and-forget).
#
# Variables de entorno que OpenVPN expone a este script:
#   common_name        -> CN del certificado del cliente = team_NN_pN
#   ifconfig_pool_remote_ip -> IP que el server asigna al cliente dentro de 10.10.0.0/16
#   trusted_ip / untrusted_ip -> IP publica real del cliente (origen del tunel)
#   trusted_port       -> puerto de origen real
#
# Dependencias: redis-cli, curl.

set -euo pipefail

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
REDIS_HOST="${REDIS_HOST:-10.10.100.31}"
REDIS_PORT="${REDIS_PORT:-6379}"
COLLECTOR_URL="${COLLECTOR_URL:-http://10.10.200.10:9000/event}"
EVENTS_LOG="${EVENTS_LOG:-/var/log/openvpn/events.log}"

[[ -f /etc/openvpn/scripts/ban.env ]] && source /etc/openvpn/scripts/ban.env

# ---------------------------------------------------------------------------
# Datos del cliente
# ---------------------------------------------------------------------------
CN="${common_name:-unknown}"
VPN_IP="${ifconfig_pool_remote_ip:-?}"
REAL_IP="${trusted_ip:-${untrusted_ip:-?}}"
REAL_PORT="${trusted_port:-${untrusted_port:-?}}"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Extrae team_id y player del CN: "team_01_p1" -> TEAM=team_01 PLAYER=p1
if [[ "$CN" =~ ^(team_[0-9]{2})(_(.+))?$ ]]; then
    TEAM="${BASH_REMATCH[1]}"
    PLAYER="${BASH_REMATCH[3]:-}"
else
    TEAM="$CN"
    PLAYER=""
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
emit_siem() {
    local event_type="$1" severity="$2" detail="$3"
    local payload
    payload=$(cat <<JSON
{"ts":"${TS}","source":"vpn","team_id":"${TEAM}","user":"${CN}","player":"${PLAYER}","src_ip":"${VPN_IP}","event_type":"${event_type}","severity":"${severity}","detail":${detail}}
JSON
)
    curl -s -o /dev/null --max-time 3 \
        -H 'Content-Type: application/json' \
        -X POST "$COLLECTOR_URL" -d "$payload" >/dev/null 2>&1 &
    return 0
}

log_event() {
    echo "${TS} evt=$1 team=${TEAM} vpn_ip=${VPN_IP} real_ip=${REAL_IP}:${REAL_PORT} ${2:-}" \
        >> "$EVENTS_LOG"
}

# ---------------------------------------------------------------------------
# 1) Registrar sesion activa en Redis (sin rechazar conexiones duplicadas).
#
# Se permite reconectar en cualquier momento con el mismo cert.
# ---------------------------------------------------------------------------
CONNECTED_KEY="vpn:connected:${CN}"
GRACE_KEY="vpn:grace:${CN}"

redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" \
    SET "$CONNECTED_KEY" "${REAL_IP}:${REAL_PORT}" EX 86400 >/dev/null 2>&1 || true
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" \
    DEL "$GRACE_KEY" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# 3) Conexion permitida: log + evento SIEM
# ---------------------------------------------------------------------------
log_event vpn_connect "action=accepted cn=${CN} player=${PLAYER}"
emit_siem "vpn_connect" "info" \
    "{\"action\":\"accepted\",\"cn\":\"${CN}\",\"player\":\"${PLAYER}\",\"real_ip\":\"${REAL_IP}\",\"real_port\":\"${REAL_PORT}\"}"

exit 0
