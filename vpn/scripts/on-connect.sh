#!/bin/bash
# on-connect.sh — script client-connect de OpenVPN.
#
# OpenVPN lo invoca cada vez que un cliente completa el handshake TLS,
# ANTES de habilitarle tráfico. Si este script sale con codigo != 0,
# OpenVPN ABORTA la conexion del cliente (lo desconecta).
#
# Responsabilidades:
#   1. Si el equipo ya esta baneado (Redis ban:team_NN) -> exit 1 (rechaza).
#   2. Si el cert ya tiene una sesion activa (otro jugador/dispositivo lo
#      usa al mismo tiempo) -> exit 1 (rechaza). Grace period: si el jugador
#      se desconecto en los ultimos 2 min puede reconectarse (caida de internet).
#   3. Loguear la conexion (CN, IP asignada VPN, IP real) en formato parseable.
#   4. Emitir evento SIEM vpn_connect (fire-and-forget).
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
# 1) Gate de ban
# ---------------------------------------------------------------------------
BANNED="0"
if BANNED=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" --no-raw EXISTS "ban:${TEAM}" 2>/dev/null); then
    BANNED="$(echo "$BANNED" | tr -dc '0-9')"
else
    BANNED="0"
    log_event vpn_connect_redis_error "note=redis_unreachable_failopen"
fi

if [[ "$BANNED" == "1" ]]; then
    log_event vpn_connect_rejected "reason=banned cn=${CN} player=${PLAYER}"
    emit_siem "vpn_connect" "alert" \
        "{\"action\":\"rejected\",\"reason\":\"team_banned\",\"cn\":\"${CN}\",\"player\":\"${PLAYER}\"}"
    exit 1
fi

# ---------------------------------------------------------------------------
# 2) Gate de cert duplicado: un solo dispositivo activo por CN.
#
# Redis keys:
#   vpn:connected:{CN}  -> existe SOLO mientras hay sesion activa (TTL 86400s).
#                          Se borra en on-disconnect.sh.
#   vpn:grace:{CN}      -> existe 120s tras desconexion (grace period).
#                          Mientras exista, el mismo CN puede reconectarse.
#
# Logica:
#   - vpn:connected existe -> mismo cert ya conectado -> rechazar.
#   - vpn:connected NO existe (este o esta en grace period) -> permitir.
# ---------------------------------------------------------------------------
CONNECTED_KEY="vpn:connected:${CN}"
GRACE_KEY="vpn:grace:${CN}"

ALREADY_CONNECTED="0"
if ALREADY_CONNECTED=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" \
        --no-raw EXISTS "$CONNECTED_KEY" 2>/dev/null); then
    ALREADY_CONNECTED="$(echo "$ALREADY_CONNECTED" | tr -dc '0-9')"
else
    ALREADY_CONNECTED="0"   # Redis caido -> fail-open (no bloqueamos)
fi

if [[ "$ALREADY_CONNECTED" == "1" ]]; then
    log_event vpn_connect_rejected \
        "reason=cert_in_use cn=${CN} player=${PLAYER}"
    emit_siem "vpn_connect" "alert" \
        "{\"action\":\"rejected\",\"reason\":\"cert_in_use\",\"cn\":\"${CN}\",\"player\":\"${PLAYER}\"}"
    echo "[on-connect] ${CN} RECHAZADO: cert ya esta en uso" >&2
    exit 1
fi

# Registrar sesion activa (TTL largo mientras este conectado).
# Borramos el grace key por si era una reconexion rapida.
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
