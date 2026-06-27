#!/bin/bash
# on-disconnect.sh — script client-disconnect de OpenVPN.
#
# Responsabilidades:
#   1. Liberar el slot del cert en Redis (vpn:connected:{CN} -> grace 120s).
#      Esto permite que el mismo jugador reconecte si su internet cayo,
#      SIN que otra persona pueda usar el mismo cert durante esos 2 min.
#   2. Contar desconexiones limpias para el sistema de ban (logica original).
#   3. Emitir evento SIEM.
#
# Variables de entorno que OpenVPN expone:
#   common_name, ifconfig_pool_remote_ip, trusted_ip, time_duration, signal
#
# HEURISTICA limpia-vs-timeout:
#   Cuenta como desconexion del CLIENTE si:
#     (a) signal == "remote-exit"  -> exit-notify explicito del cliente, o
#     (b) signal vacio Y time_duration < KEEPALIVE_TIMEOUT (~120s).
#   NO cuenta (timeout / server-side) si:
#     - signal en {ping-restart, sigterm, sigint, sigusr1, sighup}
#     - signal vacio Y time_duration >= KEEPALIVE_TIMEOUT

set -euo pipefail

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
REDIS_HOST="${REDIS_HOST:-10.10.100.31}"
REDIS_PORT="${REDIS_PORT:-6379}"
COLLECTOR_URL="${COLLECTOR_URL:-http://10.10.200.10:9000/event}"
EVENTS_LOG="${EVENTS_LOG:-/var/log/openvpn/events.log}"
DISCONNECT_THRESHOLD="${DISCONNECT_THRESHOLD:-8}"
KEEPALIVE_TIMEOUT="${KEEPALIVE_TIMEOUT:-120}"
DISC_WINDOW_TTL="${DISC_WINDOW_TTL:-0}"
# Tiempo de gracia (segundos) antes de liberar el slot del cert.
# Permite reconexion rapida tras caida de internet sin que otro use el cert.
GRACE_TTL="${GRACE_TTL:-120}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BAN_SCRIPT="${BAN_SCRIPT:-${SCRIPT_DIR}/ban-team.sh}"

[[ -f /etc/openvpn/scripts/ban.env ]] && source /etc/openvpn/scripts/ban.env

# ---------------------------------------------------------------------------
# Datos de la sesion
# ---------------------------------------------------------------------------
CN="${common_name:-unknown}"
VPN_IP="${ifconfig_pool_remote_ip:-?}"
REAL_IP="${trusted_ip:-${untrusted_ip:-?}}"
REAL_PORT="${trusted_port:-${untrusted_port:-?}}"
DURATION="${time_duration:-0}"
SIGNAL="${signal:-}"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [[ "$CN" =~ ^(team_[0-9]{2})(_(.+))?$ ]]; then
    TEAM="${BASH_REMATCH[1]}"
    PLAYER="${BASH_REMATCH[3]:-}"
else
    TEAM="$CN"
    PLAYER=""
fi

DURATION="$(echo "$DURATION" | tr -dc '0-9')"
DURATION="${DURATION:-0}"

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
    echo "${TS} evt=$1 team=${TEAM} vpn_ip=${VPN_IP} real_ip=${REAL_IP} dur=${DURATION}s signal=${SIGNAL:-none} ${2:-}" \
        >> "$EVENTS_LOG"
}

# ---------------------------------------------------------------------------
# SIEMPRE: liberar slot con grace period (independiente del tipo de cierre).
# on-connect.sh chequea vpn:connected:{CN}. Al desconectarse por cualquier
# motivo (limpio, caida, timeout), borramos vpn:connected y ponemos grace.
# Si el jugador vuelve dentro de GRACE_TTL segundos -> reconexion permitida.
# Si pasan mas de GRACE_TTL sin reconectar -> grace expira -> slot libre.
# ---------------------------------------------------------------------------
CONNECTED_KEY="vpn:connected:${CN}"
GRACE_KEY="vpn:grace:${CN}"

redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" \
    DEL "$CONNECTED_KEY" >/dev/null 2>&1 || true
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" \
    SETEX "$GRACE_KEY" "$GRACE_TTL" "${REAL_IP}:${REAL_PORT}" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# Decision: desconexion limpia (cuenta para ban) vs no-cuenta
# ---------------------------------------------------------------------------
COUNTS="no"
CLASS=""
case "$SIGNAL" in
    remote-exit)
        COUNTS="yes"; CLASS="client_exit_notify" ;;
    ping-restart)
        COUNTS="no";  CLASS="keepalive_timeout" ;;
    sigterm|sigint|sigusr1|sighup)
        COUNTS="no";  CLASS="server_side_signal" ;;
    "")
        if (( DURATION < KEEPALIVE_TIMEOUT )); then
            COUNTS="yes"; CLASS="short_session_assumed_client"
        else
            COUNTS="no";  CLASS="long_session_assumed_timeout"
        fi
        ;;
    *)
        COUNTS="no";  CLASS="unknown_signal_${SIGNAL}" ;;
esac

if [[ "$COUNTS" != "yes" ]]; then
    log_event vpn_disconnect "counts=no class=${CLASS}"
    emit_siem "vpn_disconnect" "info" \
        "{\"counts\":false,\"class\":\"${CLASS}\",\"duration_s\":${DURATION},\"signal\":\"${SIGNAL:-none}\",\"real_ip\":\"${REAL_IP}\",\"real_port\":\"${REAL_PORT}\"}"
    exit 0
fi

# ---------------------------------------------------------------------------
# Desconexion limpia: incrementar contador para ban
# ---------------------------------------------------------------------------
COUNT=""
if ! COUNT=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" \
        INCR "vpn:disc:${TEAM}" 2>/dev/null); then
    log_event vpn_disconnect "counts=yes class=${CLASS} redis=error"
    emit_siem "vpn_disconnect" "warn" \
        "{\"counts\":true,\"class\":\"${CLASS}\",\"duration_s\":${DURATION},\"error\":\"redis_unreachable\"}"
    exit 0
fi
COUNT="$(echo "$COUNT" | tr -dc '0-9')"
COUNT="${COUNT:-0}"

if (( DISC_WINDOW_TTL > 0 )); then
    redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" \
        EXPIRE "vpn:disc:${TEAM}" "$DISC_WINDOW_TTL" >/dev/null 2>&1 || true
fi

log_event vpn_disconnect "counts=yes class=${CLASS} count=${COUNT}/${DISCONNECT_THRESHOLD}"

SEV="info"; (( COUNT >= DISCONNECT_THRESHOLD - 1 )) && SEV="warn"
emit_siem "vpn_disconnect" "$SEV" \
    "{\"counts\":true,\"class\":\"${CLASS}\",\"duration_s\":${DURATION},\"count\":${COUNT},\"threshold\":${DISCONNECT_THRESHOLD},\"real_ip\":\"${REAL_IP}\",\"real_port\":\"${REAL_PORT}\"}"

# ---------------------------------------------------------------------------
# Banear si se alcanzo el umbral
# ---------------------------------------------------------------------------
if (( COUNT >= DISCONNECT_THRESHOLD )); then
    log_event vpn_ban_trigger "count=${COUNT}"
    if [[ -x "$BAN_SCRIPT" ]]; then
        "$BAN_SCRIPT" "$TEAM" "$CN" >> "$EVENTS_LOG" 2>&1 || \
            log_event vpn_ban_error "note=ban_script_failed"
    else
        log_event vpn_ban_error "note=ban_script_missing path=${BAN_SCRIPT}"
    fi
fi

exit 0
