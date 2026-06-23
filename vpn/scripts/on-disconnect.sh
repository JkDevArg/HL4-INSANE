#!/bin/bash
# on-disconnect.sh — script client-disconnect de OpenVPN.
#
# OpenVPN lo invoca cuando una sesion de cliente termina, por CUALQUIER motivo:
#   - El cliente cerro el tunel a proposito (Ctrl-C, "Disconnect", apagar app).
#   - El cliente perdio la red (su keepalive expiro -> ping-restart).
#   - El server lo expulso (reload, --explicit-exit-notify, etc).
#
# Solo nos interesan las desconexiones LIMPIAS iniciadas por el cliente.
# Las caidas por timeout/keepalive NO cuentan para el ban (ver heuristica).
#
# Variables de entorno que OpenVPN expone aqui:
#   common_name        -> CN = team_NN
#   ifconfig_pool_remote_ip -> IP VPN asignada
#   trusted_ip         -> IP publica real
#   time_duration      -> duracion de la sesion en SEGUNDOS (entero)
#   bytes_received / bytes_sent -> trafico de la sesion
#   signal             -> motivo de cierre cuando OpenVPN lo conoce:
#                          "remote-exit"  -> el cliente envio exit-notify (LIMPIO)
#                          "ping-restart" -> timeout de keepalive (NO cuenta)
#                          "sigterm"/"sigint"/"sigusr1" -> el server reinicio (NO cuenta)
#                          (vacio)        -> ambiguo, decide la heuristica por duracion
#
# ---------------------------------------------------------------------------
# HEURISTICA limpia-vs-timeout (documentada, configurable):
#   Cuenta como desconexion del CLIENTE (incrementa contador) si:
#     (a) signal == "remote-exit"  -> exit-notify explicito del cliente, o
#     (b) signal vacio Y time_duration < KEEPALIVE_TIMEOUT (la sesion no
#         murio por inactividad: un timeout siempre dura >= ~120s por el
#         keepalive 10 120 del server.conf, asi que < 120s => cierre voluntario).
#   NO cuenta (timeout / server-side / caida de red prolongada) si:
#     - signal en {ping-restart, sigterm, sigint, sigusr1, sighup}, o
#     - signal vacio Y time_duration >= KEEPALIVE_TIMEOUT (probable timeout).
#
#   Rationale: server.conf tiene "keepalive 10 120" => el server declara muerto
#   a un peer tras ~120s sin respuesta. Una desconexion voluntaria del cliente
#   manda exit-notify (signal=remote-exit) casi siempre; cuando no llega (UDP
#   perdido), la sesion corta (<120s) delata un cierre intencional reciente,
#   mientras que una caida real arrastra hasta el limite del keepalive.
# ---------------------------------------------------------------------------
#
# Dependencias: redis-cli, curl. set -euo pipefail.

set -euo pipefail

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
REDIS_HOST="${REDIS_HOST:-10.10.100.31}"
REDIS_PORT="${REDIS_PORT:-6379}"
COLLECTOR_URL="${COLLECTOR_URL:-http://10.10.200.10:9000/event}"
EVENTS_LOG="${EVENTS_LOG:-/var/log/openvpn/events.log}"
DISCONNECT_THRESHOLD="${DISCONNECT_THRESHOLD:-3}"
# Debe coincidir con el segundo valor de "keepalive 10 120" del server.conf.
KEEPALIVE_TIMEOUT="${KEEPALIVE_TIMEOUT:-120}"
# TTL de la ventana del contador (segundos). Tras este tiempo sin nuevas
# desconexiones limpias, Redis expira el contador (evita acumular caidas de
# red repartidas en todo el evento). 0 = sin expiracion.
DISC_WINDOW_TTL="${DISC_WINDOW_TTL:-0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BAN_SCRIPT="${BAN_SCRIPT:-${SCRIPT_DIR}/ban-team.sh}"

[[ -f /etc/openvpn/scripts/ban.env ]] && source /etc/openvpn/scripts/ban.env

# ---------------------------------------------------------------------------
# Datos de la sesion
# ---------------------------------------------------------------------------
CN="${common_name:-unknown}"
VPN_IP="${ifconfig_pool_remote_ip:-?}"
REAL_IP="${trusted_ip:-${untrusted_ip:-?}}"
DURATION="${time_duration:-0}"
SIGNAL="${signal:-}"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Extrae team_id del CN: "team_01_alice" → "team_01"
if [[ "$CN" =~ ^(team_[0-9]{2})(_(.+))?$ ]]; then
    TEAM="${BASH_REMATCH[1]}"
    PLAYER="${BASH_REMATCH[3]:-}"
else
    TEAM="$CN"
    PLAYER=""
fi

# DURATION debe ser numerico para la comparacion; saneamos.
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
# Decision: clean (cuenta) vs no-cuenta
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
        # Sin signal: decidir por duracion vs keepalive.
        if (( DURATION < KEEPALIVE_TIMEOUT )); then
            COUNTS="yes"; CLASS="short_session_assumed_client"
        else
            COUNTS="no";  CLASS="long_session_assumed_timeout"
        fi
        ;;
    *)
        # Signal desconocido -> conservador: no contar (evita falsos positivos).
        COUNTS="no";  CLASS="unknown_signal_${SIGNAL}" ;;
esac

if [[ "$COUNTS" != "yes" ]]; then
    log_event vpn_disconnect "counts=no class=${CLASS}"
    emit_siem "vpn_disconnect" "info" \
        "{\"counts\":false,\"class\":\"${CLASS}\",\"duration_s\":${DURATION},\"signal\":\"${SIGNAL:-none}\"}"
    exit 0
fi

# ---------------------------------------------------------------------------
# Desconexion LIMPIA del cliente: incrementar contador en Redis.
#   INCR es atomico y crea la key en 0->1 si no existia.
#   Si Redis esta caido, logueamos y salimos sin contar (no podemos banear).
# ---------------------------------------------------------------------------
COUNT=""
if ! COUNT=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" INCR "vpn:disc:${TEAM}" 2>/dev/null); then
    log_event vpn_disconnect "counts=yes class=${CLASS} redis=error"
    emit_siem "vpn_disconnect" "warn" \
        "{\"counts\":true,\"class\":\"${CLASS}\",\"duration_s\":${DURATION},\"error\":\"redis_unreachable\"}"
    exit 0
fi
COUNT="$(echo "$COUNT" | tr -dc '0-9')"
COUNT="${COUNT:-0}"

# Renovar ventana del contador si esta configurada.
if (( DISC_WINDOW_TTL > 0 )); then
    redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" EXPIRE "vpn:disc:${TEAM}" "$DISC_WINDOW_TTL" >/dev/null 2>&1 || true
fi

log_event vpn_disconnect "counts=yes class=${CLASS} count=${COUNT}/${DISCONNECT_THRESHOLD}"

# severity escala al acercarse al umbral.
SEV="info"; (( COUNT >= DISCONNECT_THRESHOLD - 1 )) && SEV="warn"
emit_siem "vpn_disconnect" "$SEV" \
    "{\"counts\":true,\"class\":\"${CLASS}\",\"duration_s\":${DURATION},\"count\":${COUNT},\"threshold\":${DISCONNECT_THRESHOLD}}"

# ---------------------------------------------------------------------------
# Si alcanzo el umbral -> banear.
# ---------------------------------------------------------------------------
if (( COUNT >= DISCONNECT_THRESHOLD )); then
    log_event vpn_ban_trigger "count=${COUNT}"
    if [[ -x "$BAN_SCRIPT" ]]; then
        # Lanzar el ban; no dejamos que un fallo del ban rompa el hook.
        "$BAN_SCRIPT" "$TEAM" >> "$EVENTS_LOG" 2>&1 || \
            log_event vpn_ban_error "note=ban_script_failed"
    else
        log_event vpn_ban_error "note=ban_script_missing path=${BAN_SCRIPT}"
    fi
fi

exit 0
