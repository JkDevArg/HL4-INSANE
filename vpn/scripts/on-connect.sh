#!/bin/bash
# on-connect.sh — script client-connect de OpenVPN.
#
# OpenVPN lo invoca cada vez que un cliente completa el handshake TLS,
# ANTES de habilitarle tráfico. Si este script sale con codigo != 0,
# OpenVPN ABORTA la conexion del cliente (lo desconecta).
#
# Responsabilidades:
#   1. Si el equipo ya esta baneado (Redis ban:team_NN) -> exit 1 (rechaza).
#   2. Loguear la conexion (CN, IP asignada VPN, IP real) en formato parseable.
#   3. Emitir evento SIEM vpn_connect (fire-and-forget).
#
# Variables de entorno que OpenVPN expone a este script:
#   common_name        -> CN del certificado del cliente = team_NN (contrato sec.1)
#   ifconfig_pool_remote_ip -> IP que el server asigna al cliente dentro de 10.10.0.0/16
#   trusted_ip / untrusted_ip -> IP publica real del cliente (origen del tunel)
#   trusted_port       -> puerto de origen real
#
# Dependencias: redis-cli, curl. Configurables por env (ver bloque CONFIG).

set -euo pipefail

# ---------------------------------------------------------------------------
# CONFIG (todo override-able por entorno; OpenVPN no exporta estas, usar
# /etc/openvpn/scripts/ban.env o systemd EnvironmentFile si se desea cambiar)
# ---------------------------------------------------------------------------
REDIS_HOST="${REDIS_HOST:-10.10.100.31}"
REDIS_PORT="${REDIS_PORT:-6379}"
COLLECTOR_URL="${COLLECTOR_URL:-http://10.10.200.10:9000/event}"
EVENTS_LOG="${EVENTS_LOG:-/var/log/openvpn/events.log}"

# Carga opcional de overrides compartidos por todos los scripts de ban.
[[ -f /etc/openvpn/scripts/ban.env ]] && source /etc/openvpn/scripts/ban.env

# ---------------------------------------------------------------------------
# Datos del cliente (con defaults defensivos para no romper set -u)
# ---------------------------------------------------------------------------
TEAM="${common_name:-unknown}"
VPN_IP="${ifconfig_pool_remote_ip:-?}"
REAL_IP="${trusted_ip:-${untrusted_ip:-?}}"
REAL_PORT="${trusted_port:-${untrusted_port:-?}}"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ---------------------------------------------------------------------------
# Helper: emite evento SIEM (fire-and-forget, nunca bloquea ni falla el script)
#   $1 = event_type, $2 = severity, $3 = detail JSON (objeto)
# ---------------------------------------------------------------------------
emit_siem() {
    local event_type="$1" severity="$2" detail="$3"
    local payload
    payload=$(cat <<JSON
{"ts":"${TS}","source":"vpn","team_id":"${TEAM}","user":"${TEAM}","src_ip":"${VPN_IP}","event_type":"${event_type}","severity":"${severity}","detail":${detail}}
JSON
)
    # --max-time corta si el collector no responde; & lo manda a background.
    curl -s -o /dev/null --max-time 3 \
        -H 'Content-Type: application/json' \
        -X POST "$COLLECTOR_URL" -d "$payload" >/dev/null 2>&1 &
    return 0
}

# Helper: log parseable (key=value, una linea). field events.log lo consume.
log_event() {
    # Formato: <ts> evt=<tipo> team=<cn> vpn_ip=<ip> real_ip=<ip:puerto> <extra>
    echo "${TS} evt=$1 team=${TEAM} vpn_ip=${VPN_IP} real_ip=${REAL_IP}:${REAL_PORT} ${2:-}" \
        >> "$EVENTS_LOG"
}

# ---------------------------------------------------------------------------
# 1) Gate de ban: si ban:team_NN existe en Redis -> rechazar conexion.
#    redis-cli EXISTS devuelve "1" si existe, "0" si no. Si Redis esta caido
#    (timeout/err) NO bloqueamos al cliente (fail-open en conectividad) pero lo
#    dejamos registrado; el ban duro real lo refuerza tambien la CRL del cert.
# ---------------------------------------------------------------------------
BANNED="0"
if BANNED=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" --no-raw EXISTS "ban:${TEAM}" 2>/dev/null); then
    BANNED="$(echo "$BANNED" | tr -dc '0-9')"
else
    BANNED="0"   # Redis inaccesible -> no bloqueamos por contador, pero logueamos
    log_event vpn_connect_redis_error "note=redis_unreachable_failopen"
fi

if [[ "$BANNED" == "1" ]]; then
    log_event vpn_connect_rejected "reason=banned"
    emit_siem "vpn_connect" "alert" '{"action":"rejected","reason":"team_banned"}'
    echo "[on-connect] ${TEAM} BANEADO -> conexion rechazada" >&2
    exit 1   # <-- OpenVPN aborta la conexion del cliente
fi

# ---------------------------------------------------------------------------
# 2) + 3) Conexion permitida: log + evento SIEM informativo.
# ---------------------------------------------------------------------------
log_event vpn_connect "action=accepted"
emit_siem "vpn_connect" "info" \
    "{\"action\":\"accepted\",\"real_ip\":\"${REAL_IP}\",\"real_port\":\"${REAL_PORT}\"}"

exit 0
