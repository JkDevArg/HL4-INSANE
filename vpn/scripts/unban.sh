#!/bin/bash
# unban.sh <team> — Revierte un ban. SOLO ADMIN.
#
# Que hace:
#   1. Borra la marca de ban en Redis (ban:team_NN) -> reactiva login en plataforma.
#   2. Borra el contador de desconexiones (vpn:disc:team_NN) -> empieza de cero.
#   3. Emite evento SIEM vpn_ban con action=unban (auditoria).
#
# IMPORTANTE — el certificado NO se "des-revoca":
#   ban-team.sh revoco el cert via CRL, y una CRL no admite quitar entradas.
#   Para que el equipo vuelva a conectar por VPN hay que GENERAR UN CERT NUEVO:
#       ./gen-team-cert.sh <team> <IP_servidor>
#   y entregar el nuevo .ovpn. Este script solo limpia el estado de ban/contador.
#
# Uso: ./unban.sh team_03
# Dependencias: redis-cli, curl.

set -euo pipefail

TEAM_NAME="${1:-}"
if [[ -z "$TEAM_NAME" ]]; then
    echo "Uso: $0 <nombre_equipo>   (ej: $0 team_03)" >&2
    exit 1
fi

REDIS_HOST="${REDIS_HOST:-10.10.100.31}"
REDIS_PORT="${REDIS_PORT:-6379}"
COLLECTOR_URL="${COLLECTOR_URL:-http://10.10.200.10:9000/event}"
EVENTS_LOG="${EVENTS_LOG:-/var/log/openvpn/events.log}"

[[ -f /etc/openvpn/scripts/ban.env ]] && source /etc/openvpn/scripts/ban.env

TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
log() { echo "${TS} evt=$1 team=${TEAM_NAME} ${2:-}" >> "$EVENTS_LOG"; }

# Borrar ambas keys (DEL devuelve cuantas borro).
DELETED="0"
if DELETED=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" \
        DEL "ban:${TEAM_NAME}" "vpn:disc:${TEAM_NAME}" 2>/dev/null); then
    DELETED="$(echo "$DELETED" | tr -dc '0-9')"
    log vpn_unban "ok=true keys_deleted=${DELETED:-0}"
else
    log vpn_unban "ok=false note=redis_unreachable"
    echo "[unban] ERROR: Redis inaccesible en ${REDIS_HOST}:${REDIS_PORT}" >&2
    exit 1
fi

# Evento SIEM (action=unban dentro de vpn_ban; severity warn por ser accion admin).
PAYLOAD=$(cat <<JSON
{"ts":"${TS}","source":"vpn","team_id":"${TEAM_NAME}","user":"${TEAM_NAME}","src_ip":"","event_type":"vpn_ban","severity":"warn","detail":{"action":"unban","by":"admin","keys_deleted":${DELETED:-0}}}
JSON
)
curl -s -o /dev/null --max-time 3 -H 'Content-Type: application/json' \
    -X POST "$COLLECTOR_URL" -d "$PAYLOAD" >/dev/null 2>&1 || true

echo "[unban] ${TEAM_NAME} desbaneado:"
echo "        - Redis ban:${TEAM_NAME} y vpn:disc:${TEAM_NAME} borradas (${DELETED:-0} keys)"
echo "        - login en plataforma reactivado"
echo ""
echo "        PASO PENDIENTE (manual): el cert sigue revocado en la CRL."
echo "        Regenera y reentrega el certificado:"
echo "            ./gen-team-cert.sh ${TEAM_NAME} <IP_servidor>"
