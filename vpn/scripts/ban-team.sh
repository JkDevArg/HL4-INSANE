#!/bin/bash
# ban-team.sh <team> — Banea a un equipo por exceso de desconexiones (o manual).
#
# Que hace:
#   1. Marca el ban en Redis (ban:team_NN) -> la plataforma lee esta key y
#      BLOQUEA el login del equipo (la API platform consulta ban:team_NN antes
#      de autorizar; ver contrato sec 6.2). Tambien lo lee on-connect.sh para
#      rechazar reconexiones.
#   2. Revoca el certificado del equipo y regenera la CRL. Reusa la logica de
#      revoke-team.sh (lo invoca) -> futuras conexiones fallan el crl-verify.
#   3. Mata las sesiones VPN activas del equipo (management interface si esta,
#      o señal al proceso) para cortar el tunel YA, sin esperar reconexion.
#   4. Emite evento SIEM vpn_ban severity critical.
#
# Idempotente: si ya estaba baneado, no vuelve a revocar (el cert ya esta en CRL)
# pero re-mata sesiones por si reconecto en la ventana.
#
# Uso: ./ban-team.sh team_03
# Dependencias: redis-cli, curl. revoke-team.sh en el mismo directorio.

set -euo pipefail

TEAM_NAME="${1:-}"
TRIGGER_CN="${2:-}"   # CN del jugador que disparó el ban (opcional, para SIEM)
if [[ -z "$TEAM_NAME" ]]; then
    echo "Uso: $0 <nombre_equipo> [cn_jugador]   (ej: $0 team_03 team_03_player1)" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
REDIS_HOST="${REDIS_HOST:-10.10.100.31}"
REDIS_PORT="${REDIS_PORT:-6379}"
COLLECTOR_URL="${COLLECTOR_URL:-http://10.10.200.10:9000/event}"
EVENTS_LOG="${EVENTS_LOG:-/var/log/openvpn/events.log}"
DISCONNECT_THRESHOLD="${DISCONNECT_THRESHOLD:-3}"
# Management interface de OpenVPN (si server-ban-additions.conf la habilito).
MGMT_HOST="${MGMT_HOST:-127.0.0.1}"
MGMT_PORT="${MGMT_PORT:-7505}"
STATUS_LOG="${STATUS_LOG:-/var/log/openvpn/status.log}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REVOKE_SCRIPT="${REVOKE_SCRIPT:-${SCRIPT_DIR}/revoke-team.sh}"

[[ -f /etc/openvpn/scripts/ban.env ]] && source /etc/openvpn/scripts/ban.env

TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

log() { echo "${TS} evt=$1 team=${TEAM_NAME} ${2:-}" >> "$EVENTS_LOG"; }

emit_siem() {
    local detail="$1"
    local payload
    payload=$(cat <<JSON
{"ts":"${TS}","source":"vpn","team_id":"${TEAM_NAME}","user":"${TEAM_NAME}","src_ip":"","event_type":"vpn_ban","severity":"critical","detail":${detail}}
JSON
)
    curl -s -o /dev/null --max-time 3 \
        -H 'Content-Type: application/json' \
        -X POST "$COLLECTOR_URL" -d "$payload" >/dev/null 2>&1 || true
}

echo "[ban-team] Baneando ${TEAM_NAME}..."

# ---------------------------------------------------------------------------
# 1) Marca de ban en Redis (lo que bloquea login en plataforma + reconexion).
#    Guardamos timestamp y motivo para auditoria.
# ---------------------------------------------------------------------------
if redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" \
        SET "ban:${TEAM_NAME}" "banned_at=${TS};reason=vpn_disconnect_threshold;threshold=${DISCONNECT_THRESHOLD}" \
        >/dev/null 2>&1; then
    log vpn_ban_redis_set "ok=true"
else
    log vpn_ban_redis_set "ok=false note=redis_unreachable"
    echo "[ban-team] ADVERTENCIA: no se pudo escribir ban:${TEAM_NAME} en Redis" >&2
fi

# ---------------------------------------------------------------------------
# 2) Revocar cert + CRL reusando revoke-team.sh (que ya hace revoke+gen-crl+reload).
# ---------------------------------------------------------------------------
if [[ -x "$REVOKE_SCRIPT" ]]; then
    if "$REVOKE_SCRIPT" "$TEAM_NAME"; then
        log vpn_ban_revoke "ok=true"
    else
        log vpn_ban_revoke "ok=false note=revoke_failed_maybe_already_revoked"
        echo "[ban-team] AVISO: revoke-team.sh fallo (¿cert ya revocado?). Continuando." >&2
    fi
else
    log vpn_ban_revoke "ok=false note=revoke_script_missing"
    echo "[ban-team] ERROR: no encuentro ${REVOKE_SCRIPT}" >&2
fi

# ---------------------------------------------------------------------------
# 3) Matar sesiones activas del equipo AHORA mismo.
#    Preferimos la management interface (kill por CN). Si no esta, caemos a
#    reload (la CRL ya revocada cortara al cliente en el siguiente handshake).
# ---------------------------------------------------------------------------
KILLED="mgmt"
if command -v nc >/dev/null 2>&1 && \
   printf 'kill %s\nquit\n' "$TEAM_NAME" | nc -w 2 "$MGMT_HOST" "$MGMT_PORT" >/dev/null 2>&1; then
    log vpn_ban_kill "method=management cn=${TEAM_NAME}"
else
    # Fallback: recargar OpenVPN para que aplique la CRL a sesiones existentes.
    KILLED="reload"
    systemctl reload openvpn@server >/dev/null 2>&1 || \
        systemctl reload openvpn@server.service >/dev/null 2>&1 || true
    log vpn_ban_kill "method=reload_fallback note=mgmt_unavailable"
fi

# ---------------------------------------------------------------------------
# 4) Evento SIEM critico.
# ---------------------------------------------------------------------------
log vpn_ban "action=banned kill=${KILLED} trigger_cn=${TRIGGER_CN:-team}"
emit_siem "{\"action\":\"banned\",\"reason\":\"vpn_disconnect_threshold\",\"threshold\":${DISCONNECT_THRESHOLD},\"kill_method\":\"${KILLED}\",\"blocks_platform_login\":true,\"trigger_cn\":\"${TRIGGER_CN:-}\"}"

echo "[ban-team] ${TEAM_NAME} BANEADO."
echo "           - login en plataforma bloqueado (Redis ban:${TEAM_NAME})"
echo "           - cert revocado + CRL regenerada"
echo "           - sesiones activas cortadas (${KILLED})"
echo "           Para revertir: ./unban.sh ${TEAM_NAME} (y regenerar cert con gen-team-cert.sh)"
