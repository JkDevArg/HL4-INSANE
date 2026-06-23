#!/bin/bash
# ============================================================================
#  setup-ccd.sh — Fija cada equipo/jugador en SU subnet (client-config-dir)
# ============================================================================
#  Soporta dos modos:
#    1) Con teams.json  (--config FILE): lee nombres reales de jugadores
#    2) Sin config     (default):        genera team_NN + team_NN_p1..p4
#
#  Estructura de teams.json:
#    {
#      "teams": [
#        {"id": 1, "name": "Bytreach", "players": ["alice", "bob", "charlie", "diana"]},
#        ...
#      ]
#    }
#
#  IPs asignadas (red VPN 10.10.0.0/16):
#    team_NN          -> 10.10.N.2    (cert de equipo, admin)
#    team_NN_<player> -> 10.10.N.1M   (.11 .12 .13 .14 ... hasta .19)
#
#  Uso: sudo ./setup-ccd.sh [--config /ruta/teams.json] [--teams N]
# ============================================================================
set -euo pipefail

CCD_DIR="/etc/openvpn/ccd"
SERVER_CONF="/etc/openvpn/server.conf"
NETMASK="255.255.0.0"
TEAMS=5
CONFIG_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --config) CONFIG_FILE="$2"; shift 2 ;;
        --teams)  TEAMS="$2"; shift 2 ;;
        *) echo "Opción desconocida: $1" >&2; exit 1 ;;
    esac
done

mkdir -p "$CCD_DIR"

if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
    # ── Modo con teams.json ─────────────────────────────────────────────────
    echo "[*] Leyendo configuración desde $CONFIG_FILE..."
    TEAMS=$(jq '.teams | length' "$CONFIG_FILE")
    for idx in $(seq 0 $((TEAMS-1))); do
        n=$(jq -r ".teams[$idx].id" "$CONFIG_FILE")
        team="team_$(printf '%02d' "$n")"
        # Cert de equipo
        echo "ifconfig-push 10.10.${n}.2 ${NETMASK}" > "${CCD_DIR}/${team}"
        # Certs por jugador con nombre real
        players=$(jq -r ".teams[$idx].players[]" "$CONFIG_FILE")
        m=1
        while IFS= read -r player; do
            if [[ $m -gt 9 ]]; then
                echo "[!] Equipo $team: máximo 9 jugadores por equipo (omitiendo $player)"
                break
            fi
            cn="${team}_${player}"
            echo "ifconfig-push 10.10.${n}.1${m} ${NETMASK}" > "${CCD_DIR}/${cn}"
            echo "    $cn -> 10.10.${n}.1${m}"
            m=$((m+1))
        done <<< "$players"
        echo "[*] $team configurado ($((m-1)) jugadores)"
    done
else
    # ── Modo sin config: team_NN + team_NN_p1..p4 ──────────────────────────
    echo "[*] Modo genérico: $TEAMS equipos, 4 miembros cada uno (team_NN_p1..p4)"
    for n in $(seq 1 "$TEAMS"); do
        team="team_$(printf '%02d' "$n")"
        echo "ifconfig-push 10.10.${n}.2 ${NETMASK}" > "${CCD_DIR}/${team}"
        for m in 1 2 3 4; do
            echo "ifconfig-push 10.10.${n}.1${m} ${NETMASK}" > "${CCD_DIR}/${team}_p${m}"
        done
        echo "[*] $team: 10.10.${n}.2 ; miembros: 10.10.${n}.11..14"
    done
fi

# Habilita client-config-dir en el server.conf (idempotente)
grep -q '^client-config-dir' "$SERVER_CONF" || \
    echo "client-config-dir ${CCD_DIR}" >> "$SERVER_CONF"

echo "[OK] CCD configurado en ${CCD_DIR}."
echo "     Reinicia VPN: systemctl restart openvpn@server"
