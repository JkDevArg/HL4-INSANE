#!/bin/bash
# ============================================================================
#  setup-ccd.sh — Fija cada equipo en SU subnet /24 (client-config-dir)
# ============================================================================
#  PROBLEMA que resuelve: OpenVPN con "server 10.10.0.0 255.255.0.0" reparte
#  IPs de un pool plano /16 (10.10.0.2, 10.10.0.3, ...). Esas IPs NO caen en
#  los rangos por-equipo (10.10.N.0/24) que usa el firewall nftables, así que
#  el aislamiento por equipo NO funciona y el tráfico se bloquea.
#
#  SOLUCIÓN: client-config-dir + ifconfig-push para anclar cada CN a una IP
#  fija dentro de la /24 de su equipo.
#
#  - 1 cert por equipo (team_NN)         -> 10.10.N.2   (1 conexión simultánea)
#  - 4 certs por miembro (team_NN_pM)    -> 10.10.N.1M  (.11 .12 .13 .14)
#    (genera los certs de miembro con gen-team-cert.sh usando esos nombres)
#
#  Ejecutar como root. Idempotente. Tras correrlo: systemctl restart openvpn@server
#  Uso: sudo ./setup-ccd.sh
# ============================================================================
set -euo pipefail

CCD_DIR="/etc/openvpn/ccd"
SERVER_CONF="/etc/openvpn/server.conf"
NETMASK="255.255.0.0"      # topology subnet sobre 10.10.0.0/16

mkdir -p "$CCD_DIR"

for n in $(seq 1 10); do
    team="team_$(printf '%02d' "$n")"
    # IP del cert de equipo (1 conexión): 10.10.N.2
    echo "ifconfig-push 10.10.${n}.2 ${NETMASK}" > "${CCD_DIR}/${team}"

    # IPs de los 4 miembros (si usas certs por miembro team_NN_p1..p4):
    for m in 1 2 3 4; do
        echo "ifconfig-push 10.10.${n}.1${m} ${NETMASK}" > "${CCD_DIR}/${team}_p${m}"
    done
done

# Habilita client-config-dir en el server.conf (idempotente).
grep -q '^client-config-dir' "$SERVER_CONF" || echo "client-config-dir ${CCD_DIR}" >> "$SERVER_CONF"

echo "[OK] CCD configurado en ${CCD_DIR}. Reinicia: systemctl restart openvpn@server"
echo "     team_NN -> 10.10.N.2 ; team_NN_pM -> 10.10.N.1M"
