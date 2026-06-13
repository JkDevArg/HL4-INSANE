#!/bin/bash
# Revoca el certificado de un equipo (corta su acceso VPN)
# Uso: ./revoke-team.sh <nombre_equipo>

set -euo pipefail

TEAM_NAME="${1:-}"

if [[ -z "$TEAM_NAME" ]]; then
    echo "Uso: $0 <nombre_equipo>"
    exit 1
fi

EASYRSA_DIR="/etc/openvpn/easy-rsa"
cd "$EASYRSA_DIR"

echo "[*] Revocando certificado de $TEAM_NAME..."
echo "yes" | ./easyrsa revoke "$TEAM_NAME"

echo "[*] Regenerando CRL..."
./easyrsa gen-crl
cp pki/crl.pem /etc/openvpn/crl.pem

# Asegurarse que el servidor usa la CRL
if ! grep -q "crl-verify" /etc/openvpn/server.conf; then
    echo "crl-verify crl.pem" >> /etc/openvpn/server.conf
fi

echo "[*] Recargando OpenVPN..."
systemctl reload openvpn@server

echo "[OK] Acceso de $TEAM_NAME revocado."
