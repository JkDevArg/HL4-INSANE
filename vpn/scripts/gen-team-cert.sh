#!/bin/bash
# Genera certificado + archivo .ovpn para un equipo
# Uso: ./gen-team-cert.sh <nombre_equipo> <IP_servidor> [puerto] [protocolo]

set -euo pipefail

TEAM_NAME="${1:-}"
SERVER_IP="${2:-}"
VPN_PORT="${3:-1194}"
VPN_PROTO="${4:-udp}"
OUTPUT_DIR="${5:-/etc/openvpn/clients}"

if [[ -z "$TEAM_NAME" || -z "$SERVER_IP" ]]; then
    echo "Uso: $0 <nombre_equipo> <IP_servidor> [puerto] [protocolo] [output_dir]"
    echo "Ejemplo: $0 team_01 192.168.1.100"
    exit 1
fi

EASYRSA_DIR="/etc/openvpn/easy-rsa"
mkdir -p "$OUTPUT_DIR"

cd "$EASYRSA_DIR"

echo "[*] Generando certificado para $TEAM_NAME..."
./easyrsa gen-req "$TEAM_NAME" nopass
echo "yes" | ./easyrsa sign-req client "$TEAM_NAME"

# Leer archivos para embeber en el .ovpn
CA=$(cat pki/ca.crt)
CERT=$(cat "pki/issued/${TEAM_NAME}.crt" | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p')
KEY=$(cat "pki/private/${TEAM_NAME}.key")
TA=$(cat /etc/openvpn/ta.key)

OVPN_FILE="${OUTPUT_DIR}/${TEAM_NAME}.ovpn"

cat > "$OVPN_FILE" <<EOF
client
dev tun
proto $VPN_PROTO
remote $SERVER_IP $VPN_PORT

resolv-retry infinite
nobind
persist-key
persist-tun

remote-cert-tls server
cipher AES-256-GCM
tls-version-min 1.2
verb 3

key-direction 1

<ca>
$CA
</ca>

<cert>
$CERT
</cert>

<key>
$KEY
</key>

<tls-auth>
$TA
</tls-auth>
EOF

chmod 600 "$OVPN_FILE"

echo "[OK] Archivo generado: $OVPN_FILE"
echo "     Entregar SOLO este archivo al equipo $TEAM_NAME"
echo "     Si se filtra, ejecutar: ./revoke-team.sh $TEAM_NAME"
