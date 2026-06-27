#!/bin/bash
# Instala y configura OpenVPN + EasyRSA en Ubuntu 22.04
# Ejecutar como root en el servidor

set -euo pipefail

SERVER_IP="${1:-}"
VPN_PORT="${2:-1194}"
VPN_PROTO="${3:-udp}"

if [[ -z "$SERVER_IP" ]]; then
    echo "Uso: $0 <IP_DEL_SERVIDOR> [puerto] [protocolo]"
    echo "Ejemplo: $0 192.168.1.100 1194 udp"
    exit 1
fi

echo "[*] Instalando OpenVPN + EasyRSA..."
apt-get update -qq
apt-get install -y openvpn easy-rsa iptables-persistent

# Inicializar PKI
EASYRSA_DIR="/etc/openvpn/easy-rsa"
mkdir -p "$EASYRSA_DIR"
cp -r /usr/share/easy-rsa/* "$EASYRSA_DIR/"
cd "$EASYRSA_DIR"

echo "[*] Inicializando PKI..."
./easyrsa init-pki

echo "[*] Construyendo CA (sin passphrase para automatización)..."
echo "CTFHL4-CA" | ./easyrsa build-ca nopass

echo "[*] Generando certificado del servidor..."
./easyrsa gen-req ctfhl4-server nopass
echo "yes" | ./easyrsa sign-req server ctfhl4-server

echo "[*] Generando Diffie-Hellman..."
./easyrsa gen-dh

echo "[*] Generando TLS auth key..."
# --genkey tls-auth es la sintaxis para OpenVPN 2.5+; en 2.4 era --genkey --secret
# Intentar nueva sintaxis primero y caer en la vieja si falla.
if openvpn --genkey tls-auth /etc/openvpn/ta.key 2>/dev/null; then
    echo "    ta.key generado (OpenVPN 2.5+ syntax)"
else
    openvpn --genkey --secret /etc/openvpn/ta.key
    echo "    ta.key generado (OpenVPN 2.4 legacy syntax)"
fi

# Copiar archivos necesarios al directorio OpenVPN
cp pki/ca.crt /etc/openvpn/
cp pki/issued/ctfhl4-server.crt /etc/openvpn/
cp pki/private/ctfhl4-server.key /etc/openvpn/
cp pki/dh.pem /etc/openvpn/

echo "[*] Generando configuración del servidor..."
cat > /etc/openvpn/server.conf <<EOF
port $VPN_PORT
proto $VPN_PROTO
dev tun

ca ca.crt
cert ctfhl4-server.crt
key ctfhl4-server.key
dh dh.pem
tls-auth ta.key 0

# Cada equipo en su propia subnet /24
topology subnet
server 10.10.0.0 255.255.192.0

# Habilitar routing entre clientes y hacia challenges
client-to-client
push "route 10.10.100.0 255.255.255.0"
push "route 10.10.200.0 255.255.255.0"
push "redirect-gateway def1"
push "dhcp-option DNS 10.10.0.1"
push "block-outside-dns"

# Logs de conexión (alimentan el SIEM)
status /var/log/openvpn/status.log 10
log-append /var/log/openvpn/openvpn.log
verb 3

# Persistencia
keepalive 10 120
persist-key
persist-tun

# Seguridad — OpenVPN 2.5+ usa data-ciphers; cipher se mantiene como fallback
data-ciphers AES-256-GCM:AES-128-GCM
cipher AES-256-GCM
tls-version-min 1.2
# DCO (Data Channel Offload) bypasea netfilter/nftables completamente.
# Debe estar deshabilitado para que las reglas de firewall/routing funcionen.
disable-dco
EOF

mkdir -p /var/log/openvpn

echo "[*] Habilitando IP forwarding..."
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p

echo "[*] Configurando NAT con nftables..."
IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
# Ubuntu 22.04 usa nftables como backend por defecto. iptables MASQUERADE no tiene efecto.
nft add table ip nat 2>/dev/null || true
nft add chain ip nat POSTROUTING "{ type nat hook postrouting priority 100 ; }" 2>/dev/null || true
nft add rule ip nat POSTROUTING ip saddr 10.10.0.0/16 oifname "$IFACE" masquerade
# Persistir las reglas nftables al reinicio.
nft list ruleset > /etc/nftables.conf
systemctl enable nftables 2>/dev/null || true

echo "[*] Iniciando OpenVPN..."
systemctl enable openvpn@server
systemctl start openvpn@server

echo ""
echo "[OK] OpenVPN configurado."
echo "     Siguiente paso: ./gen-team-cert.sh <nombre_equipo>"
