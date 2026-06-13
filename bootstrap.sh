#!/usr/bin/env bash
# ============================================================================
#  CTFHL4-INSANE — Bootstrap de despliegue COMPLETO (1 comando)
# ============================================================================
#  Reproduce TODO el stack en un servidor Ubuntu 22.04/24.04 limpio:
#    - Docker (repo oficial) + utilidades
#    - Plataforma + SIEM (docker compose) + seed de equipos/retos
#    - VPN OpenVPN (gateway, DNS interno, hooks de ban) + certs por miembro
#    - DNS interno (dnsmasq) con sinkhole de IA/chatbots
#    - Firewall nftables (aislamiento por equipo, internet permitido, IA off)
#    - Suricata IDS + caster overlay público (anonimizado)
#    - Retos por equipo (opcional)
#
#  Incluye los FIXES descubiertos en producción:
#    * NO reiniciar el servicio nftables (su ExecStop hace flush ruleset y
#      borra las reglas de Docker). Se aplica con `nft -f`.
#    * Reglas raw PREROUTING para que la VPN (tun0) alcance los contenedores
#      (Docker >=27 bloquea acceso directo a IPs de contenedor).
#    * DNS del daemon Docker (daemon.json) para que los `docker build` resuelvan.
#    * client-config-dir para fijar cada equipo/miembro en su /24.
#    * dnsmasq sinkhole loguea "config ... is 0.0.0.0".
#
#  USO (como root, desde la raíz del repo):
#    sudo ./bootstrap.sh <IP_O_DOMINIO_PUBLICO> [opciones]
#  Opciones:
#    --teams N         Nº de equipos (default 10)
#    --no-challenges   No lanzar los retos por equipo (solo infra)
#    --vpn-proto tcp   Protocolo VPN (default udp)
#    --vpn-port N      Puerto VPN (default 1194)
#  Ejemplo:
#    sudo ./bootstrap.sh ctf.midominio.com
#    sudo ./bootstrap.sh 203.0.113.10 --teams 10
# ============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Parámetros
# ---------------------------------------------------------------------------
SERVER_IP="${1:-}"
if [[ -z "$SERVER_IP" || "$SERVER_IP" == --* ]]; then
    echo "ERROR: falta la IP/dominio público." >&2
    echo "Uso: sudo $0 <IP_O_DOMINIO_PUBLICO> [--teams N] [--no-challenges] [--vpn-proto tcp] [--vpn-port N]" >&2
    exit 1
fi
shift || true

TEAMS=10
LAUNCH_CHALLENGES=1
VPN_PROTO="udp"
VPN_PORT="1194"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --teams) TEAMS="$2"; shift 2 ;;
        --no-challenges) LAUNCH_CHALLENGES=0; shift ;;
        --vpn-proto) VPN_PROTO="$2"; shift 2 ;;
        --vpn-port) VPN_PORT="$2"; shift 2 ;;
        *) echo "Opción desconocida: $1" >&2; exit 1 ;;
    esac
done

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: ejecútalo como root (sudo)." >&2
    exit 1
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"
export DEBIAN_FRONTEND=noninteractive EASYRSA_BATCH=1

step() { echo ""; echo "============================================================"; echo ">>> $*"; echo "============================================================"; }

step "CTFHL4-INSANE bootstrap — servidor=${SERVER_IP} equipos=${TEAMS} retos=$([[ $LAUNCH_CHALLENGES -eq 1 ]] && echo si || echo no)"

# ---------------------------------------------------------------------------
# 1) Dependencias + Docker (repo oficial)
# ---------------------------------------------------------------------------
step "1/9 Instalando dependencias y Docker"
apt-get update -qq
apt-get install -y ca-certificates curl gnupg git make jq redis-tools dnsutils nftables iptables-persistent
if ! command -v docker >/dev/null 2>&1; then
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

# DNS del daemon Docker -> los `docker build` resuelven aunque el DNS del host
# sea inestable (evita "Temporary failure in name resolution" en pip).
mkdir -p /etc/docker
if [[ ! -f /etc/docker/daemon.json ]] || ! grep -q '"dns"' /etc/docker/daemon.json; then
    echo '{ "dns": ["1.1.1.1", "8.8.8.8"] }' > /etc/docker/daemon.json
    systemctl restart docker
fi
systemctl enable --now docker

# ---------------------------------------------------------------------------
# 2) .env con secretos
# ---------------------------------------------------------------------------
step "2/9 Generando secretos (.env)"
ENV_FILE="infra/.env"
if [[ ! -f "$ENV_FILE" ]]; then
    cat > "$ENV_FILE" <<EOF
MASTER_SECRET=$(openssl rand -hex 32)
JWT_SECRET=$(openssl rand -hex 32)
POSTGRES_PASSWORD=$(openssl rand -hex 16)
GRAFANA_PASSWORD=$(openssl rand -hex 12)
DISCORD_WEBHOOK_URL=
CTF_NAME=CTFHL4-INSANE
EOF
    echo "[*] .env creado."
else
    echo "[*] .env ya existe, no se sobreescribe."
fi

# ---------------------------------------------------------------------------
# 3) Plataforma + SIEM (docker compose) + seed
# ---------------------------------------------------------------------------
step "3/9 Construyendo y levantando plataforma + SIEM"
( cd infra && docker compose up -d --build )
echo "[*] Esperando a que la API esté lista..."
for i in $(seq 1 30); do
    if docker compose -f infra/docker-compose.yml exec -T platform-api python -c "print('ok')" >/dev/null 2>&1; then break; fi
    sleep 2
done
echo "[*] Seed de equipos y retos..."
docker compose -f infra/docker-compose.yml exec -T platform-api python seed.py || \
    echo "[!] seed falló (¿ya sembrado?). Continuando."

# ---------------------------------------------------------------------------
# 4) VPN OpenVPN
# ---------------------------------------------------------------------------
step "4/9 Configurando OpenVPN"
if [[ ! -f /etc/openvpn/server.conf ]]; then
    rm -rf /etc/openvpn/easy-rsa
    bash vpn/scripts/setup-server.sh "$SERVER_IP" "$VPN_PORT" "$VPN_PROTO"
else
    echo "[*] /etc/openvpn/server.conf ya existe; no se reinicia la PKI."
fi
# Directivas extra (idempotente): gateway+DNS y hooks de ban.
grep -q 'redirect-gateway' /etc/openvpn/server.conf || cat vpn/configs/server-additions.conf     >> /etc/openvpn/server.conf
grep -q 'client-connect'   /etc/openvpn/server.conf || cat vpn/configs/server-ban-additions.conf >> /etc/openvpn/server.conf
# Hooks de ban en su sitio.
mkdir -p /etc/openvpn/scripts
cp vpn/scripts/on-connect.sh vpn/scripts/on-disconnect.sh vpn/scripts/ban-team.sh \
   vpn/scripts/unban.sh vpn/scripts/revoke-team.sh vpn/scripts/gen-team-cert.sh /etc/openvpn/scripts/
chmod +x /etc/openvpn/scripts/*.sh
# IPs fijas por equipo y por miembro (client-config-dir).
bash vpn/scripts/setup-ccd.sh
systemctl restart openvpn@server
sleep 2
ip -br a show tun0 || { echo "ERROR: tun0 no levantó"; exit 1; }

# ---------------------------------------------------------------------------
# 5) DNS interno (dnsmasq) + sinkhole IA
# ---------------------------------------------------------------------------
step "5/9 Configurando DNS interno (dnsmasq + sinkhole IA)"
# Liberar el puerto 53 del stub de systemd-resolved y dar DNS estable al host.
if ! grep -q '^DNSStubListener=no' /etc/systemd/resolved.conf 2>/dev/null; then
    echo 'DNSStubListener=no' >> /etc/systemd/resolved.conf
fi
printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf
systemctl restart systemd-resolved || true
apt-get install -y dnsmasq
( cd infra/firewall && bash gen-dnsmasq-blocklist.sh && cp dnsmasq.conf /etc/dnsmasq.d/ctf.conf )
mkdir -p /var/log/dnsmasq
systemctl restart dnsmasq

# ---------------------------------------------------------------------------
# 6) Suricata IDS (necesita tun0 activo)
# ---------------------------------------------------------------------------
step "6/9 Levantando Suricata IDS"
mkdir -p /var/log/suricata && chmod 777 /var/log/suricata
( cd infra && docker compose -f docker-compose.suricata.yml up -d )

# ---------------------------------------------------------------------------
# 7) Certificados por miembro (4 por equipo)
# ---------------------------------------------------------------------------
step "7/9 Generando certificados (.ovpn) — equipo + 4 miembros"
for n in $(seq 1 "$TEAMS"); do
    t="team_$(printf '%02d' "$n")"
    [[ -f "/etc/openvpn/clients/${t}.ovpn" ]] || bash vpn/scripts/gen-team-cert.sh "$t" "$SERVER_IP" "$VPN_PORT" "$VPN_PROTO" /etc/openvpn/clients >/dev/null 2>&1
    for m in 1 2 3 4; do
        [[ -f "/etc/openvpn/clients/${t}_p${m}.ovpn" ]] || \
            bash vpn/scripts/gen-team-cert.sh "${t}_p${m}" "$SERVER_IP" "$VPN_PORT" "$VPN_PROTO" /etc/openvpn/clients >/dev/null 2>&1
    done
    echo "[*] $t: certs listos"
done

# ---------------------------------------------------------------------------
# 8) Retos por equipo (opcional)
# ---------------------------------------------------------------------------
if [[ "$LAUNCH_CHALLENGES" -eq 1 ]]; then
    step "8/9 Lanzando retos por equipo (puede tardar)"
    chmod +x infra/launch-team-challenges.sh
    for n in $(seq 1 "$TEAMS"); do
        t="team_$(printf '%02d' "$n")"
        bash infra/launch-team-challenges.sh "$t" || echo "[!] fallo lanzando retos de $t"
    done
else
    step "8/9 Retos por equipo OMITIDOS (--no-challenges)"
    echo "    Lánzalos luego con: cd infra && ./launch-team-challenges.sh team_01"
fi

# ---------------------------------------------------------------------------
# 9) Firewall (ÚLTIMO: tras crear las redes de retos, para que las reglas raw
#    cubran los contenedores). Aplica nft (sin reiniciar el servicio) +
#    DOCKER-USER + raw + NAT.
# ---------------------------------------------------------------------------
step "9/9 Aplicando firewall (aislamiento por equipo + internet con IA bloqueada)"
( cd infra/firewall && bash setup-nftables.sh )
# NAT: la VPN sale a internet (IA bloqueada por DNS, no por aquí).
IFACE="$(ip route show default | grep -oP 'dev \K\S+' | head -1)"
if [[ -n "$IFACE" ]]; then
    iptables -t nat -C POSTROUTING -s 10.10.0.0/16 -o "$IFACE" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s 10.10.0.0/16 -o "$IFACE" -j MASQUERADE
    command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------
# Resumen
# ---------------------------------------------------------------------------
GP="$(grep '^GRAFANA_PASSWORD=' infra/.env | cut -d= -f2)"
step "DESPLIEGUE COMPLETO"
cat <<RESUMEN

  Plataforma (jugadores, vía VPN) : http://10.10.100.10
  SIEM público (comentaristas)    : http://${SERVER_IP}:8090   (NO desde la VPN)
  Grafana admin (túnel SSH)       : ssh -L 3000:127.0.0.1:3000 <user>@${SERVER_IP}  -> http://localhost:3000  (admin / ${GP})

  Certificados .ovpn              : /etc/openvpn/clients/  (team_NN_p1..p4 = 1 por integrante)
  Credenciales de equipos         : impresas arriba por seed.py (+ credentials.txt en el contenedor)

  Empaquetar certs para repartir:
    tar -czf ovpn.tar.gz -C /etc/openvpn/clients .

  Operación:
    cd infra && make ps            # estado
    ./launch-team-challenges.sh team_03         # (re)lanzar retos de un equipo
    sudo bash infra/firewall/setup-nftables.sh  # reaplicar firewall si recreas contenedores

  NOTA: tras recrear contenedores Docker reescribe la tabla 'raw'; reaplica el
  firewall (línea de arriba) para que la VPN siga alcanzando los retos.
RESUMEN
