#!/usr/bin/env bash
# check-vps.sh — Verificación de estado pre-CTF
#
# USO: bash check-vps.sh
# Ejecutar en el VPS para confirmar que todo está operativo antes del evento.

set -uo pipefail

GRN='\033[0;32m'; RED='\033[0;31m'; YLW='\033[1;33m'; BLU='\033[0;34m'; NC='\033[0m'

PASS=0; FAIL=0; WARN=0

check() {
    local desc="$1"; shift
    if eval "$@" &>/dev/null; then
        echo -e "  ${GRN}PASS${NC}  $desc"
        (( PASS++ ))
    else
        echo -e "  ${RED}FAIL${NC}  $desc"
        (( FAIL++ ))
    fi
}

warn_check() {
    local desc="$1"; shift
    if eval "$@" &>/dev/null; then
        echo -e "  ${GRN}PASS${NC}  $desc"
        (( PASS++ ))
    else
        echo -e "  ${YLW}WARN${NC}  $desc"
        (( WARN++ ))
    fi
}

separator() {
    echo ""
    echo -e "${BLU}── $* ──────────────────────────────────────${NC}"
}

echo ""
echo -e "${BLU}╔══════════════════════════════════════════╗${NC}"
echo -e "${BLU}║    CTFHL4 - FINAL · Checklist pre-CTF   ║${NC}"
echo -e "${BLU}╚══════════════════════════════════════════╝${NC}"

# ── CONTENEDORES ──────────────────────────────────────────────────────────
separator "Contenedores Docker"

for svc in ctf-nginx ctf-web ctf-api ctf-postgres ctf-redis ctf-flag-service \
           ctf-loki ctf-promtail ctf-caster ctf-grafana ctf-collector ctf-admin-panel; do
    STATUS=$(docker inspect "$svc" --format='{{.State.Status}}' 2>/dev/null || echo "missing")
    if [[ "$STATUS" == "running" ]]; then
        echo -e "  ${GRN}PASS${NC}  $svc (running)"
        (( PASS++ ))
    else
        echo -e "  ${RED}FAIL${NC}  $svc (estado: $STATUS)"
        (( FAIL++ ))
    fi
done

# ── LOKI ──────────────────────────────────────────────────────────────────
separator "SIEM - Loki"
check "Loki endpoint /ready" \
    "docker exec ctf-loki wget -qO- http://localhost:3100/ready | grep -q ready"

# ── SIEM API ──────────────────────────────────────────────────────────────
separator "SIEM - Caster API"
check "GET /api/teams devuelve 5 equipos" \
    "curl -sf http://localhost:8090/api/teams | python3 -c 'import sys,json; d=json.load(sys.stdin); exit(0 if len(d)==5 else 1)'"
check "GET /api/stats responde" \
    "curl -sf http://localhost:8090/api/stats | python3 -m json.tool"

# ── VPN ───────────────────────────────────────────────────────────────────
separator "OpenVPN"
check "openvpn@server activo" "systemctl is-active openvpn@server"
check "Interface tun0 existe" "ip link show tun0"
check "20 archivos .ovpn generados" \
    "test \$(ls /etc/openvpn/clients/*.ovpn 2>/dev/null | wc -l) -eq 20"
check "CCD configurado (20 entradas)" \
    "test \$(ls /etc/openvpn/ccd/ 2>/dev/null | wc -l) -ge 20"

# ── FIREWALL ──────────────────────────────────────────────────────────────
separator "Firewall VPN (nftables)"
check "Regla DROP en DOCKER-USER" \
    "nft list chain ip filter DOCKER-USER 2>/dev/null | grep -q '10.10.0.0/16.*drop\|drop.*10.10.0.0'"
check "Regla accept platform CTF" \
    "nft list chain ip filter DOCKER-USER 2>/dev/null | grep -q '10.10.100.0/24.*accept\|accept.*10.10.100'"
check "ctf-firewall.service habilitado" "systemctl is-enabled ctf-firewall.service"

# ── DNS ───────────────────────────────────────────────────────────────────
separator "DNS sinkhole"
warn_check "dnsmasq activo" "systemctl is-active dnsmasq"
warn_check "Sinkhole ctf configurado" "test -f /etc/dnsmasq.d/ctf-sinkhole.conf"

# ── REDIS ─────────────────────────────────────────────────────────────────
separator "Redis (estado VPN)"
check "Redis responde" \
    "docker exec ctf-redis redis-cli PING | grep -q PONG"
CONNECTED=$(docker exec ctf-redis redis-cli KEYS 'vpn:connected:*' 2>/dev/null | wc -l)
GRACE=$(docker exec ctf-redis redis-cli KEYS 'vpn:grace:*' 2>/dev/null | wc -l)
echo -e "       Sesiones activas: ${CONNECTED} | En grace period: ${GRACE}"

# ── DB ────────────────────────────────────────────────────────────────────
separator "Base de datos"
check "5 equipos en DB" \
    "test \$(docker exec ctf-postgres psql -U ctf -d ctf -tAc 'SELECT COUNT(*) FROM teams;' 2>/dev/null) -eq 5"
check "Retos en DB (>0)" \
    "test \$(docker exec ctf-postgres psql -U ctf -d ctf -tAc 'SELECT COUNT(*) FROM challenges;' 2>/dev/null) -gt 0"

# ── RESUMEN ───────────────────────────────────────────────────────────────
echo ""
echo -e "${BLU}────────────────────────────────────────────────${NC}"
echo -e "  Resultados: ${GRN}PASS: $PASS${NC}  ${RED}FAIL: $FAIL${NC}  ${YLW}WARN: $WARN${NC}"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "  ${RED}NO APTO para el CTF — corrige los FAIL antes de arrancar.${NC}"
    exit 1
elif [[ $WARN -gt 0 ]]; then
    echo -e "  ${YLW}CASI LISTO — revisa los WARN (no son bloqueantes).${NC}"
    exit 0
else
    echo -e "  ${GRN}TODO OK — plataforma lista para el CTF.${NC}"
    exit 0
fi
