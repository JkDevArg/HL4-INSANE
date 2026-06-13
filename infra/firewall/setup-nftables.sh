#!/usr/bin/env bash
# ============================================================================
#  setup-nftables.sh — Aplica y persiste el firewall de aislamiento CTFHL4
# ============================================================================
#  - Valida la sintaxis de nftables.conf (nft -c -f) ANTES de aplicar.
#  - Lo instala como /etc/nftables.conf y lo aplica.
#  - Habilita el servicio nftables (persistencia tras reboot).
#  - Imprime un resumen del ruleset cargado.
#
#  Plataforma: Ubuntu 22.04. Ejecutar como root en el servidor VPN.
#  Uso: sudo ./setup-nftables.sh
# ============================================================================

set -euo pipefail

# Directorio donde vive este script (para localizar nftables.conf relativo).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_CONF="${SCRIPT_DIR}/nftables.conf"
DST_CONF="/etc/nftables.conf"

# --- Pre-requisitos ---------------------------------------------------------
if [[ "${EUID}" -ne 0 ]]; then
    echo "[ERROR] Debe ejecutarse como root." >&2
    exit 1
fi

if [[ ! -f "${SRC_CONF}" ]]; then
    echo "[ERROR] No se encontró ${SRC_CONF}" >&2
    exit 1
fi

if ! command -v nft >/dev/null 2>&1; then
    echo "[*] nftables no está instalado. Instalando..."
    apt-get update -qq
    apt-get install -y nftables
fi

# --- 1) Validar sintaxis SIN aplicar ---------------------------------------
echo "[*] Validando sintaxis de ${SRC_CONF} ..."
if ! nft -c -f "${SRC_CONF}"; then
    echo "[ERROR] La validación de sintaxis falló. NO se aplicará nada." >&2
    exit 1
fi
echo "[OK] Sintaxis válida."

# --- 2) Respaldar config previa (si existe) --------------------------------
if [[ -f "${DST_CONF}" ]]; then
    BACKUP="${DST_CONF}.bak.$(date +%Y%m%d%H%M%S)"
    cp -a "${DST_CONF}" "${BACKUP}"
    echo "[*] Respaldo de config previa en ${BACKUP}"
fi

# --- 3) Instalar y aplicar --------------------------------------------------
echo "[*] Instalando ${SRC_CONF} -> ${DST_CONF}"
install -m 0644 "${SRC_CONF}" "${DST_CONF}"

echo "[*] Aplicando ruleset..."
nft -f "${DST_CONF}"

# --- 3b) Regla complementaria DOCKER-USER: forward tun0 <-> bridges Docker --
# El aislamiento por equipo lo impone ctf_isolation (prioridad -10). Aquí solo
# habilitamos que Docker no DROPee el forward de/para la VPN. Idempotente.
if command -v iptables >/dev/null 2>&1 && iptables -nL DOCKER-USER >/dev/null 2>&1; then
    echo "[*] Aplicando reglas DOCKER-USER para tun0..."
    iptables -D DOCKER-USER -i tun0 -j ACCEPT 2>/dev/null || true
    iptables -D DOCKER-USER -o tun0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    iptables -I DOCKER-USER -o tun0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -I DOCKER-USER -i tun0 -j ACCEPT
    command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
    echo "[OK] DOCKER-USER permite forward tun0 <-> contenedores."
else
    echo "[!] No se encontró la cadena DOCKER-USER (¿Docker corriendo?). Aplica"
    echo "    luego: sudo iptables -I DOCKER-USER -i tun0 -j ACCEPT"
fi

# --- 3c) CRÍTICO: tabla raw — desactivar la protección anti-acceso-directo ---
# Docker (>=27) añade en 'raw PREROUTING' reglas que DROPean cualquier paquete
# hacia la IP de un contenedor que NO entre por SU bridge. Eso bloquea el acceso
# de los clientes VPN (tun0) a la plataforma y a los retos por su IP. Insertamos
# ACCEPT para tun0 -> subredes del CTF ANTES de esos DROP. Sin esto, NADA del
# tráfico de la VPN llega a los contenedores aunque FORWARD/DOCKER-USER permitan.
if command -v iptables >/dev/null 2>&1; then
    echo "[*] Permitiendo tun0 -> contenedores en la tabla raw..."
    for net in 10.10.100.0/24 172.30.0.0/16; do
        iptables -t raw -D PREROUTING -i tun0 -d "$net" -j ACCEPT 2>/dev/null || true
        iptables -t raw -I PREROUTING -i tun0 -d "$net" -j ACCEPT
    done
    command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
    echo "[OK] raw PREROUTING permite tun0 -> plataforma y retos."
fi

# --- 4) Persistencia (sobrevive reboot) ------------------------------------
# IMPORTANTE: NO hacer "systemctl restart nftables". El ExecStop del servicio
# ejecuta "nft flush ruleset", que borra TAMBIÉN las reglas de Docker
# (iptables-nft) y rompe toda la red de contenedores. El ruleset ya quedó
# aplicado con "nft -f" en el paso 3; aquí solo habilitamos el arranque en boot.
echo "[*] Habilitando servicio nftables para el próximo boot (sin reiniciarlo)..."
systemctl enable nftables >/dev/null 2>&1 || true

# --- 5) Resumen -------------------------------------------------------------
echo ""
echo "==================== RESUMEN DEL FIREWALL ===================="
echo "[*] Tablas cargadas:"
nft list tables
echo ""
echo "[*] Sets/maps de equipos:"
nft list set inet ctf_isolation team_subnets 2>/dev/null || true
nft list set inet ctf_isolation team_docker_pairs 2>/dev/null || true
echo ""
echo "[OK] Firewall de aislamiento aplicado y persistente."
echo "     Logs de bloqueo (prefijos): INTER_TEAM_BLOCK, INTERNET_BLOCK,"
echo "     SIEM_BLOCK, FWD_DROP, INPUT_DROP, AI_BLOCK."
echo "     Visualizar:  journalctl -k -g 'INTER_TEAM_BLOCK|AI_BLOCK' -f"
echo "============================================================="
