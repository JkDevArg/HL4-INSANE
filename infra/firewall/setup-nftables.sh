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

# --- 4) Persistencia (sobrevive reboot) ------------------------------------
echo "[*] Habilitando servicio nftables (persistencia)..."
systemctl enable nftables >/dev/null 2>&1 || true
systemctl restart nftables

# --- 5) Resumen -------------------------------------------------------------
echo ""
echo "==================== RESUMEN DEL FIREWALL ===================="
echo "[*] Tablas cargadas:"
nft list tables
echo ""
echo "[*] Sets/maps de equipos:"
nft list set inet ctf_isolation team_subnets 2>/dev/null || true
nft list map inet ctf_isolation team_to_docker 2>/dev/null || true
echo ""
echo "[OK] Firewall de aislamiento aplicado y persistente."
echo "     Logs de bloqueo (prefijos): INTER_TEAM_BLOCK, INTERNET_BLOCK,"
echo "     SIEM_BLOCK, FWD_DROP, INPUT_DROP, AI_BLOCK."
echo "     Visualizar:  journalctl -k -g 'INTER_TEAM_BLOCK|AI_BLOCK' -f"
echo "============================================================="
