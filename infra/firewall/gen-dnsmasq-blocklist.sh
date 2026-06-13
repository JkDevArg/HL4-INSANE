#!/usr/bin/env bash
# ============================================================================
#  gen-dnsmasq-blocklist.sh — Genera el bloque de sinkhole IA en dnsmasq.conf
# ============================================================================
#  Lee ai-blocklist.txt y reescribe (de forma IDEMPOTENTE) las líneas
#  'address=/<dominio>/0.0.0.0' entre los marcadores:
#
#      # >>> BEGIN AI SINKHOLE ... <<<
#      ...
#      # >>> END AI SINKHOLE <<<
#
#  dentro de dnsmasq.conf. Volver a ejecutarlo reemplaza el bloque sin
#  duplicar líneas. Tras ejecutar, recarga dnsmasq (ver README.md).
#
#  Uso: ./gen-dnsmasq-blocklist.sh [ruta_dnsmasq.conf] [ruta_ai-blocklist.txt]
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DNSMASQ_CONF="${1:-${SCRIPT_DIR}/dnsmasq.conf}"
BLOCKLIST="${2:-${SCRIPT_DIR}/ai-blocklist.txt}"

BEGIN_MARK="# >>> BEGIN AI SINKHOLE"
END_MARK="# >>> END AI SINKHOLE <<<"

# --- Validaciones -----------------------------------------------------------
if [[ ! -f "${DNSMASQ_CONF}" ]]; then
    echo "[ERROR] No existe ${DNSMASQ_CONF}" >&2
    exit 1
fi
if [[ ! -f "${BLOCKLIST}" ]]; then
    echo "[ERROR] No existe ${BLOCKLIST}" >&2
    exit 1
fi
if ! grep -qF "${BEGIN_MARK}" "${DNSMASQ_CONF}" || ! grep -qF "${END_MARK}" "${DNSMASQ_CONF}"; then
    echo "[ERROR] No se encontraron los marcadores BEGIN/END AI SINKHOLE en ${DNSMASQ_CONF}" >&2
    echo "        Asegúrate de usar la plantilla dnsmasq.conf provista." >&2
    exit 1
fi

# --- Construir el bloque de sinkhole a partir de la blocklist ---------------
# Ignora comentarios (#) y líneas vacías; normaliza (minúsculas, sin espacios).
TMP_BLOCK="$(mktemp)"
trap 'rm -f "${TMP_BLOCK}" "${TMP_OUT:-}"' EXIT

{
    echo "${BEGIN_MARK} (autogenerado por gen-dnsmasq-blocklist.sh) <<<"
    echo "# Generado: $(date -u +%Y-%m-%dT%H:%M:%SZ) — NO editar a mano."
    echo "# Cada address=/dominio/0.0.0.0 cubre TODOS sus subdominios."
    COUNT=0
    while IFS= read -r raw; do
        # Quitar comentarios inline y espacios.
        line="${raw%%#*}"
        line="$(echo "${line}" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
        [[ -z "${line}" ]] && continue
        echo "address=/${line}/0.0.0.0"
        COUNT=$((COUNT + 1))
    done < "${BLOCKLIST}"
    echo "${END_MARK}"
    echo "[*] ${COUNT} dominios de IA en sinkhole." >&2
} > "${TMP_BLOCK}"

# --- Reemplazar el bloque existente (idempotente) con awk -------------------
TMP_OUT="$(mktemp)"
awk -v begin="${BEGIN_MARK}" -v endm="${END_MARK}" -v blockfile="${TMP_BLOCK}" '
    BEGIN { inblock = 0 }
    index($0, begin) == 1 {
        inblock = 1
        # Volcar el bloque nuevo en lugar del antiguo.
        while ((getline l < blockfile) > 0) print l
        close(blockfile)
        next
    }
    index($0, endm) == 1 { inblock = 0; next }
    inblock == 0 { print }
' "${DNSMASQ_CONF}" > "${TMP_OUT}"

# Conservar permisos del archivo destino.
cat "${TMP_OUT}" > "${DNSMASQ_CONF}"

echo "[OK] Bloque AI SINKHOLE regenerado en ${DNSMASQ_CONF}"
echo "     Recarga dnsmasq:  sudo systemctl restart dnsmasq"
