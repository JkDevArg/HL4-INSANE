#!/usr/bin/env bash
# ============================================================================
#  ai-ip-blocklist.sh — Bloqueo por IP de proveedores de IA (refuerzo del DNS)
# ============================================================================
#  El sinkhole DNS (dnsmasq) se evade si el cliente usa IPs directas o un
#  DNS propio. Esta capa añade reglas nftables que DROP + LOG (prefijo
#  "AI_BLOCK") rangos CIDR conocidos de proveedores de IA.
#
#  Se monta como una tabla/cadena SEPARADA (inet ctf_ai_block) que se
#  engancha al hook forward con prioridad MÁS ALTA (más temprana) que la
#  tabla de aislamiento, de modo que el tráfico a IA se bloquea primero.
#
#  >>> IMPORTANTE: los CIDR cambian con frecuencia. Los de abajo son
#      PLACEHOLDERS de ejemplo. DEBES poblarlos/actualizarlos (ver más abajo).
#
#  Plataforma: Ubuntu 22.04. Ejecutar como root DESPUÉS de setup-nftables.sh.
#  Uso: sudo ./ai-ip-blocklist.sh
# ============================================================================

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "[ERROR] Debe ejecutarse como root." >&2
    exit 1
fi

# ----------------------------------------------------------------------------
#  CÓMO POBLAR ESTOS RANGOS (los CIDR de los proveedores cambian seguido):
#
#  1) Por número de Sistema Autónomo (ASN). Ejemplos de ASN útiles:
#       - OpenAI            : AS-AS400 / consultar "AS openai" (usan Azure/Cloudflare)
#       - Anthropic         : suele ir tras Google Cloud / Cloudflare
#       - Cloudflare        : AS13335   (claude.ai, muchas APIs IA detrás)
#       - Microsoft/Azure   : AS8075    (Copilot, OpenAI en Azure)
#       - Google            : AS15169   (Gemini)
#     Obtener los prefijos de un ASN (requiere acceso a internet del ADMIN,
#     NO desde la VPN):
#
#       whois -h whois.radb.net -- '-i origin AS13335' | awk '/^route:/ {print $2}'
#
#     o con bgpq4 (recomendado):
#
#       bgpq4 -4 -A AS13335 | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+'
#
#  2) Pegar los CIDR resultantes en el set 'ai_cidrs' de abajo (un elemento
#     por rango). Revisar para NO incluir rangos compartidos con servicios
#     legítimos (Cloudflare/Azure alojan medio internet) — preferir el
#     sinkhole DNS como capa principal y reservar el bloqueo por IP para
#     rangos ESPECÍFICOS de inferencia de IA cuando se conozcan.
#
#  3) Re-ejecutar este script (es idempotente: recrea la tabla).
# ----------------------------------------------------------------------------

# Limpia una versión previa de la tabla (idempotencia).
nft list table inet ctf_ai_block >/dev/null 2>&1 && nft delete table inet ctf_ai_block

nft -f - <<'NFT'
table inet ctf_ai_block {

    # ------------------------------------------------------------------
    #  SET de CIDRs de proveedores de IA.
    #  PLACEHOLDERS DE EJEMPLO — reemplazar por rangos reales (ver arriba).
    #  Documentación-only: NO bloquean nada útil tal cual; ajústalos.
    # ------------------------------------------------------------------
    set ai_cidrs {
        type ipv4_addr
        flags interval
        # comment "Rangos IA — poblar con bgpq4/whois por ASN. PLACEHOLDERS:"
        elements = {
            # --- EJEMPLOS (reemplazar). NO usar en producción tal cual: ---
            # 192.0.2.0/24,      # TEST-NET-1 (RFC 5737) — placeholder visible
            # 198.51.100.0/24,   # TEST-NET-2 (RFC 5737) — placeholder visible
            # 203.0.113.0/24     # TEST-NET-3 (RFC 5737) — placeholder visible
        }
    }

    # Hook forward con prioridad -10: corre ANTES que la tabla de
    # aislamiento (priority filter = 0), para que el bloqueo IA sea lo
    # primero que se evalúa y quede logueado con su propio prefijo.
    chain ai_forward {
        type filter hook forward priority -10; policy accept;

        # Si el set está vacío esta regla no matchea nada (no rompe la red).
        ip daddr @ai_cidrs log prefix "AI_BLOCK " level warn drop
    }
}
NFT

echo "[OK] Tabla inet ctf_ai_block aplicada."
COUNT="$(nft list set inet ctf_ai_block ai_cidrs 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+' | wc -l || true)"
if [[ "${COUNT}" -eq 0 ]]; then
    echo "[AVISO] El set 'ai_cidrs' está VACÍO (solo placeholders comentados)."
    echo "        El bloqueo por IP NO está activo hasta que pobles rangos reales."
    echo "        Mientras tanto, la capa efectiva es el sinkhole DNS (dnsmasq)."
else
    echo "[*] ${COUNT} rangos CIDR de IA en bloqueo."
fi
echo "     Ver logs:  journalctl -k -g 'AI_BLOCK' -f"
