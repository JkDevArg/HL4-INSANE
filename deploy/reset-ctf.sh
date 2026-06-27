#!/usr/bin/env bash
# reset-ctf.sh — Reseteo completo del CTF para nueva ronda
#
# USO: sudo bash reset-ctf.sh [--confirm]
# Sin --confirm muestra qué haría y pide confirmación.

set -euo pipefail

GRN='\033[0;32m'; RED='\033[0;31m'; YLW='\033[1;33m'; BLU='\033[0;34m'; NC='\033[0m'
REPO_DIR="${REPO_DIR:-/opt/HL4-INSANE}"

log()  { echo -e "${BLU}[$(date +%H:%M:%S)]${NC} $*"; }
ok()   { echo -e "${GRN}  ✓ $*${NC}"; }
warn() { echo -e "${YLW}  ⚠ $*${NC}"; }

if [[ "${1:-}" != "--confirm" ]]; then
    echo ""
    echo -e "${YLW}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${YLW}║    RESET CTF — Esto borrará:                        ║${NC}"
    echo -e "${YLW}║    - Todos los datos de Loki (logs del SIEM)        ║${NC}"
    echo -e "${YLW}║    - Sesiones VPN en Redis (connected, grace, disc) ║${NC}"
    echo -e "${YLW}║    - Puntos y resoluciones de retos en la DB        ║${NC}"
    echo -e "${YLW}║    - Flags (se regeneran con seed.py)               ║${NC}"
    echo -e "${YLW}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    read -p "  ¿Confirmar reset? (escribe 'SI' para continuar): " CONFIRM
    if [[ "$CONFIRM" != "SI" ]]; then
        echo "Cancelado."
        exit 0
    fi
fi

cd "$REPO_DIR/infra"

log "Paso 1/5 — Limpiando Loki (logs SIEM)..."
docker stop ctf-loki ctf-promtail 2>/dev/null || true
docker run --rm -v infra_loki-data:/loki alpine sh -c \
    "rm -rf /loki/chunks/* /loki/index/* /loki/wal/* /loki/compactor/* 2>/dev/null; \
     mkdir -p /loki/chunks /loki/index /loki/wal /loki/compactor; \
     chown -R 10001:10001 /loki" 2>/dev/null
ok "Loki limpio"

log "Paso 2/5 — Generando posiciones actuales para Promtail..."
python3 << 'EOF'
import os, glob
with open("/tmp/positions_reset.yaml", "w") as f:
    f.write("positions:\n")
    for p in [
        "/var/log/openvpn/openvpn.log", "/var/log/openvpn/status.log",
        "/var/log/openvpn/events.log",  "/var/log/syslog",
        "/var/log/suricata/eve.json",   "/var/log/dnsmasq/queries.log",
        "/var/log/kern.log"
    ]:
        for fn in glob.glob(p):
            try:
                f.write(f'  {fn}: "{os.path.getsize(fn)}"\n')
            except: pass
print("  positions.yaml generado")
EOF

docker run --rm \
    -v infra_promtail-positions:/pos \
    -v /tmp/positions_reset.yaml:/src/positions.yaml:ro \
    alpine cp /src/positions.yaml /pos/positions.yaml
ok "Posiciones de Promtail actualizadas"

log "Paso 3/5 — Limpiando Redis (sesiones VPN y contadores)..."
docker exec ctf-redis redis-cli FLUSHDB > /dev/null
ok "Redis limpio"

log "Paso 4/5 — Reseteando DB (nuevas flags y puntos)..."
docker exec ctf-api python seed.py --reset
ok "Base de datos reseteada"

log "Paso 5/5 — Reiniciando SIEM y reaplicando firewall..."
docker compose start loki
docker compose up -d --force-recreate promtail
bash /etc/openvpn/scripts/apply-firewall.sh
ok "SIEM reiniciado, firewall reaplicado"

echo ""
echo -e "${GRN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GRN}║    RESET COMPLETADO — Listo para nueva  ║${NC}"
echo -e "${GRN}║    ronda del CTF.                       ║${NC}"
echo -e "${GRN}╚══════════════════════════════════════════╝${NC}"
echo ""
