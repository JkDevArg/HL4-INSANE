#!/bin/bash
# launch-rev-team.sh — Pre-lanza los 3 retos de reversing para un equipo.
# Uso desde ~/HL4-INSANE/infra/:
#   bash launch-rev-team.sh team_01 1
#   bash launch-rev-team.sh team_02 2
#
# Si la instancia ya está corriendo, la salta sin tocarla.
# Requiere: Docker, curl, python3, que la plataforma esté levantada.

set -euo pipefail

TEAM="${1:?Uso: $0 <team_id> <team_n>  (ej: team_01 1)}"
N="${2:?Uso: $0 <team_id> <team_n>  (ej: team_01 1)}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FLAG_SVC="${FLAG_SERVICE_URL:-http://10.10.100.20:8001}"

REV_CHALLENGES=(rev-vm-bytecode rev-go-binary rev-dotnet-obf)

# La red del equipo debe existir. La crea la plataforma al init,
# pero si no existe la creamos aquí con la subred correcta.
CHAL_NET="ctf_${TEAM}"
if ! docker network inspect "${CHAL_NET}" >/dev/null 2>&1; then
    echo "[red]  Creando red ${CHAL_NET} (172.30.${N}.0/24)..."
    docker network create \
        --driver bridge \
        --subnet "172.30.${N}.0/24" \
        "${CHAL_NET}"
fi

echo "=== Lanzando retos REV para ${TEAM} (N=${N}) ==="

for CHAL_ID in "${REV_CHALLENGES[@]}"; do
    COMPOSE_FILE="${ROOT}/challenges/reversing/${CHAL_ID}/docker-compose.yml"

    if [ ! -f "${COMPOSE_FILE}" ]; then
        echo "  [SKIP] ${CHAL_ID} — docker-compose.yml no encontrado"
        continue
    fi

    # Proyecto Docker Compose (guiones → guiones bajos para compatibilidad)
    PROJECT="ctf_${TEAM}_${CHAL_ID//-/_}"

    # Si ya hay contenedores corriendo bajo este proyecto, saltar
    RUNNING=$(docker compose -p "${PROJECT}" -f "${COMPOSE_FILE}" ps --quiet 2>/dev/null | wc -l)
    if [ "${RUNNING}" -gt 0 ]; then
        echo "  [OK]   ${CHAL_ID} ya está corriendo (${RUNNING} contenedor/es)"
        continue
    fi

    # Obtener flag única del flag-service
    FLAG=$(curl -sf "${FLAG_SVC}/flag?team_id=${TEAM}&challenge_id=${CHAL_ID}" \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['flag'])")

    echo "  [UP]   ${CHAL_ID} — arrancando..."
    env TEAM_ID="${TEAM}" TEAM_N="${N}" FLAG="${FLAG}" CHAL_NET="${CHAL_NET}" \
        docker compose -p "${PROJECT}" -f "${COMPOSE_FILE}" up -d --build

    echo "  [OK]   ${CHAL_ID} lanzado"
done

echo ""
echo "Instancias REV activas para ${TEAM}:"
docker ps --filter "name=ctf_${TEAM}_rev" --format "  {{.Names}}  ({{.Status}})"
echo "=== Listo ==="
