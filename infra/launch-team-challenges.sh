#!/bin/bash
# Lanza (o detiene) los retos asignados a UN equipo, aislados en su red 172.30.N.0/24.
# Cada reto recibe su FLAG dinámica (flag-service) y TEAM_ID por env.
# El aislamiento entre equipos lo refuerza nftables (infra/firewall): 10.10.N.0/24 → 172.30.N.0/24.
#
# NOTA: el flujo principal de instanciación es on-demand vía la API (/instances/{id}/start).
# Este script es un fallback para admin o pre-calentamiento.
#
# Uso:
#   ./launch-team-challenges.sh team_01        # levanta los retos del equipo 01
#   ./launch-team-challenges.sh team_01 down   # los detiene
#
# Requisitos: docker, jq, el flag-service corriendo (compose principal).

set -euo pipefail

TEAM="${1:-}"
ACTION="${2:-up}"
CHALLENGES_DIR="$(cd "$(dirname "$0")/../challenges" && pwd)"
FLAG_NET="infra_net_platform"   # red del compose principal donde vive flag-service

if [[ ! "$TEAM" =~ ^team_([0-9]{2})$ ]]; then
    echo "Uso: $0 team_NN [up|down]   (ej: team_01)"; exit 1
fi
N=$((10#${BASH_REMATCH[1]}))          # 01 -> 1
TEAM_SUBNET="172.30.${N}.0/24"
TEAM_NET="ctf_${TEAM}"                 # red docker aislada del equipo

# Asignación de retos por equipo: cada equipo tiene retos únicos (anti-trampas).
# Formato: "categoria/challenge-id"
declare -A TEAM_CHALLENGES
TEAM_CHALLENGES["team_01"]="web/web-creditview api/api-datahub crypto/crypto-rsalsb reversing/rev-customvm"
TEAM_CHALLENGES["team_02"]="web/web-reportgen api/api-cloudconnect crypto/crypto-paddingoracle reversing/rev-gobinary"
TEAM_CHALLENGES["team_03"]="web/web-docmanager api/api-metricstream crypto/crypto-ecdsanonce reversing/rev-wasmcrack"
TEAM_CHALLENGES["team_04"]="web/web-coinswap api/api-securevault crypto/crypto-lengthext reversing/rev-packeddelta"
TEAM_CHALLENGES["team_05"]="web/web-taskflow api/api-hrmpro crypto/crypto-hastad reversing/rev-dotnetobf"

if [[ -z "${TEAM_CHALLENGES[$TEAM]+_}" ]]; then
    echo "Error: equipo '$TEAM' no reconocido (válidos: team_01..team_05)"; exit 1
fi

IFS=' ' read -ra CHALLENGES <<< "${TEAM_CHALLENGES[$TEAM]}"

# Obtiene la flag dinámica del flag-service (a través de un contenedor efímero en su red).
fetch_flag() {
    local cid="$1"
    docker run --rm --network "$FLAG_NET" curlimages/curl:8.10.1 -s \
        "http://flag-service:8001/flag?team_id=${TEAM}&challenge_id=${cid}" \
        | jq -r '.flag'
}

if [[ "$ACTION" == "down" ]]; then
    for c in "${CHALLENGES[@]}"; do
        cid="$(basename "$c")"
        proj="ctf_${TEAM}_${cid//-/_}"
        echo "[*] Deteniendo $cid de $TEAM..."
        TEAM_ID="$TEAM" TEAM_N="$N" FLAG="x" CHAL_NET="$TEAM_NET" \
            docker compose -p "$proj" -f "${CHALLENGES_DIR}/${c}/docker-compose.yml" down || true
    done
    docker network rm "$TEAM_NET" 2>/dev/null || true
    echo "[OK] Retos de $TEAM detenidos."
    exit 0
fi

# Crea la red aislada del equipo si no existe.
if ! docker network inspect "$TEAM_NET" >/dev/null 2>&1; then
    echo "[*] Creando red aislada $TEAM_NET ($TEAM_SUBNET)..."
    docker network create --subnet "$TEAM_SUBNET" "$TEAM_NET"
fi

for c in "${CHALLENGES[@]}"; do
    cid="$(basename "$c")"
    proj="ctf_${TEAM}_${cid//-/_}"
    echo "[*] Generando flag y lanzando $cid para $TEAM..."
    FLAG="$(fetch_flag "$cid")"
    if [[ -z "$FLAG" || "$FLAG" == "null" ]]; then
        echo "[!] No se pudo obtener la flag de $cid; ¿está arriba flag-service?"; exit 1
    fi
    TEAM_ID="$TEAM" TEAM_N="$N" FLAG="$FLAG" CHAL_NET="$TEAM_NET" \
        docker compose -p "$proj" -f "${CHALLENGES_DIR}/${c}/docker-compose.yml" up -d --build
done

echo ""
echo "[OK] Retos de $TEAM montados en $TEAM_NET ($TEAM_SUBNET)."
echo "     nftables debe permitir 10.10.${N}.0/24 → ${TEAM_SUBNET} (ver infra/firewall)."
