#!/bin/bash
# Lanza (o detiene) los retos de UN equipo, aislados en su propia red 172.30.N.0/24.
# Cada reto recibe su FLAG dinámica (flag-service) y TEAM_ID por env.
# El aislamiento entre equipos lo refuerza nftables (infra/firewall): 10.10.N.0/24 → 172.30.N.0/24.
#
# Uso:
#   ./launch-team-challenges.sh team_03        # levanta los retos del equipo 03
#   ./launch-team-challenges.sh team_03 down   # los detiene
#
# Requisitos: docker, jq, el flag-service corriendo (compose principal).

set -euo pipefail

TEAM="${1:-}"
ACTION="${2:-up}"
CHALLENGES_DIR="$(cd "$(dirname "$0")/../challenges" && pwd)"
FLAG_NET="infra_net_platform"   # red del compose principal donde vive flag-service

if [[ ! "$TEAM" =~ ^team_([0-9]{2})$ ]]; then
    echo "Uso: $0 team_NN [up|down]   (ej: team_03)"; exit 1
fi
N=$((10#${BASH_REMATCH[1]}))          # 03 -> 3
TEAM_SUBNET="172.30.${N}.0/24"
TEAM_NET="ctf_${TEAM}"                 # red docker aislada del equipo

# Lista de retos a montar por equipo (ids del catálogo, deben existir en challenges/).
# Octetos dentro de 172.30.N.0/24: web-supply .10/.11, web-ssrf .12/.13(metadata),
# api-bola .20, api-graphql .22, crypto-oracle .30, crypto-aesgcm .33.
CHALLENGES=(
    "web/web-supply-01"
    "web/web-ssrf-02"
    "web/web-jwt-04"
    "web/web-race-05"
    "web/web-proto-03"
    "api/api-bola-01"
    "api/api-bola-02"
    "api/api-graphql-03"
    "api/api-grpc-04"
    "api/api-cache-05"
    "crypto/crypto-oracle-01"
    "crypto/crypto-aesgcm-04"
)

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
