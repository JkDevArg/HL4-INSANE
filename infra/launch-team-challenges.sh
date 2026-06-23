#!/bin/bash
# Lanza (o detiene) los 12 retos asignados a UN equipo, aislados en su red 172.30.N.0/24.
# Cada reto recibe su FLAG dinámica (flag-service) y TEAM_ID/TEAM_N por env.
#
# Estructura: 4 categorías × 3 retos únicos por equipo = 12 retos totales
# IPs por categoría/slot:
#   web:    .10 .11 .12   (puerto 8080)
#   crypto: .20 .21 .22   (puerto 9999)
#   pwn:    .30 .31 .32   (puerto 9998 via socat)
#   rev:    .40 .41 .42   (puerto 8080 serve+submit)
#
# Uso:
#   ./launch-team-challenges.sh team_01        # levanta los retos del equipo 01
#   ./launch-team-challenges.sh team_01 down   # los detiene
#
# Requisitos: docker, jq, flag-service corriendo.

set -euo pipefail

TEAM="${1:-}"
ACTION="${2:-up}"
CHALLENGES_DIR="$(cd "$(dirname "$0")/../challenges" && pwd)"
FLAG_NET="infra_net_platform"

if [[ ! "$TEAM" =~ ^team_([0-9]{2})$ ]]; then
    echo "Uso: $0 team_NN [up|down]   (ej: team_01)"; exit 1
fi
N=$((10#${BASH_REMATCH[1]}))
TEAM_SUBNET="172.30.${N}.0/24"
TEAM_NET="ctf_${TEAM}"

# ---------------------------------------------------------------------------
# Asignación de retos: 3 por categoría por equipo (sin solapamiento entre equipos)
# Formato: "categoria/challenge-id"
# ---------------------------------------------------------------------------
declare -A TEAM_CHALLENGES
TEAM_CHALLENGES["team_01"]="
  web/web-oss-registry
  web/web-gitops-pipeline
  web/web-saml-sso
  crypto/crypto-lattice-ecdsa
  crypto/crypto-jwt-confusion
  crypto/crypto-tls-downgrade
  pwn/pwn-heap-chain
  pwn/pwn-rop-chain
  pwn/pwn-kernel-lpe
  rev/rev-firmware-chain
  rev/rev-malware-dropper
  rev/rev-wasm-chain"

TEAM_CHALLENGES["team_02"]="
  web/web-cache-deception
  web/web-http-desync
  web/web-xxe-ssrf
  crypto/crypto-rsa-lsb
  crypto/crypto-padding-oracle
  crypto/crypto-hash-length-ext
  pwn/pwn-format-string
  pwn/pwn-race-condition
  pwn/pwn-uaf-chain
  rev/rev-vm-bytecode
  rev/rev-go-binary
  rev/rev-dotnet-obf"

TEAM_CHALLENGES["team_03"]="
  web/web-sqli-chain
  web/web-graphql-chain
  web/web-ssti-chain
  crypto/crypto-hastad-broadcast
  crypto/crypto-fermat-rsa
  crypto/crypto-dsa-nonce
  pwn/pwn-seccomp-bypass
  pwn/pwn-pie-leak
  pwn/pwn-vm-escape
  rev/rev-packed-delta
  rev/rev-anti-debug-chain
  rev/rev-llvm-obf"

TEAM_CHALLENGES["team_04"]="
  web/web-oauth-misconfig
  web/web-prototype-pollution
  web/web-websocket-chain
  crypto/crypto-ecdh-invalid
  crypto/crypto-cbc-bitflip
  crypto/crypto-gcm-nonce
  pwn/pwn-srop-chain
  pwn/pwn-off-by-one
  pwn/pwn-sandbox-escape
  rev/rev-rust-binary
  rev/rev-kernel-module
  rev/rev-mobile-apk"

TEAM_CHALLENGES["team_05"]="
  web/web-cors-chain
  web/web-java-deserialization
  web/web-waf-bypass
  crypto/crypto-rsa-crt-fault
  crypto/crypto-bleichenbacher
  crypto/crypto-wiener
  pwn/pwn-aarch64-rop
  pwn/pwn-heap-master
  pwn/pwn-driver-exploit
  rev/rev-symbolic-exec
  rev/rev-taint-analysis
  rev/rev-decompiler-puzzle"

if [[ -z "${TEAM_CHALLENGES[$TEAM]+_}" ]]; then
    echo "Error: equipo '$TEAM' no reconocido (válidos: team_01..team_05)"; exit 1
fi

# Normaliza: elimina espacios/newlines extra y carga en array
readarray -t CHALLENGES < <(echo "${TEAM_CHALLENGES[$TEAM]}" | tr -s ' \n' '\n' | grep -v '^$')

# Obtiene flag dinámica del flag-service
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
            docker compose -p "$proj" -f "${CHALLENGES_DIR}/${c}/docker-compose.yml" down 2>/dev/null || true
    done
    docker network rm "$TEAM_NET" 2>/dev/null || true
    echo "[OK] Retos de $TEAM detenidos."
    exit 0
fi

# Crea la red aislada del equipo si no existe
if ! docker network inspect "$TEAM_NET" >/dev/null 2>&1; then
    echo "[*] Creando red aislada $TEAM_NET ($TEAM_SUBNET)..."
    docker network create --subnet "$TEAM_SUBNET" "$TEAM_NET"
fi

LAUNCHED=0
FAILED=0
for c in "${CHALLENGES[@]}"; do
    cid="$(basename "$c")"
    proj="ctf_${TEAM}_${cid//-/_}"
    echo "[*] Lanzando $cid para $TEAM..."
    FLAG="$(fetch_flag "$cid")"
    if [[ -z "$FLAG" || "$FLAG" == "null" ]]; then
        echo "[!] No se pudo obtener flag para $cid; ¿está arriba flag-service?"
        FAILED=$((FAILED+1))
        continue
    fi
    TEAM_ID="$TEAM" TEAM_N="$N" FLAG="$FLAG" CHAL_NET="$TEAM_NET" \
        docker compose -p "$proj" -f "${CHALLENGES_DIR}/${c}/docker-compose.yml" up -d --build \
        && LAUNCHED=$((LAUNCHED+1)) \
        || { echo "[!] Fallo lanzando $cid"; FAILED=$((FAILED+1)); }
done

echo ""
echo "[OK] $TEAM: $LAUNCHED/${#CHALLENGES[@]} retos montados en $TEAM_NET ($TEAM_SUBNET)."
[[ "$FAILED" -gt 0 ]] && echo "[!] $FAILED reto(s) fallaron."
echo "     nftables debe permitir 10.10.${N}.0/24 → ${TEAM_SUBNET} (ver infra/firewall)."
