#!/bin/bash
# Smoke-test post-arranque (ejecutar en la VM tras `make up` + `make seed`).
# Verifica que los servicios responden y que el aislamiento de retos es correcto.
# No es exhaustivo: el checklist manual está en docs/INTEGRACION-Y-PRUEBA.md.

set -uo pipefail
cd "$(dirname "$0")"

PASS=0; FAIL=0
ok()   { echo "  [OK]  $1"; PASS=$((PASS+1)); }
bad()  { echo "  [!!]  $1"; FAIL=$((FAIL+1)); }

echo "== 1. Contenedores corriendo =="
for c in ctf-nginx ctf-web ctf-api ctf-flag-service ctf-postgres ctf-redis ctf-collector ctf-loki ctf-promtail ctf-grafana; do
    state=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo "ausente")
    [ "$state" = "running" ] && ok "$c ($state)" || bad "$c ($state)"
done

echo "== 2. Endpoints internos =="
# API health (a través de nginx, como lo ve el jugador)
code=$(docker run --rm --network infra_net_platform curlimages/curl:8.10.1 -s -o /dev/null -w '%{http_code}' http://10.10.100.10/api/health 2>/dev/null || echo 000)
[ "$code" = "200" ] && ok "platform-api /health (200 vía nginx)" || bad "platform-api /health (got $code)"

# Frontend responde
code=$(docker run --rm --network infra_net_platform curlimages/curl:8.10.1 -s -o /dev/null -w '%{http_code}' http://10.10.100.10/ 2>/dev/null || echo 000)
[ "$code" = "200" ] && ok "platform-web (200 vía nginx)" || bad "platform-web (got $code)"

# Flag-service health (red interna)
flag=$(docker run --rm --network infra_net_platform curlimages/curl:8.10.1 -s "http://flag-service:8001/health" 2>/dev/null || echo "")
echo "$flag" | grep -q '"status":"ok"' && ok "flag-service /health" || bad "flag-service /health ($flag)"

# Collector health (red SIEM)
col=$(docker run --rm --network infra_net_siem curlimages/curl:8.10.1 -s "http://collector:9000/health" 2>/dev/null || echo "")
echo "$col" | grep -q '"status":"ok"' && ok "collector /health" || bad "collector /health ($col)"

# Loki ready
code=$(docker run --rm --network infra_net_siem curlimages/curl:8.10.1 -s -o /dev/null -w '%{http_code}' http://loki:3100/ready 2>/dev/null || echo 000)
[ "$code" = "200" ] && ok "loki /ready" || bad "loki /ready (got $code)"

# Grafana en localhost
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3000/api/health 2>/dev/null || echo 000)
[ "$code" = "200" ] && ok "grafana /api/health (localhost)" || bad "grafana /api/health (got $code)"

echo "== 3. Flag dinámica (HMAC por equipo) =="
f1=$(docker run --rm --network infra_net_platform curlimages/curl:8.10.1 -s "http://flag-service:8001/flag?team_id=team_01&challenge_id=web-creditview" | jq -r .flag 2>/dev/null)
f2=$(docker run --rm --network infra_net_platform curlimages/curl:8.10.1 -s "http://flag-service:8001/flag?team_id=team_02&challenge_id=web-reportgen" | jq -r .flag 2>/dev/null)
[[ "$f1" =~ ^HL4\{ && "$f1" != "$f2" ]] && ok "flags distintas por equipo ($f1 != $f2)" || bad "flags por equipo (f1=$f1 f2=$f2)"

echo "== 4. Aislamiento: ningún reto publica puertos al host =="
# Excluye _templates (son scaffolds, no se lanzan).
pub=$(grep -rl --include=docker-compose.yml -E '^\s*ports:' ../challenges 2>/dev/null | grep -v '/_templates/' || true)
[ -z "$pub" ] && ok "ningún docker-compose de reto publica puertos" || bad "estos retos publican puertos: $pub"

echo ""
echo "== RESUMEN ==  OK=$PASS  FALLOS=$FAIL"
[ "$FAIL" -eq 0 ] && echo "Smoke-test verde. Continúa con el checklist manual (INTEGRACION-Y-PRUEBA.md)." \
                  || { echo "Hay fallos: revisa 'docker compose logs' del servicio afectado."; exit 1; }
