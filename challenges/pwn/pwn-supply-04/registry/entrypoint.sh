#!/bin/sh
# Registry npm INTERNO de Forgewright. Publica el baseline @forge/logger@1.0.0
# (legitimo) y arranca el servidor con UPLOAD ANONIMO (la vuln del reto:
# cualquiera en la red interna puede publicar paquetes sin firma ni revision).
set -e

PKGDIR="${PKGDIR:-/data/packages}"
mkdir -p "$PKGDIR"

# Arranca el registry en background.
node /app/server.js &
REG_PID=$!

# Espera a que el registry responda (node:slim no trae wget; usamos node).
for i in $(seq 1 30); do
  if node -e "require('http').get('http://127.0.0.1:'+(process.env.PORT||8080)+'/-/ping',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))" 2>/dev/null; then
    break
  fi
  sleep 0.5
done

# Publica el baseline legitimo SOLO si aun no existe.
if [ ! -f "$PKGDIR/@forge%2flogger.json" ] && [ ! -f "$PKGDIR/$(printf '%s' '@forge/logger' | sed 's#/#%2f#g').json" ]; then
  echo "[registry] publicando baseline @forge/logger@1.0.0 ..."
  cd /seed/forge-logger
  npm publish --registry "http://127.0.0.1:${PORT:-8080}/" >/tmp/seed.log 2>&1 || {
    echo "[registry] WARN: fallo el publish del baseline:"; cat /tmp/seed.log;
  }
fi

echo "[registry] listo. Sirviendo index npm en :${PORT:-8080}"
wait "$REG_PID"
