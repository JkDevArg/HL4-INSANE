#!/bin/sh
# Registry interno PyPI (pypiserver) con UPLOAD ANONIMO habilitado (-P . -a .).
# Mala práctica deliberada: cualquiera en la red interna puede publicar.
set -e

PKGDIR=/data/packages
mkdir -p "$PKGDIR"

# Construir e instalar el sdist baseline legítimo (acme-utils 1.0.0) si falta.
if [ -z "$(ls -A "$PKGDIR" 2>/dev/null | grep acme-utils || true)" ]; then
  echo "[registry] construyendo baseline acme-utils-1.0.0..."
  cd /seed/acme-utils-1.0.0
  python setup.py sdist --dist-dir "$PKGDIR" >/dev/null 2>&1
fi

echo "[registry] sirviendo index en :8080 (upload anonimo habilitado)"
# -P . -a .  => sin autenticacion para upload ni para descarga.
exec pypi-server run -p 8080 -P . -a . "$PKGDIR"
