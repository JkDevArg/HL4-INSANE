#!/bin/sh
set -e
FLAG="${FLAG:-HL4{EJEMPLO_LOCAL}}"
export FLAG
ADMIN_TOKEN="${ADMIN_TOKEN:-secret-admin-token-xyz}"
export ADMIN_TOKEN
echo "[*] Starting gunicorn backend..."
# gunicorn with default settings prefers Transfer-Encoding over Content-Length
# which creates the CL.TE desync condition with HAProxy
exec gunicorn app:app \
    --bind 0.0.0.0:5000 \
    --workers 1 \
    --threads 4 \
    --timeout 30 \
    --keep-alive 5 \
    --log-level info
