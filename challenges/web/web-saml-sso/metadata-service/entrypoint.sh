#!/bin/sh
set -e
FLAG="${FLAG:-HL4{EJEMPLO_LOCAL}}"
export FLAG
echo "[*] Metadata service starting."
exec python /app/app.py
