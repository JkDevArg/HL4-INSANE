#!/bin/sh
set -e
FLAG="${FLAG:-HL4{EJEMPLO_LOCAL}}"
export FLAG
echo "[*] SP starting, flag configured."
exec python /app/app.py
