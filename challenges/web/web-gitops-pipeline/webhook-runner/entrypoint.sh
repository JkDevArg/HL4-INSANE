#!/bin/sh
set -e
FLAG="${FLAG:-HL4{EJEMPLO_LOCAL}}"
echo "${FLAG}" > /flag.txt
chmod 600 /flag.txt
echo "[*] Webhook runner initialized."
exec python /app/app.py
