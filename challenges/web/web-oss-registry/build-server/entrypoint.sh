#!/bin/sh
set -e
# Write flag at startup
FLAG="${FLAG:-HL4{EJEMPLO_LOCAL}}"
mkdir -p /app/secrets
echo "${FLAG}" > /app/secrets/flag.txt
echo "SECRET_DATA=production_db_password_xyz987" > /app/secrets/config.env
echo "[*] Build server secrets initialized."
exec python /app/app.py
