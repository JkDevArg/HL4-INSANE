#!/bin/sh
# pwn-pgrce-01 — escribe la FLAG (env) a /flag.txt DENTRO del contenedor de
# postgres antes de arrancar la base. La flag NO esta en la imagen ni en la
# DB: solo se alcanza ejecutando un comando del SO (RCE via COPY FROM PROGRAM)
# en este contenedor. Patron: flag SOLO por env.
set -e

: "${FLAG:=flag{EJEMPLO_LOCAL}}"

# Archivo legible por el usuario 'postgres' del SO (quien ejecuta los COPY
# ... FROM PROGRAM). Es el unico sitio donde vive la flag.
printf '%s\n' "$FLAG" > /flag.txt
chmod 0644 /flag.txt

# Cede el control al entrypoint oficial de la imagen postgres.
exec docker-entrypoint.sh "$@"
