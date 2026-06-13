#!/bin/bash
# ============================================================================
#  ctf-fwassert.sh — Re-asegura las reglas que Docker puede sobrescribir
# ============================================================================
#  Docker (>=27/28) reescribe la tabla 'raw' (y a veces DOCKER-USER) cada vez
#  que crea/recrea contenedores o redes, volviendo a poner sus DROP de
#  protección anti-acceso-directo. Eso re-bloquea a los clientes VPN (tun0)
#  hacia la plataforma y los retos. Este script REINSERTA al tope las reglas
#  que permiten tun0 -> subredes del CTF. Lo ejecuta un timer cada 30s y se
#  invoca al final de launch-team-challenges.sh.
#  Idempotente (borra y reinserta al tope para garantizar el ORDEN).
# ============================================================================
set -u

CTF_NETS="10.10.100.0/24 172.30.0.0/16"

# --- raw PREROUTING: ACCEPT tun0 -> CTF (antes de los DROP de Docker) -------
for net in $CTF_NETS; do
    iptables -t raw -D PREROUTING -i tun0 -d "$net" -j ACCEPT 2>/dev/null || true
    iptables -t raw -I PREROUTING -i tun0 -d "$net" -j ACCEPT
done

# --- DOCKER-USER: forward tun0 <-> contenedores ----------------------------
if iptables -nL DOCKER-USER >/dev/null 2>&1; then
    iptables -D DOCKER-USER -i tun0 -j ACCEPT 2>/dev/null || true
    iptables -D DOCKER-USER -o tun0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    iptables -I DOCKER-USER -o tun0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -I DOCKER-USER -i tun0 -j ACCEPT
fi
