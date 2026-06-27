#!/bin/bash
# watch.sh — Re-inserta reglas accept en ip raw PREROUTING después de
# cada docker compose up, para que el tráfico VPN pueda llegar a los
# contenedores de retos aunque Docker (>=26) agregue sus drop rules.
#
# Docker 26+ añade en ip raw PREROUTING:
#   ip daddr <container_ip> iifname != "br-X" drop
# Estas reglas se insertan al FRENTE de la chain en cada 'docker compose up'.
# Este watcher escucha eventos Docker y re-inserta nuestros accepts ENCIMA
# de las drops de Docker cada vez que arranca un contenedor.

VPN_CIDR="172.30.0.0/16"
PLATFORM_CIDR="10.10.100.0/24"
VPN_IFACE="tun0"

log() { echo "[raw-watcher] $*"; }

insert_accepts() {
    # Borrar nuestros accepts anteriores (si ya existen) para evitar duplicados
    # Usa sed en vez de grep -oP (busybox no soporta Perl regex)
    OLD=$(nft -a list chain ip raw PREROUTING 2>/dev/null \
        | grep "iifname.*${VPN_IFACE}.*accept" \
        | sed -n 's/.*# handle \([0-9]*\).*/\1/p' \
        | sort -rn | tr '\n' ' ' || true)
    for h in $OLD; do
        nft delete rule ip raw PREROUTING handle "$h" 2>/dev/null || true
    done

    # Insertar al frente de la chain (antes de cualquier drop de Docker)
    nft insert rule ip raw PREROUTING \
        iifname "${VPN_IFACE}" ip daddr "${PLATFORM_CIDR}" counter accept 2>/dev/null || true
    nft insert rule ip raw PREROUTING \
        iifname "${VPN_IFACE}" ip daddr "${VPN_CIDR}" counter accept 2>/dev/null || true

    log "accepts re-insertados (tun0 → ${VPN_CIDR}, ${PLATFORM_CIDR})"
}

log "Iniciando. Escuchando eventos Docker para re-insertar accepts en ip raw PREROUTING..."
insert_accepts

docker events --filter 'event=start' --filter 'type=container' --format '{{.Actor.Attributes.name}}' \
| while read -r name; do
    log "Contenedor arrancado: ${name} — re-insertando accepts..."
    sleep 0.3
    insert_accepts
done
