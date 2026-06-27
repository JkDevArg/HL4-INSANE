#!/bin/bash
set -e

# Display virtual 800x640 (deja espacio al overlay CTF de 45px)
Xvfb :99 -screen 0 800x640x24 -ac &
export DISPLAY=:99
sleep 1

# VNC server (solo localhost, sin auth)
x11vnc -display :99 -nopw -listen 127.0.0.1 -rfbport 5900 -forever -quiet -noncache &
sleep 1

# noVNC WebSocket proxy (sirve HTML + proxy VNC)
websockify --web /usr/share/novnc/ 6080 127.0.0.1:5900 &

sleep 1

# Bucle para reiniciar el emulador si el jugador lo cierra
while true; do
    SDL_AUDIODRIVER=dummy mgba-sdl -4 /game/POKE_L4BS.gbc 2>/dev/null || true
    sleep 2
done
