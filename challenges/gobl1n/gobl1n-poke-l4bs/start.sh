#!/bin/bash

# mgba-sdl se instala en /usr/games en Ubuntu; agregar al PATH
export PATH="/usr/games:$PATH"

Xvfb :99 -screen 0 800x640x24 -ac &
export DISPLAY=:99

# Esperar a que Xvfb cree su socket Unix (más fiable que sleep ciego)
for i in $(seq 1 40); do
    [ -e /tmp/.X11-unix/X99 ] && break
    sleep 0.25
done

x11vnc -display :99 -nopw -listen 127.0.0.1 -rfbport 5900 -forever -quiet -noncache &
sleep 1

websockify --web /usr/share/novnc/ 6080 127.0.0.1:5900 &
sleep 1

# Reiniciar el emulador automáticamente si el jugador lo cierra
while true; do
    SDL_VIDEODRIVER=x11 SDL_AUDIODRIVER=dummy mgba-sdl -4 /game/POKE_L4BS.gbc 2>/dev/null || true
    sleep 2
done
