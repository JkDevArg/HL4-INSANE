# web-proto-03 — Doom Templates (Node/Express). Vive solo en la red del equipo.
FROM node:20-slim

WORKDIR /app
COPY app/package.json ./
# EJS 3.1.6 (gadget outputFunctionName) + Express 4. Versiones pineadas a propósito.
RUN npm install --omit=dev --no-audit --no-fund

COPY app/ .

EXPOSE 8080
# La flag llega por env FLAG en runtime, no en la imagen. app.js la escribe a
# /flag.txt en el arranque (objetivo de la cadena prototype-pollution -> RCE).
CMD ["node", "app.js"]
