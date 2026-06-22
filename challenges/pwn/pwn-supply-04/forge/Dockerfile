# Forgewright CI / forge-runner. Necesita el toolchain de npm para "construir"
# (instalar dependencias y correr lifecycle scripts) los builds de clientes.
FROM node:20-slim

WORKDIR /app
COPY app/ /app/

# Sin dependencias externas: el runner usa solo stdlib de Node + el cliente npm
# que ya trae la imagen base (node:20 incluye npm). El toolchain de build (npm)
# es justamente lo que el runner ejecuta para "construir".

EXPOSE 8080
# La flag llega por env FLAG en runtime, no en la imagen.
CMD ["node", "/app/server.js"]
