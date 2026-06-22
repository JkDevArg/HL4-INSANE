# Registry npm INTERNO de Forgewright (implementacion minima en Node).
# Upload ANONIMO habilitado deliberadamente (mala practica del reto).
FROM node:20-slim

WORKDIR /app
COPY server.js /app/server.js
COPY entrypoint.sh /entrypoint.sh
COPY seed/ /seed/
RUN chmod +x /entrypoint.sh

# Token dummy: el servidor IGNORA la auth, pero el cliente npm exige un
# _authToken presente para `npm publish`. Cualquiera publica anonimamente.
RUN printf '//127.0.0.1:8080/:_authToken=anon\nregistry=http://127.0.0.1:8080/\n' > /root/.npmrc

ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
