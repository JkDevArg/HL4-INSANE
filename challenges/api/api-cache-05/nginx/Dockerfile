# api-cache-05 — Edge/CDN simulado (nginx). Servicio "cache". Punto de entrada.
FROM nginx:1.27-alpine

# Config del edge con la cache deception (ver nginx.conf).
COPY nginx.conf /etc/nginx/nginx.conf

# Directorio de cache en disco.
RUN mkdir -p /var/cache/nginx && chown -R nginx:nginx /var/cache/nginx

EXPOSE 8080
