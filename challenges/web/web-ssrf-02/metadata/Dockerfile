# web-ssrf-02 metadata — servicio interno simulado (stdlib only).
FROM python:3.12-slim

WORKDIR /app
COPY metadata.py .

EXPOSE 8080
# La flag llega por env FLAG en runtime, no en la imagen.
CMD ["python", "-u", "metadata.py"]
