# crypto-aesgcm-04 — VaultGCM (TCP). Servir por red, sin binario descargable.
FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir pycryptodome==3.20.0

COPY app/ .

EXPOSE 9999
# La flag llega por env FLAG en runtime, no en la imagen.
CMD ["python", "-u", "server.py"]
