# api-securevault — SecureVault API (JWT kid path traversal → empty HMAC)
FROM python:3.11-slim

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

# Crear directorio de claves con la clave "current"
RUN mkdir -p /keys

EXPOSE 5004
CMD ["sh", "-c", "python /app/setup_keys.py && python -u /app/server.py"]
