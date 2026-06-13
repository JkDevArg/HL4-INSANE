# Panel de administración del CTF — imagen mínima.
FROM python:3.12-slim

WORKDIR /app

# Dependencias primero (mejor cache de capas).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Código + UI estática.
COPY app/ ./app/
COPY static/ ./static/

# El panel se publica SOLO en 127.0.0.1:8091 desde el compose (túnel SSH).
EXPOSE 8091

# uvicorn en 0.0.0.0 DENTRO del contenedor; el aislamiento lo da el bind del host.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8091"]
