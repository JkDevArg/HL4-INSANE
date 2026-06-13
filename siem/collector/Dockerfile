# Imagen del siem-collector (FastAPI). Escucha en 9000 (contrato sección 3).
FROM python:3.12-slim

# Evita .pyc y buffering para que los logs salgan en tiempo real.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Instala dependencias primero para aprovechar la cache de capas.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia el código de la app.
COPY app ./app

EXPOSE 9000

# Healthcheck contra /health.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import httpx,sys; sys.exit(0 if httpx.get('http://127.0.0.1:9000/health').status_code==200 else 1)"

# Arranque con uvicorn. 2 workers es suficiente para la ingesta del CTF.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9000", "--workers", "2"]
