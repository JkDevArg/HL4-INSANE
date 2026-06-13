FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LOKI_URL=http://loki:3100 \
    WINDOW_MIN=15 \
    CTF_NAME=CTFHL4-INSANE

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY static ./static

# Validación de privacidad en build: si los tests de anonimización fallan,
# la imagen NO se construye (no se permite exponer IPs reales al aire).
RUN python app/anonymize.py

EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=4s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8090/api/health',timeout=3).status==200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8090"]
