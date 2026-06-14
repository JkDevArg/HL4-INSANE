# api-cache-05 — EdgeNews API (FastAPI). Servicio "api" (backend tras el edge).
FROM python:3.12-slim

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

EXPOSE 8000
# La flag llega por env FLAG en runtime, no en la imagen.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
