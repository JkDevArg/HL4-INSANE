# pwn-pgrce-01 — MoneyPipe API (FastAPI). Servicio "api": punto de entrada.
FROM python:3.12-slim

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

EXPOSE 8080
# La flag llega por env FLAG en runtime, no en la imagen.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
