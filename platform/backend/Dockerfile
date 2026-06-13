FROM python:3.12-slim

WORKDIR /app

# Dependencias del sistema minimas (bcrypt/cryptography ya traen wheels).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ app/
COPY seed.py .

EXPOSE 8000

# La siembra se ejecuta aparte: `docker compose run --rm platform-api python seed.py`
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
