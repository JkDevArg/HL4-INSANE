# DevOps Portal (build runner). Necesita pip para instalar dependencias.
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080
# Un solo worker sync + timeout alto: los builds son subprocesos largos.
# La flag NO esta en la imagen: llega por env FLAG en runtime.
CMD ["gunicorn", "-b", "0.0.0.0:8080", "-w", "2", "-k", "sync", "--timeout", "180", "app:app"]
