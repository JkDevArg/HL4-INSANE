# Template WEB (Flask). Imagen minima.
FROM python:3.12-slim

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

EXPOSE 8080
# La flag NO se copia a la imagen: llega por env FLAG en runtime.
CMD ["gunicorn", "-b", "0.0.0.0:8080", "-w", "2", "app:app"]
