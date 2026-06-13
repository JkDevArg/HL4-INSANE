# api-graphql-03 — NebulaGraph (GraphQL). Vive solo en la red del equipo.
FROM python:3.12-slim

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

EXPOSE 8080
# La flag llega por env FLAG en runtime, no en la imagen.
CMD ["python", "-u", "server.py"]
