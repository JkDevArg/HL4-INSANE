# api-cloudconnect — Cloud Connector API (JWT algorithm confusion RS256→HS256)
FROM python:3.11-slim

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

EXPOSE 5002
CMD ["python", "-u", "server.py"]
