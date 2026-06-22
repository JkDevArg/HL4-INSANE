# api-datahub — DataHub Analytics API (GraphQL SQLi via custom directive)
FROM python:3.11-slim

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

EXPOSE 5001
# La flag llega por env FLAG en runtime, no en la imagen.
CMD ["python", "-u", "server.py"]
