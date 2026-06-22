# api-metricstream — MetricStream API (header injection auth bypass)
FROM python:3.11-slim

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

EXPOSE 5003
CMD ["python", "-u", "server.py"]
