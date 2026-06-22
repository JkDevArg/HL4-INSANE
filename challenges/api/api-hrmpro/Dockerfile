# api-hrmpro — HRMPro API (mass assignment + type-check bypass)
FROM python:3.11-slim

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

EXPOSE 5005
CMD ["python", "-u", "server.py"]
