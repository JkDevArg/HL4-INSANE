FROM python:3.11-slim
WORKDIR /app
RUN pip install flask==3.0.0 werkzeug==3.0.1
COPY app/ /app/
RUN mkdir -p /app/uploads /app/backups /app/data
EXPOSE 8080
ENTRYPOINT ["/bin/sh", "/app/entrypoint.sh"]
