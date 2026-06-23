FROM python:3.11-slim
WORKDIR /app
RUN pip install flask==3.0.0 --no-cache-dir
COPY webhook-runner/app/ /app/
COPY webhook-runner/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 9001
ENTRYPOINT ["/entrypoint.sh"]
