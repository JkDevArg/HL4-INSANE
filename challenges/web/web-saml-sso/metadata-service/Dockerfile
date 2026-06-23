FROM python:3.11-slim
WORKDIR /app
RUN pip install flask==3.0.0 --no-cache-dir
COPY metadata-service/app/ /app/
COPY metadata-service/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
