FROM python:3.11-slim
WORKDIR /app
RUN pip install flask==3.0.0 --no-cache-dir
RUN mkdir -p /app/secrets
COPY build-server/app/ /app/
# Flag is written at container startup via entrypoint
COPY build-server/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 9000
ENTRYPOINT ["/entrypoint.sh"]
