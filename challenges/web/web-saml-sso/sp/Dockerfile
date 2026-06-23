FROM python:3.11-slim
WORKDIR /app
RUN pip install flask==3.0.0 lxml==4.9.4 cryptography==41.0.7 requests==2.31.0 --no-cache-dir
COPY sp/app/ /app/
COPY sp/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 8081
ENTRYPOINT ["/entrypoint.sh"]
