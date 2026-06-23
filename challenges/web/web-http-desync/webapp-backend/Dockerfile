FROM python:3.11-slim
WORKDIR /app
RUN pip install flask==3.0.0 gunicorn==21.2.0 --no-cache-dir
COPY webapp-backend/app.py /app/app.py
COPY webapp-backend/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 5000
ENTRYPOINT ["/entrypoint.sh"]
