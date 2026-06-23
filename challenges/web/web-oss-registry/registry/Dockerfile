FROM python:3.11-slim
WORKDIR /app
RUN pip install flask==3.0.0 werkzeug==3.0.1 --no-cache-dir
COPY registry/app/ /app/
RUN mkdir -p /app/packages /app/data
EXPOSE 8080
CMD ["python", "app.py"]
