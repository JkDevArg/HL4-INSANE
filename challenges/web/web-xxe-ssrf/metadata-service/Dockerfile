FROM python:3.11-slim
WORKDIR /app
RUN pip install flask==3.0.0
COPY metadata-service/app/ /app/
EXPOSE 80
CMD ["python", "app.py"]
