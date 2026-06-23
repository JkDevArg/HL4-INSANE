FROM python:3.11-slim
WORKDIR /app
RUN pip install flask==3.0.0 lxml==5.1.0 requests==2.31.0
COPY webapp/app/ /app/
RUN mkdir -p /app/uploads
EXPOSE 8080
CMD ["python", "app.py"]
