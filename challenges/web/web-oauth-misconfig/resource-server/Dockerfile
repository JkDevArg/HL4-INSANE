FROM python:3.11-slim
WORKDIR /app
RUN pip install flask==3.0.0 requests==2.31.0
COPY resource-server/app/ /app/
EXPOSE 9000
CMD ["python", "app.py"]
