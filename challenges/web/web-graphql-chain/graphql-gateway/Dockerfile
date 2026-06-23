FROM python:3.11-slim
WORKDIR /app
RUN pip install flask==3.0.0 ariadne==0.23.0 requests==2.31.0
COPY graphql-gateway/app/ /app/
EXPOSE 8080
CMD ["python", "app.py"]
