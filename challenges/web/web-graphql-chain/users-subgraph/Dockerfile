FROM python:3.11-slim
WORKDIR /app
RUN pip install flask==3.0.0 ariadne==0.23.0
COPY users-subgraph/app/ /app/
EXPOSE 4001
CMD ["python", "app.py"]
