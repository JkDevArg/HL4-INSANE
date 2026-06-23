FROM python:3.11-slim
WORKDIR /app
RUN pip install flask==3.0.0 flask-socketio==5.3.6 eventlet==0.35.2
COPY app/ /app/
CMD ["python", "app.py"]
