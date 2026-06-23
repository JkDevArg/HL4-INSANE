FROM python:3.11-slim
WORKDIR /app
RUN pip install "python-socketio[client]" requests eventlet
COPY bot.py /app/
CMD ["python", "bot.py"]
