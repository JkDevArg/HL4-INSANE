FROM python:3.11-slim
WORKDIR /app
RUN pip install requests==2.31.0 --no-cache-dir
COPY admin-bot/bot.py /app/bot.py
CMD ["python", "bot.py"]
