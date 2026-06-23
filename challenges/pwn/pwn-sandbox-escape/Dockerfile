FROM python:3.11-slim

WORKDIR /app
COPY app/server.py .

RUN useradd -m ctf

EXPOSE 9998
CMD ["python3", "/app/server.py"]
