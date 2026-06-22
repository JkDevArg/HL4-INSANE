# crypto-lengthext — MD5 Length Extension Attack (HTTP/Flask).
FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir flask==3.0.3

COPY app/ .

EXPOSE 9999
CMD ["python", "-u", "app.py"]
