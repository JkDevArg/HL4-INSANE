# crypto-ecdsanonce — ECDSA Biased Nonce (HTTP/Flask).
FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir flask==3.0.3 pycryptodome==3.20.0 ecdsa==0.19.0

COPY app/ .

EXPOSE 9999
CMD ["python", "-u", "app.py"]
