# crypto-paddingoracle — AES-CBC Noisy Padding Oracle (TCP).
FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir pycryptodome==3.20.0

COPY app/ .

EXPOSE 9999
CMD ["python", "-u", "server.py"]
