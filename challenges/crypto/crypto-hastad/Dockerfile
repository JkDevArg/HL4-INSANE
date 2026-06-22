# crypto-hastad — Hastad Broadcast Attack (HTTP/Flask).
FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir flask==3.0.3 pycryptodome==3.20.0 sympy==1.13.1

COPY app/ .

EXPOSE 9999
CMD ["python", "-u", "app.py"]
