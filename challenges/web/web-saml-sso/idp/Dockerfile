FROM python:3.11-slim
WORKDIR /app
RUN pip install flask==3.0.0 cryptography==41.0.7 lxml==4.9.4 --no-cache-dir
RUN mkdir -p /app/keys
# Generate RSA key pair at build time (fixed for reproducibility in CTF)
COPY idp/app/ /app/
COPY idp/generate_keys.py /app/generate_keys.py
RUN python /app/generate_keys.py
EXPOSE 8080
CMD ["python", "app.py"]
