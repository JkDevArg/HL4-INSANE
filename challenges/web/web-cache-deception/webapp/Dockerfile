FROM python:3.11-slim
WORKDIR /app
RUN pip install flask==3.0.0 --no-cache-dir
COPY webapp/app.py /app/app.py
EXPOSE 5000
CMD ["python", "app.py"]
