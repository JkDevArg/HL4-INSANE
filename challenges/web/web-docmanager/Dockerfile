# web-docmanager — DocManager SOAP XXE (Flask/lxml). Vive solo en la red del equipo.
FROM python:3.12-slim

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

EXPOSE 8080
CMD ["python", "-u", "app.py"]
