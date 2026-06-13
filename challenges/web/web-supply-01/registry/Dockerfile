# Registry PyPI interno (pypiserver) con upload anonimo (mala practica del reto).
FROM python:3.12-slim

RUN pip install --no-cache-dir pypiserver==2.1.1 setuptools wheel

COPY seed/ /seed/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
