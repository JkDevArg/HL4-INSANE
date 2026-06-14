# api-grpc-04 — SilentChannel gRPC server (grpcio).
FROM python:3.12-slim

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

# Genera los stubs gRPC en build a partir de los .proto del repo.
# (channel.proto = servicio público; vault.proto = servicio admin oculto.)
RUN python -m grpc_tools.protoc -I protos \
      --python_out=. --grpc_python_out=. \
      protos/channel.proto protos/vault.proto

EXPOSE 8080
# La flag llega por env FLAG en runtime, no en la imagen.
CMD ["python", "server.py"]
