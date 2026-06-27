FROM rust:1.75 AS builder
COPY src/ /src/
WORKDIR /src
RUN cargo build --release
# strip is handled by Cargo.toml profile, but run strip for extra safety
RUN strip /src/target/release/wasmcrack || true

FROM python:3.11-slim
RUN pip install --no-cache-dir flask
COPY --from=builder /src/target/release/wasmcrack /app/wasmcrack
COPY server/ /app/server/
EXPOSE 6003
CMD ["sh", "-c", "echo \"$FLAG\" > /app/flag.txt && python /app/server/app.py"]
