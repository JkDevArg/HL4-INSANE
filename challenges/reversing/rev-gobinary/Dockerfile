FROM golang:1.21 AS builder
COPY src/ /src/
WORKDIR /src
RUN go build -ldflags="-s -w" -trimpath -o /go_checker main.go

FROM python:3.11-slim
RUN pip install --no-cache-dir flask
COPY --from=builder /go_checker /app/go_checker
COPY server/ /app/server/
EXPOSE 6002
CMD ["sh", "-c", "echo \"$FLAG\" > /app/flag.txt && python /app/server/app.py"]
