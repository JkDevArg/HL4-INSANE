FROM gcc:12 AS builder
COPY src/ /src/
RUN gcc -O1 -no-pie -fno-stack-protector \
        -o /delta_checker /src/delta_checker.c

FROM python:3.11-slim
RUN pip install --no-cache-dir flask
COPY --from=builder /delta_checker /app/delta_checker
COPY server/ /app/server/
EXPOSE 6004
CMD ["sh", "-c", "echo \"$FLAG\" > /app/flag.txt && python /app/server/app.py"]
