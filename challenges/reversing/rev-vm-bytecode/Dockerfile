FROM gcc:12 AS builder
COPY src/ /src/
RUN gcc -O0 -no-pie -fno-stack-protector \
        -o /vm_checker /src/vm_checker.c

FROM python:3.11-slim
RUN pip install --no-cache-dir flask
COPY --from=builder /vm_checker /app/vm_checker
COPY server/ /app/server/
EXPOSE 6001
CMD ["sh", "-c", "echo \"$FLAG\" > /app/flag.txt && python /app/server/app.py"]
