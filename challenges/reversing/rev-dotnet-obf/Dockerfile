FROM python:3.11-slim AS builder
COPY src/checker.py /src/checker.py
# Compile to .pyc — the magic header + marshal'd code object is the reversing target
RUN python -c "import py_compile; py_compile.compile('/src/checker.py', '/src/checker.pyc', optimize=0)"

FROM python:3.11-slim
RUN pip install --no-cache-dir flask
# Place .pyc in /app so GET /binary serves it
COPY --from=builder /src/checker.pyc /app/checker.pyc
COPY server/app.py /app/app.py
EXPOSE 6005
CMD ["sh", "-c", "echo \"$FLAG\" > /app/flag.txt && python /app/app.py"]
