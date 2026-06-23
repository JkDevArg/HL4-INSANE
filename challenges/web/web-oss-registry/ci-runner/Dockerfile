FROM python:3.11-slim
WORKDIR /app
RUN pip install requests --no-cache-dir
COPY ci-runner/ci_runner.py /app/ci_runner.py
CMD ["python", "ci_runner.py"]
