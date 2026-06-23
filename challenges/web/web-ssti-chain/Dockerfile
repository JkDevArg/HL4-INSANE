FROM python:3.11-slim
WORKDIR /app
RUN pip install flask==3.0.0 jinja2==3.1.3
COPY app/ /app/
RUN echo "HL4{PLACEHOLDER}" > /flag.txt && chmod 444 /flag.txt
EXPOSE 8080
CMD ["python", "app.py"]
