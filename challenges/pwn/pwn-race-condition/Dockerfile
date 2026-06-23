FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    gcc \
    socat \
    bash \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY src/reader.c .
RUN gcc -o reader reader.c

RUN useradd -m ctf
# reader binary runs as root but players connect as ctf user
RUN chmod u+s /app/reader

COPY app/run.sh /app/run.sh
RUN chmod +x /app/run.sh

EXPOSE 9998
CMD ["socat", "TCP-LISTEN:9998,reuseaddr,fork", "EXEC:/app/run.sh,pty,stderr,setsid,sigint,sighup"]
