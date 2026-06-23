FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    gcc \
    socat \
    libseccomp-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY src/vuln.c .
RUN gcc -o vuln vuln.c -static -no-pie -fstack-protector-all \
    -Wl,-z,noexecstack -lseccomp

RUN useradd -m ctf
COPY app/run.sh /app/run.sh
RUN chmod +x /app/run.sh

EXPOSE 9998
CMD ["socat", "TCP-LISTEN:9998,reuseaddr,fork", "EXEC:/app/run.sh,pty,stderr,setsid,sigint,sighup"]
