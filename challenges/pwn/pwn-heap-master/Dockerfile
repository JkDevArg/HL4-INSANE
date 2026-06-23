FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    gcc \
    socat \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY src/vuln.c .

RUN gcc -o vuln vuln.c \
        -pie -fPIE \
        -fstack-protector-all \
        -Wl,-z,relro,-z,now

RUN useradd -m ctf
COPY app/run.sh /app/run.sh
RUN chmod +x /app/run.sh

EXPOSE 9999
CMD ["socat", "TCP-LISTEN:9999,reuseaddr,fork", "EXEC:/app/run.sh,pty,stderr,setsid,sigint,sighup"]
