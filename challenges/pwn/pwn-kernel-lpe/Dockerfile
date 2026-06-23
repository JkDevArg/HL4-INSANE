FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    gcc \
    socat \
    libseccomp-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY src/driver.c .
# Compile WITHOUT ASLR support (process will use personality() to disable ASLR)
RUN gcc -o driver driver.c -no-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -static-libgcc

RUN useradd -m ctf
RUN mkdir -p /root && echo "placeholder" > /root/flag.txt && chmod 400 /root/flag.txt

COPY app/run.sh /app/run.sh
RUN chmod +x /app/run.sh

EXPOSE 9998
# Driver runs as root (uid=0 default in Docker)
CMD ["socat", "TCP-LISTEN:9998,reuseaddr,fork", "EXEC:/app/run.sh,pty,stderr,setsid,sigint,sighup"]
