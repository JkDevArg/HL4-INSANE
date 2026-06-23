FROM ubuntu:22.04

RUN apt-get update && apt-get install -y gcc socat \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY src/vuln.c .

# Sin libc, entry manual, sin stack protector, sin PIE, sección W+X para gadgets
RUN gcc -o vuln vuln.c \
        -nostdlib -static \
        -fno-stack-protector \
        -no-pie \
        -Wl,-N \
        -Wl,--entry=main

RUN useradd -m ctf
COPY app/run.sh /app/run.sh
RUN chmod +x /app/run.sh

EXPOSE 9998
CMD ["socat", "TCP-LISTEN:9998,reuseaddr,fork", "EXEC:/app/run.sh,pty,stderr,setsid,sigint,sighup"]
