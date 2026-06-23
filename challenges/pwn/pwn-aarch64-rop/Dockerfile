FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    gcc-aarch64-linux-gnu \
    qemu-user-static \
    socat \
    libc6-arm64-cross \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY src/vuln.c .

# Cross-compile para AArch64, sin PIE, sin stack protector
RUN aarch64-linux-gnu-gcc -o vuln vuln.c \
        -no-pie \
        -fno-stack-protector \
        -Wl,-z,norelro \
        -static

RUN useradd -m ctf
COPY app/run.sh /app/run.sh
RUN chmod +x /app/run.sh

EXPOSE 9998
CMD ["socat", "TCP-LISTEN:9998,reuseaddr,fork", "EXEC:/app/run.sh,pty,stderr,setsid,sigint,sighup"]
