"""ColdVault Firmware — pwn-binary-05 (PWN INSANE, binario clásico en C).

Este front Python expone el binario C `coldvault` por TCP 9999. Por CADA
conexión:
  - hace fork/exec del binario (un proceso por jugador, aislado),
  - hace de PUENTE bidireccional socket <-> stdio del proceso,
  - LOGUEA todo lo que el jugador envía con `reqlog_tcp(...)` (línea
    `CTFREQ {json}` con proto:"tcp"), de modo que el caster del stream ve
    cada payload (los bytes binarios del exploit salen como `hex:...`).

El binario hereda la env del contenedor (incluida FLAG): el binario lee FLAG
y SÓLO la imprime al alcanzar unlock_vault(). La flag NUNCA está en la imagen
ni en este Python; llega por env en runtime y es por-equipo.

El puente es BYTE-TRANSPARENTE: no interpreta ni recorta el payload, así el
exploit (format string + overflow con bytes crudos, NUL incluidos) llega
intacto al binario.
"""
import os
import socket
import socketserver
import subprocess
import threading

from siem import emit
from reqlog import reqlog_tcp

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "9999"))
BINARY = os.environ.get("VAULT_BIN", "/app/coldvault")

# Umbral heurístico de bytes recibidos para sospechar de un payload de
# explotación de memoria (un cliente normal no manda kilobytes de basura).
SUSPICIOUS_BYTES = 200


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(120)
        src_ip = self.client_address[0]

        # Lanza el firmware C. stdin/stdout puenteados al socket.
        proc = subprocess.Popen(
            [BINARY],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
            env=os.environ.copy(),
        )

        total_in = {"n": 0}
        alerted = {"v": False}

        def sock_to_proc():
            # socket -> stdin del binario. Loguea cada bloque recibido.
            try:
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    try:
                        reqlog_tcp(src_ip, data, label="raw")
                    except Exception:
                        pass
                    total_in["n"] += len(data)
                    # Payload anormalmente grande -> probable overflow/ROP.
                    if not alerted["v"] and total_in["n"] >= SUSPICIOUS_BYTES:
                        alerted["v"] = True
                        try:
                            emit("scan_detected", "alert", src_ip=src_ip,
                                 detail={"reason": "memory-corruption-payload",
                                         "bytes": total_in["n"]})
                        except Exception:
                            pass
                    try:
                        proc.stdin.write(data)
                        proc.stdin.flush()
                    except (BrokenPipeError, ValueError):
                        break
            finally:
                try:
                    proc.stdin.close()
                except Exception:
                    pass

        def proc_to_sock():
            # stdout del binario -> socket.
            try:
                while True:
                    out = proc.stdout.read(4096)
                    if not out:
                        break
                    try:
                        sock.sendall(out)
                    except OSError:
                        break
            finally:
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t1 = threading.Thread(target=sock_to_proc, daemon=True)
        t2 = threading.Thread(target=proc_to_sock, daemon=True)
        t1.start()
        t2.start()

        # Espera a que el binario termine (unlock_vault hace _exit, o EOF/exit).
        try:
            proc.wait(timeout=120)
        except subprocess.TimeoutExpired:
            proc.kill()
        t1.join(timeout=2)
        t2.join(timeout=2)
        try:
            sock.close()
        except OSError:
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server((HOST, PORT), Handler) as srv:
        print(f"[*] ColdVault bridge escuchando en {HOST}:{PORT} -> {BINARY}",
              flush=True)
        srv.serve_forever()
