"""Template de reto CRYPTO (servicio TCP estilo `nc host port`).

- Lee la flag SOLO de os.environ["FLAG"] (inyectada por equipo).
- Servir por red (NO binario descargable) -> anti-cheat ARCHITECTURE §6.3.

Reemplaza el protocolo de abajo por tu oraculo/esquema real.
"""
import os
import socketserver

FLAG = os.environ.get("FLAG", "HL4{EJEMPLO_LOCAL}").encode()
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "9999"))


class Handler(socketserver.StreamRequestHandler):
    timeout = 60

    def send(self, msg: str) -> None:
        self.wfile.write((msg + "\n").encode())
        self.wfile.flush()

    def handle(self):
        self.send("=== Template crypto service ===")
        self.send("Reemplaza esto por el protocolo del reto.")
        # Ejemplo trivial (NO usar en un reto real): eco.
        while True:
            line = self.rfile.readline()
            if not line:
                break
            data = line.strip()
            if data == b"flag":
                self.send("nope, hay que romper el cripto")
                continue
            self.send("echo: " + data.decode(errors="replace"))


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server((HOST, PORT), Handler) as srv:
        print(f"[*] Escuchando en {HOST}:{PORT}", flush=True)
        srv.serve_forever()
