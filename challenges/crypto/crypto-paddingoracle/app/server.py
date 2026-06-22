"""NoisyVault — crypto-paddingoracle (Crypto INSANE, servido por TCP).

Vulnerabilidad central: AES-CBC PADDING ORACLE con ruido estadístico.

El oráculo tiene una tasa de error del 5%: responde VALID/INVALID
incorrectamente en 1 de cada 20 consultas. Esto requiere que el atacante:
  1. Consulte cada byte múltiples veces (mínimo 5, recomendado 7-10).
  2. Use el voto mayoritario para determinar la respuesta real.
  3. Implemente el ataque POODLE/CBC-Padding-Oracle completo con este ruido.

Protocolo TCP (nc host 9999):
  - Banner: TOKEN <hex iv||ct> + instrucciones
  - Comandos:
      VERIFY <hex_iv_plus_ciphertext>  → VALID o INVALID (con 5% de error)
      quit
  - La clave AES-256 y el IV son aleatorios al iniciar el proceso.
  - El TOKEN es encrypt(FLAG), IV prepended.
  - El FLAG solo se puede recuperar decifrando via el oráculo.

Nota: la clave es FIJA por instancia (no cambia entre conexiones).
El IV del TOKEN también es fijo (prepended al ciphertext en el banner).
"""
import os
import random
import socketserver

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from siem import emit
from reqlog import reqlog_tcp

FLAG = os.environ.get("FLAG", "flag{EJEMPLO_LOCAL}").encode()
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "9999"))
BLOCK = 16
ERROR_RATE = 0.05  # 5% de respuestas incorrectas

# Clave AES-256 fija por instancia.
KEY = get_random_bytes(32)

# IV + ciphertext de la FLAG (fijo por instancia).
_TOKEN_IV = get_random_bytes(BLOCK)
_CIPHER_INIT = AES.new(KEY, AES.MODE_CBC, _TOKEN_IV)


def pkcs7_pad(data: bytes) -> bytes:
    n = BLOCK - (len(data) % BLOCK)
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK != 0:
        raise ValueError("longitud invalida")
    n = data[-1]
    if n < 1 or n > BLOCK:
        raise ValueError("padding invalido")
    if data[-n:] != bytes([n]) * n:
        raise ValueError("padding invalido")
    return data[:-n]


def _encrypt_flag() -> bytes:
    """Cifra la FLAG con AES-256-CBC. Devuelve IV||CT."""
    iv = get_random_bytes(BLOCK)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pkcs7_pad(FLAG))
    return iv + ct


def _padding_valid(blob: bytes) -> bool:
    """Oráculo REAL: verifica si el padding es válido."""
    if len(blob) < 2 * BLOCK or len(blob) % BLOCK != 0:
        return False
    iv, ct = blob[:BLOCK], blob[BLOCK:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    try:
        pkcs7_unpad(pt)
        return True
    except ValueError:
        return False


def noisy_oracle(blob: bytes) -> bool:
    """Oráculo con ruido: 5% de probabilidad de respuesta incorrecta."""
    real = _padding_valid(blob)
    if random.random() < ERROR_RATE:
        return not real  # miente
    return real


# El TOKEN de la FLAG se genera UNA VEZ al iniciar.
FLAG_TOKEN = _encrypt_flag()


class Handler(socketserver.StreamRequestHandler):
    timeout = 600

    def send(self, msg: str) -> None:
        self.wfile.write((msg + "\n").encode())
        self.wfile.flush()

    def handle(self):
        self.send("=== NoisyVault — oraculo de padding con ruido ===")
        self.send("Token cifrado de la flag (AES-256-CBC, hex iv||ct):")
        self.send("TOKEN " + FLAG_TOKEN.hex())
        self.send("ADVERTENCIA: el oraculo miente el 5% de las veces.")
        self.send("Comandos:")
        self.send("  VERIFY <hex_iv_plus_ciphertext>  -> VALID o INVALID")
        self.send("  quit")
        self.send("")

        oracle_calls = 0
        while True:
            raw = self.rfile.readline()
            if not raw:
                break
            try:
                reqlog_tcp(self.client_address[0], raw, label="line")
            except Exception:
                pass
            line = raw.strip().decode(errors="replace")
            if not line:
                continue

            if line == "quit":
                self.send("bye")
                break

            if line.upper().startswith("VERIFY "):
                hexpart = line[7:].strip()
                try:
                    blob = bytes.fromhex(hexpart)
                except ValueError:
                    self.send("ERR hex invalido")
                    continue
                oracle_calls += 1
                if oracle_calls == 1000:
                    emit("scan_detected", "alert",
                         src_ip=self.client_address[0],
                         detail={"vuln": "noisy-padding-oracle", "calls": oracle_calls})
                result = noisy_oracle(blob)
                self.send("VALID" if result else "INVALID")
                continue

            self.send("ERR comando desconocido")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server((HOST, PORT), Handler) as srv:
        print(f"[*] NoisyVault escuchando en {HOST}:{PORT}", flush=True)
        srv.serve_forever()
