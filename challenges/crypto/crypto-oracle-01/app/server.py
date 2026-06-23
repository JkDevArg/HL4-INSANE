"""SecureVault — crypto-oracle-01 (Crypto INSANE).

Vulnerabilidad central: PADDING ORACLE (AES-CBC + PKCS#7).

Protocolo de texto sobre TCP (`nc host 9999`):
  - Al conectar, el servicio:
      * genera (o reusa) una clave AES-128 aleatoria por instancia,
      * cifra la FLAG con AES-CBC + PKCS#7 (IV aleatorio prepended),
      * entrega el token en hex: `TOKEN <iv||ct hex>`.
  - Comando `decrypt <hex>`:
      * descifra, valida padding PKCS#7,
      * responde `OK` si el padding es válido, `BAD_PADDING` si no.
    -> esa distinción ES el oráculo que permite recuperar el plaintext.

La FLAG se inyecta por equipo vía env FLAG. NO hardcodeada. La clave es
aleatoria por instancia: no sirve de nada filtrar el binario (se sirve por red).
"""
import os
import socketserver

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from siem import emit
from reqlog import reqlog_tcp

FLAG = os.environ.get("FLAG", "HL4{EJEMPLO_LOCAL}").encode()
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "9999"))
BLOCK = 16

# Clave AES aleatoria, fija durante la vida del proceso (por instancia/equipo).
KEY = get_random_bytes(16)


def pkcs7_pad(data: bytes) -> bytes:
    n = BLOCK - (len(data) % BLOCK)
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK != 0:
        raise ValueError("longitud inválida")
    n = data[-1]
    if n < 1 or n > BLOCK:
        raise ValueError("padding inválido")
    if data[-n:] != bytes([n]) * n:
        raise ValueError("padding inválido")
    return data[:-n]


def encrypt_flag() -> bytes:
    iv = get_random_bytes(BLOCK)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pkcs7_pad(FLAG))
    return iv + ct  # IV prepended


def decrypt_check(token: bytes) -> bool:
    """Devuelve True si el padding PKCS#7 es válido tras descifrar. (EL ORÁCULO)"""
    if len(token) < 2 * BLOCK or len(token) % BLOCK != 0:
        return False
    iv, ct = token[:BLOCK], token[BLOCK:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    try:
        pkcs7_unpad(pt)
        return True
    except ValueError:
        return False


class Handler(socketserver.StreamRequestHandler):
    timeout = 120

    def send(self, msg: str) -> None:
        self.wfile.write((msg + "\n").encode())
        self.wfile.flush()

    def handle(self):
        token = encrypt_flag()
        self.send("=== SecureVault ===")
        self.send("Tu token cifrado (hex, iv||ct):")
        self.send("TOKEN " + token.hex())
        self.send("Comandos: decrypt <hex>  |  quit")

        oracle_calls = 0
        while True:
            raw = self.rfile.readline()
            if not raw:
                break
            # SIEM: loguea los bytes/línea CRUDOS recibidos del jugador.
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
            if line.startswith("decrypt "):
                hexpart = line[len("decrypt "):].strip()
                try:
                    blob = bytes.fromhex(hexpart)
                except ValueError:
                    self.send("ERR hex inválido")
                    continue
                oracle_calls += 1
                # Un padding oracle se delata por MILES de consultas: lo logueamos.
                if oracle_calls == 200:
                    emit("scan_detected", "alert",
                         src_ip=self.client_address[0],
                         detail={"reason": "padding-oracle-bruteforce", "calls": oracle_calls})
                self.send("OK" if decrypt_check(blob) else "BAD_PADDING")
            else:
                self.send("ERR comando desconocido")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server((HOST, PORT), Handler) as srv:
        print(f"[*] SecureVault escuchando en {HOST}:{PORT}", flush=True)
        srv.serve_forever()
