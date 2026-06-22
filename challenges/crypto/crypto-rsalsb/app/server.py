"""RSALeak — crypto-rsalsb (Crypto INSANE, servido por TCP).

Vulnerabilidad central: RSA LSB ORACLE (bit de paridad).

RSA-2048 con clave generada aleatoriamente al iniciar el proceso.
La FLAG se cifra con la clave pública. El oráculo permite descifrar
cualquier ciphertext PERO solo revela el bit menos significativo (LSB)
del plaintext resultante.

Ataque:
  Dado ct = flag_pt^e mod n y el oráculo f(c) = (c^d mod n) & 1,
  el jugador hace:
    c_k = (2^e)^k * ct mod n  (multiplicar el ciphertext por 2^e "desplaza" el plaintext)
  Entonces decrypt(c_k) = 2^k * flag_pt mod n.
  El LSB de (2^k * flag_pt mod n) revela si el valor está en la mitad
  superior o inferior del intervalo [0, n). Búsqueda binaria en 2048 pasos.

Protocolo TCP (nc host 9999):
  - Banner: JSON {"n":"<hex>","e":65537,"ct":"<hex>"} + instrucciones
  - Comandos:
      ORACLE <hex_c>   → "0" o "1" (LSB del descifrado)
      ANSWER <hex_pt>  → si hex_pt decodifica a la FLAG, responde con la FLAG
  - Límite: 4096 consultas ORACLE por conexión (suficiente para 2048-bit RSA).
"""
import os
import socketserver
import json

from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, inverse, long_to_bytes, bytes_to_long

from siem import emit
from reqlog import reqlog_tcp

FLAG = os.environ.get("FLAG", "flag{EJEMPLO_LOCAL}").encode()
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "9999"))

MAX_ORACLE_CALLS = 4096

# Generamos la clave RSA-2048 una sola vez al iniciar el proceso.
print("[*] Generando clave RSA-2048... (puede tardar unos segundos)", flush=True)
_rsa_key = RSA.generate(2048)
N = _rsa_key.n
E = _rsa_key.e
D = _rsa_key.d

# Cifrar la FLAG con la clave pública: ct = pt^e mod n
FLAG_PT = bytes_to_long(FLAG)
FLAG_CT = pow(FLAG_PT, E, N)

print(f"[*] RSA-2048 listo. n={N.bit_length()} bits", flush=True)


def lsb_oracle(c_int: int) -> int:
    """Devuelve el LSB (0 o 1) del descifrado de c_int."""
    pt = pow(c_int, D, N)
    return pt & 1


class Handler(socketserver.StreamRequestHandler):
    timeout = 600  # 10 minutos para dar tiempo al ataque

    def send(self, msg: str) -> None:
        self.wfile.write((msg + "\n").encode())
        self.wfile.flush()

    def handle(self):
        # Banner: clave pública + ciphertext cifrado
        banner = json.dumps({
            "n": hex(N),
            "e": E,
            "ct": hex(FLAG_CT),
        })
        self.send("=== RSALeak — oráculo LSB ===")
        self.send("Clave publica y ciphertext de la flag:")
        self.send("PUBKEY " + banner)
        self.send("Comandos:")
        self.send("  ORACLE <hex_c>   -> 0 o 1 (LSB del descifrado)")
        self.send("  ANSWER <hex_pt>  -> envia el plaintext recuperado")
        self.send(f"Limite: {MAX_ORACLE_CALLS} consultas ORACLE por sesion.")
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

            if line.upper().startswith("ORACLE "):
                if oracle_calls >= MAX_ORACLE_CALLS:
                    self.send("ERR limite de consultas alcanzado")
                    continue
                hexpart = line[7:].strip()
                try:
                    c_int = int(hexpart, 16)
                except ValueError:
                    self.send("ERR hex invalido")
                    continue
                if not (0 < c_int < N):
                    self.send("ERR valor fuera de rango [1, n)")
                    continue
                oracle_calls += 1
                if oracle_calls == 512:
                    emit("scan_detected", "alert",
                         src_ip=self.client_address[0],
                         detail={"vuln": "rsa-lsb-oracle", "calls": oracle_calls})
                result = lsb_oracle(c_int)
                self.send(str(result))
                continue

            if line.upper().startswith("ANSWER "):
                hexpart = line[7:].strip()
                try:
                    candidate = bytes.fromhex(hexpart)
                except ValueError:
                    self.send("ERR hex invalido")
                    continue
                if candidate == FLAG:
                    emit("scan_detected", "critical",
                         src_ip=self.client_address[0],
                         detail={"event": "flag-recovered", "oracle_calls": oracle_calls})
                    self.send("CORRECTO! FLAG: " + FLAG.decode())
                else:
                    self.send("INCORRECTO plaintext. Sigue intentando.")
                continue

            self.send("ERR comando desconocido")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server((HOST, PORT), Handler) as srv:
        print(f"[*] RSALeak escuchando en {HOST}:{PORT}", flush=True)
        srv.serve_forever()
