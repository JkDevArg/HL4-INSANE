"""VaultGCM — crypto-aesgcm-04 (Crypto INSANE, servido por TCP).

Vulnerabilidad central: REUSO DE NONCE en AES-GCM.

GCM calcula el tag como:
    T = GHASH_H(AAD, C) XOR E_K(J0)
donde H = E_K(0^128) (la "authentication key") y J0 depende SOLO del nonce.
Si el nonce se REUSA, E_K(J0) es constante entre mensajes. Con dos (o más)
pares (ciphertext, tag) bajo el mismo nonce, la diferencia de los polinomios
GHASH da una ecuación polinómica en H sobre GF(2^128); resolviéndola se recupera
H y, con él, se pueden FORJAR tags válidos para cualquier ciphertext elegido.

Protocolo de texto sobre TCP (`nc host 9999`):
  - Banner: muestra el comando objetivo (admin) que hay que forjar.
  - `encrypt <hex>`  -> cifra el plaintext (clave fija, NONCE REUSADO) y devuelve
                        `nonce||ct||tag` en hex. ES el oráculo de nonce-reuse.
  - `command <ct_hex> <tag_hex>` -> descifra con el nonce fijo, verifica el tag y,
                        si es válido Y el plaintext == comando admin, entrega la FLAG.
  - `quit`

La clave AES y el nonce son aleatorios por instancia (NO hardcodeados). La FLAG
se inyecta por equipo vía env FLAG. Se sirve por red: no hay binario descargable.
"""
import os
import socketserver

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from siem import emit

FLAG = os.environ.get("FLAG", "flag{EJEMPLO_LOCAL}")
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "9999"))

# Comando que el jugador debe FORJAR (ct+tag válidos) para ganar.
ADMIN_CMD = b'{"action":"reveal_flag","role":"admin"}'

# Clave AES-128 y NONCE de 12 bytes: aleatorios por instancia... y el nonce se
# REUSA en cada cifrado (la vulnerabilidad).
KEY = get_random_bytes(16)
NONCE = get_random_bytes(12)


def gcm_encrypt(plaintext: bytes):
    """Cifra con AES-GCM reusando SIEMPRE el mismo NONCE. Devuelve (ct, tag)."""
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=NONCE)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return ct, tag


def gcm_verify_decrypt(ct: bytes, tag: bytes):
    """Descifra y verifica el tag con el nonce fijo. Lanza si el tag no valida."""
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=NONCE)
    return cipher.decrypt_and_verify(ct, tag)  # ValueError si tag inválido


class Handler(socketserver.StreamRequestHandler):
    timeout = 180

    def send(self, msg: str) -> None:
        self.wfile.write((msg + "\n").encode())
        self.wfile.flush()

    def handle(self):
        self.send("=== VaultGCM — firmador de comandos AES-GCM ===")
        self.send("Comandos:")
        self.send("  encrypt <hex>            -> nonce||ct||tag (hex)")
        self.send("  command <ct_hex> <tag_hex> -> ejecuta si el tag es válido")
        self.send("  quit")
        self.send("")
        self.send("Para obtener la FLAG, ejecuta este comando admin (forja su ct+tag):")
        self.send("  PLAINTEXT_OBJETIVO = " + ADMIN_CMD.decode())
        self.send("")

        enc_calls = 0
        while True:
            raw = self.rfile.readline()
            if not raw:
                break
            line = raw.strip().decode(errors="replace")
            if not line:
                continue

            if line == "quit":
                self.send("bye")
                break

            if line.startswith("encrypt "):
                hexpart = line[len("encrypt "):].strip()
                try:
                    pt = bytes.fromhex(hexpart)
                except ValueError:
                    self.send("ERR hex inválido")
                    continue
                if len(pt) == 0 or len(pt) > 256:
                    self.send("ERR longitud 1..256 bytes")
                    continue
                ct, tag = gcm_encrypt(pt)
                enc_calls += 1
                if enc_calls == 2:
                    # Dos cifrados bajo el mismo nonce ya bastan para el ataque.
                    emit("scan_detected", "alert",
                         src_ip=self.client_address[0],
                         detail={"vuln": "aes-gcm-nonce-reuse", "encrypt_calls": enc_calls})
                self.send("CT " + (NONCE + ct + tag).hex())
                continue

            if line.startswith("command "):
                parts = line.split()
                if len(parts) != 3:
                    self.send("ERR uso: command <ct_hex> <tag_hex>")
                    continue
                try:
                    ct = bytes.fromhex(parts[1])
                    tag = bytes.fromhex(parts[2])
                except ValueError:
                    self.send("ERR hex inválido")
                    continue
                if len(tag) != 16:
                    self.send("ERR tag debe ser 16 bytes")
                    continue
                try:
                    pt = gcm_verify_decrypt(ct, tag)
                except ValueError:
                    self.send("BAD_TAG")
                    continue
                # Tag válido: ejecuta el "comando".
                if pt == ADMIN_CMD:
                    emit("scan_detected", "critical",
                         src_ip=self.client_address[0],
                         detail={"event": "forged-admin-command"})
                    self.send("OK admin verificado.")
                    self.send("FLAG " + FLAG)
                else:
                    self.send("OK comando ejecutado: " + pt.decode(errors="replace"))
                continue

            self.send("ERR comando desconocido")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server((HOST, PORT), Handler) as srv:
        print(f"[*] VaultGCM escuchando en {HOST}:{PORT}", flush=True)
        srv.serve_forever()
