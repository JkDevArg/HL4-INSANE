import os
import hashlib
import socketserver
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

FLAG = os.environ.get('FLAG', 'HL4{EJEMPLO_LOCAL}')
KEY = hashlib.sha256(os.urandom(32)).digest()


def encrypt(plaintext):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    iv = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, 16))
    return iv + ct


def decrypt_raw(data):
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return cipher.decrypt(ct)


def decrypt_unpad(data):
    pt = decrypt_raw(data)
    return unpad(pt, 16)


# Admin cookie: role=guest, so attacker must flip to admin=true
ADMIN_PLAINTEXT = b"role=guest&user=hacker&admin=false"
ADMIN_COOKIE = encrypt(ADMIN_PLAINTEXT)


class Handler(socketserver.StreamRequestHandler):
    def send(self, msg):
        self.wfile.write((str(msg) + "\n").encode())

    def handle(self):
        self.send("=== Session Manager v1.0 ===")
        self.send(f"ADMIN_COOKIE={ADMIN_COOKIE.hex()}")
        self.send("Commands: DECRYPT <hex> | GET_FLAG <hex_cookie> | QUIT")

        while True:
            try:
                self.wfile.write(b"> ")
                line = self.rfile.readline()
                if not line:
                    break
                line = line.strip().decode(errors='ignore')
                if not line:
                    continue
                parts = line.split()
                if not parts:
                    continue
                cmd = parts[0].upper()

                if cmd == 'QUIT':
                    self.send("Bye!")
                    break
                elif cmd == 'DECRYPT':
                    if len(parts) < 2:
                        self.send("ERROR: DECRYPT <hex>")
                        continue
                    try:
                        data = bytes.fromhex(parts[1])
                    except Exception:
                        self.send("ERROR: invalid hex")
                        continue
                    if len(data) < 32 or len(data) % 16 != 0:
                        self.send("INVALID_LENGTH")
                        continue
                    try:
                        pt = decrypt_raw(data)
                        unpad(pt, 16)
                        self.send("VALID_PADDING")
                    except ValueError:
                        self.send("PADDING_ERROR")
                    except Exception:
                        self.send("PADDING_ERROR")
                elif cmd == 'GET_FLAG':
                    if len(parts) < 2:
                        self.send("ERROR: GET_FLAG <hex_cookie>")
                        continue
                    try:
                        data = bytes.fromhex(parts[1])
                    except Exception:
                        self.send("ERROR: invalid hex")
                        continue
                    try:
                        plaintext = decrypt_unpad(data).decode('utf-8', errors='replace')
                        if 'admin=true' in plaintext:
                            self.send(f"FLAG: {FLAG}")
                        else:
                            self.send(f"ACCESS DENIED. Decrypted: {plaintext}")
                    except Exception:
                        self.send("INVALID_TOKEN: bad padding")
                else:
                    self.send("Unknown command")
            except Exception:
                break


if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(('0.0.0.0', 9999), Handler) as srv:
        print("Padding Oracle server on port 9999")
        srv.serve_forever()
