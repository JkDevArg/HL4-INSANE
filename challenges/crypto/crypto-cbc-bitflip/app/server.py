import os
import hashlib
import time
import socketserver
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

FLAG = os.environ.get('FLAG', 'HL4{EJEMPLO_LOCAL}')
KEY = hashlib.sha256(os.urandom(32)).digest()


def encrypt_token(username):
    """
    Plaintext structure (username padded to exactly 6 chars):
    Offset 0:  "user=XXXXXX&role=guest&ts=NNNNNNNNNN"
    Block 0 (bytes 0-15):  "user=XXXXXX&role"
    Block 1 (bytes 16-31): "=guest&ts=NNNNNN"
    Block 2 (bytes 32-47): "NNNN" + padding

    "guest" starts at byte 17 (offset 1 in block 1).
    To flip "guest" -> "admin": XOR bytes 1-5 of block 0 (the previous block)
    with (ord('g') ^ ord('a')), (ord('u') ^ ord('d')), etc.
    """
    ts = int(time.time())
    # Username exactly 6 chars
    username = username[:6].ljust(6)
    plaintext = f"user={username}&role=guest&ts={ts}"
    iv = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode(), 16))
    return iv + ct, plaintext


def decrypt_token(data):
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    try:
        pt = unpad(cipher.decrypt(ct), 16)
        return pt.decode('utf-8', errors='replace')
    except Exception:
        return None


class Handler(socketserver.StreamRequestHandler):
    def send(self, msg):
        self.wfile.write((str(msg) + "\n").encode())

    def handle(self):
        self.send("=== Auth Service v1.0 ===")
        self.send("Commands: LOGIN <username> | VERIFY <hex_token> | FLAG <hex_token> | QUIT")
        self.send("Hint: Login as 'hacker' to get a token. 'role=guest' starts at byte 17.")

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
                elif cmd == 'LOGIN':
                    if len(parts) < 2:
                        self.send("ERROR: LOGIN <username>")
                        continue
                    username = parts[1]
                    token, pt = encrypt_token(username)
                    self.send(f"TOKEN={token.hex()}")
                    self.send(f"PLAINTEXT_HINT=user={username[:6].ljust(6)}&role=guest&ts=...")
                    self.send(f"STRUCTURE_HINT=Block0(0-15)='user=XXXXXX&role' | Block1(16-31)='=guest&ts=NNNNNN'")
                    self.send(f"FLIP_HINT='guest'(bytes 17-21) is in block1; XOR block0[1:6] to flip it")
                elif cmd == 'VERIFY':
                    if len(parts) < 2:
                        self.send("ERROR: VERIFY <hex_token>")
                        continue
                    try:
                        token = bytes.fromhex(parts[1])
                    except Exception:
                        self.send("ERROR: invalid hex")
                        continue
                    pt = decrypt_token(token)
                    if pt is None:
                        self.send("INVALID_TOKEN: bad padding")
                    elif 'role=admin' in pt:
                        self.send(f"OK_ADMIN: {pt}")
                    else:
                        self.send(f"OK_GUEST: {pt}")
                elif cmd == 'FLAG':
                    if len(parts) < 2:
                        self.send("ERROR: FLAG <hex_token>")
                        continue
                    try:
                        token = bytes.fromhex(parts[1])
                    except Exception:
                        self.send("ERROR: invalid hex")
                        continue
                    pt = decrypt_token(token)
                    if pt is None:
                        self.send("INVALID_TOKEN: bad padding")
                        continue
                    if 'role=admin' in pt:
                        self.send(f"FLAG: {FLAG}")
                    else:
                        self.send("ACCESS_DENIED: not admin")
                else:
                    self.send("Unknown command")
            except Exception:
                break


if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(('0.0.0.0', 9999), Handler) as srv:
        print("CBC Bitflip server on port 9999")
        srv.serve_forever()
