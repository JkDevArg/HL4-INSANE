import os
import socketserver
from Crypto.Cipher import AES

FLAG = os.environ.get('FLAG', 'HL4{EJEMPLO_LOCAL}')

KEY = os.urandom(32)
NONCE = os.urandom(12)  # Fixed nonce — reused for ALL encryptions (the vulnerability)

PLAINTEXT_M1 = b"""SYSTEM MANUAL v2.3
Operation mode: SECURE
Cipher: AES-256-GCM
Status: All systems nominal
Nonce policy: Fixed nonce for performance optimization
Contact: admin@hackl4bs.io
END_OF_MANUAL"""

PLAINTEXT_M2 = FLAG.encode()


def gcm_encrypt(plaintext):
    """Encrypt with the fixed nonce (always reused)"""
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=NONCE)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return ct, tag


CT_M1, TAG_M1 = gcm_encrypt(PLAINTEXT_M1)
CT_M2, TAG_M2 = gcm_encrypt(PLAINTEXT_M2)


class Handler(socketserver.StreamRequestHandler):
    def send(self, msg):
        self.wfile.write((str(msg) + "\n").encode())

    def handle(self):
        self.send("=== AES-256-GCM Secure Message Store ===")
        self.send("Commands: GET_CIPHERTEXTS | GET_KNOWN_PLAINTEXT | ENCRYPT <hex_pt> | SUBMIT <flag> | QUIT")

        while True:
            try:
                self.wfile.write(b"> ")
                line = self.rfile.readline()
                if not line:
                    break
                line = line.strip().decode(errors='ignore')
                if not line:
                    continue
                parts = line.split(None, 1)
                if not parts:
                    continue
                cmd = parts[0].upper()

                if cmd == 'QUIT':
                    self.send("Bye!")
                    break
                elif cmd == 'GET_CIPHERTEXTS':
                    self.send(f"NONCE={NONCE.hex()}")
                    self.send(f"CT1={CT_M1.hex()}")
                    self.send(f"TAG1={TAG_M1.hex()}")
                    self.send(f"CT2={CT_M2.hex()}")
                    self.send(f"TAG2={TAG_M2.hex()}")
                elif cmd == 'GET_KNOWN_PLAINTEXT':
                    self.send(f"PT1={PLAINTEXT_M1.hex()}")
                    self.send("NOTE: This is the known plaintext for CT1")
                elif cmd == 'ENCRYPT':
                    if len(parts) < 2:
                        self.send("ERROR: ENCRYPT <hex_plaintext>")
                        continue
                    try:
                        pt = bytes.fromhex(parts[1].strip())
                    except Exception:
                        self.send("ERROR: invalid hex")
                        continue
                    if len(pt) > 4096:
                        self.send("ERROR: too long (max 4096 bytes)")
                        continue
                    # Encrypt with SAME nonce — vulnerability!
                    ct, tag = gcm_encrypt(pt)
                    self.send(f"CT={ct.hex()}")
                    self.send(f"TAG={tag.hex()}")
                elif cmd == 'SUBMIT':
                    if len(parts) < 2:
                        self.send("ERROR: SUBMIT <flag_string>")
                        continue
                    submitted = parts[1].strip()
                    if submitted == FLAG:
                        self.send(f"CORRECT! FLAG: {FLAG}")
                    else:
                        self.send("WRONG flag")
                else:
                    self.send("Unknown command")
            except Exception:
                break


if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(('0.0.0.0', 9999), Handler) as srv:
        print("AES-GCM Nonce Reuse server on port 9999")
        print(f"Nonce (hidden): {NONCE.hex()}")
        srv.serve_forever()
