import os
import socketserver
import random
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

FLAG = os.environ.get('FLAG', 'HL4{EJEMPLO_LOCAL}')


def gen_rsa(bits=1024):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return n, e, d


print("[*] Generating 1024-bit RSA key...")
N, E, D = gen_rsa(1024)
K = (N.bit_length() + 7) // 8  # byte length of N
print(f"[*] K = {K} bytes")


def pkcs1_pad(msg):
    """PKCS#1 v1.5 type 2 encryption padding."""
    mlen = len(msg)
    if mlen > K - 11:
        raise ValueError("Message too long for PKCS#1 v1.5")
    ps_len = K - mlen - 3
    # PS must be non-zero bytes
    ps = bytes([random.randint(1, 255) for _ in range(ps_len)])
    return b'\x00\x02' + ps + b'\x00' + msg


def pkcs1_check(pt_int):
    """
    Check if pt_int, when represented as K bytes, starts with 0x00 0x02.
    This is the PKCS#1 v1.5 conformance check.
    """
    pt_bytes = long_to_bytes(pt_int, K)
    return pt_bytes[0] == 0x00 and pt_bytes[1] == 0x02


# Encrypt flag with PKCS#1 v1.5
FLAG_PADDED = pkcs1_pad(FLAG.encode())
FLAG_INT = bytes_to_long(FLAG_PADDED)
FLAG_CIPHER = pow(FLAG_INT, E, N)

print(f"[*] Flag encrypted. Ciphertext: {hex(FLAG_CIPHER)[:20]}...")


class Handler(socketserver.StreamRequestHandler):
    def send(self, msg):
        self.wfile.write((str(msg) + "\n").encode())

    def handle(self):
        self.send("=== RSA PKCS#1 v1.5 Decryption Oracle ===")
        self.send(f"n={hex(N)}")
        self.send(f"e={hex(E)}")
        self.send(f"k={K}")
        self.send(f"CIPHERTEXT={hex(FLAG_CIPHER)}")
        self.send("Commands: CHECK <hex_ct> | QUIT")
        self.send("CHECK returns VALID_PADDING or INVALID_PADDING")

        query_count = 0
        MAX_QUERIES = 2000000  # Bleichenbacher needs ~1M for 1024-bit RSA

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
                elif cmd == 'CHECK':
                    if query_count >= MAX_QUERIES:
                        self.send("RATE_LIMITED")
                        continue
                    if len(parts) < 2:
                        self.send("ERROR: CHECK <hex_ct>")
                        continue
                    try:
                        ct = int(parts[1], 16)
                    except Exception:
                        self.send("ERROR: invalid hex")
                        continue
                    pt = pow(ct, D, N)
                    if pkcs1_check(pt):
                        self.send("VALID_PADDING")
                    else:
                        self.send("INVALID_PADDING")
                    query_count += 1
                else:
                    self.send("Unknown command")
            except Exception:
                break


if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(('0.0.0.0', 9999), Handler) as srv:
        print(f"Bleichenbacher Oracle on port 9999, K={K}")
        srv.serve_forever()
