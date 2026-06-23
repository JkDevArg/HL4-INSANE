import os
import socketserver
import random
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from sympy import nextprime

FLAG = os.environ.get('FLAG', 'HL4{EJEMPLO_LOCAL}')


def get_close_primes(bits=512):
    """
    Generate p and q such that |p - q| < 2^20.
    This makes Fermat factorization trivial.
    """
    p = getPrime(bits)
    # Pick delta in [2, 2^20] and find the next prime after p + delta
    delta = random.randint(2, 2**20)
    q_candidate = p + delta
    if q_candidate % 2 == 0:
        q_candidate += 1
    q = nextprime(q_candidate)
    return p, q


print("[*] Generating RSA key with close primes...")
P_KEY, Q_KEY = get_close_primes(512)
N_KEY = P_KEY * Q_KEY
E_KEY = 65537
PHI = (P_KEY - 1) * (Q_KEY - 1)
D_KEY = pow(E_KEY, -1, PHI)

FLAG_INT = bytes_to_long(FLAG.encode())
FLAG_CIPHER = pow(FLAG_INT, E_KEY, N_KEY)

print(f"[*] N = {hex(N_KEY)[:20]}... ({N_KEY.bit_length()} bits)")
print(f"[*] |p - q| = {abs(P_KEY - Q_KEY)}")


class Handler(socketserver.StreamRequestHandler):
    def send(self, msg):
        self.wfile.write((str(msg) + "\n").encode())

    def handle(self):
        self.send("=== RSA Key Exchange Server ===")
        self.send("Commands: GET_PUBLIC_KEY | GET_ENCRYPTED_FLAG | ENCRYPT <hex_msg> | DECRYPT_FLAG <hex_pt> | QUIT")

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
                elif cmd == 'GET_PUBLIC_KEY':
                    self.send(f"n={hex(N_KEY)}")
                    self.send(f"e={hex(E_KEY)}")
                elif cmd == 'GET_ENCRYPTED_FLAG':
                    self.send(f"ct={hex(FLAG_CIPHER)}")
                elif cmd == 'ENCRYPT':
                    if len(parts) < 2:
                        self.send("ERROR: ENCRYPT <hex_msg>")
                        continue
                    try:
                        m = int(parts[1], 16)
                    except Exception:
                        self.send("ERROR: invalid hex")
                        continue
                    if m >= N_KEY:
                        self.send("ERROR: message too large")
                        continue
                    ct = pow(m, E_KEY, N_KEY)
                    self.send(f"ct={hex(ct)}")
                elif cmd == 'DECRYPT_FLAG':
                    if len(parts) < 2:
                        self.send("ERROR: DECRYPT_FLAG <hex_plaintext>")
                        continue
                    try:
                        pt_int = int(parts[1], 16)
                        pt_bytes = long_to_bytes(pt_int)
                        if pt_bytes == FLAG.encode():
                            self.send(f"CORRECT! FLAG: {FLAG}")
                        else:
                            self.send("WRONG plaintext")
                    except Exception:
                        self.send("ERROR: invalid hex")
                else:
                    self.send("Unknown command")
            except Exception:
                break


if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(('0.0.0.0', 9999), Handler) as srv:
        print("Fermat RSA server on port 9999")
        srv.serve_forever()
