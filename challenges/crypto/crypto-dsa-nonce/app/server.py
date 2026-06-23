import os
import socketserver
import hashlib
import random
from Crypto.Util.number import getPrime
import sympy

FLAG = os.environ.get('FLAG', 'HL4{EJEMPLO_LOCAL}')


def gen_dsa_params():
    """Generate DSA parameters (p, q, g) with 1024/160-bit sizes"""
    q = getPrime(160)
    # Find a 1024-bit prime p = k*q + 1
    while True:
        k = random.randint(2**863, 2**864)
        p = k * q + 1
        if p.bit_length() == 1024 and sympy.isprime(p):
            break
    # Find generator g of the subgroup of order q
    h = 2
    while True:
        g = pow(h, (p - 1) // q, p)
        if g != 1:
            break
        h += 1
    return p, q, g


print("[*] Generating DSA parameters (may take a moment)...")
P_DSA, Q_DSA, G_DSA = gen_dsa_params()
X_DSA = random.randint(1, Q_DSA - 1)   # private key
Y_DSA = pow(G_DSA, X_DSA, P_DSA)       # public key
print(f"[*] p = {hex(P_DSA)[:20]}... ({P_DSA.bit_length()} bits)")
print(f"[*] q = {hex(Q_DSA)[:20]}... ({Q_DSA.bit_length()} bits)")

# Sign two messages with the SAME nonce (the vulnerability)
K_REUSED = random.randint(1, Q_DSA - 1)
MSG1 = b"Hello from the server at startup time"
MSG2 = b"Operational status: all systems nominal"
CHALLENGE_MSG = b"AUTHENTICATE_HACKL4BS_2024"


def dsa_sign(msg, k):
    h = int(hashlib.sha1(msg).hexdigest(), 16)
    r = pow(G_DSA, k, P_DSA) % Q_DSA
    if r == 0:
        raise ValueError("r is 0")
    s = pow(k, -1, Q_DSA) * (h + X_DSA * r) % Q_DSA
    if s == 0:
        raise ValueError("s is 0")
    return r, s


def dsa_verify(msg, r, s):
    if not (0 < r < Q_DSA and 0 < s < Q_DSA):
        return False
    h = int(hashlib.sha1(msg).hexdigest(), 16)
    w = pow(s, -1, Q_DSA)
    u1 = h * w % Q_DSA
    u2 = r * w % Q_DSA
    v = pow(G_DSA, u1, P_DSA) * pow(Y_DSA, u2, P_DSA) % P_DSA % Q_DSA
    return v == r


R1, S1 = dsa_sign(MSG1, K_REUSED)
R2, S2 = dsa_sign(MSG2, K_REUSED)

# Verify both share the same r (since k is the same, G^k mod p mod q is the same)
assert R1 == R2, "r values should be equal when k is reused"
print(f"[*] Both signatures share r = {hex(R1)[:20]}... (reused nonce detected!)")


class Handler(socketserver.StreamRequestHandler):
    def send(self, msg):
        self.wfile.write((str(msg) + "\n").encode())

    def handle(self):
        self.send("=== DSA Signature Verification Service ===")
        self.send("Commands: GET_PUBLIC_KEY | GET_SIGNATURES | VERIFY_AUTH <r> <s> | QUIT")

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
                    self.send(f"p={hex(P_DSA)}")
                    self.send(f"q={hex(Q_DSA)}")
                    self.send(f"g={hex(G_DSA)}")
                    self.send(f"y={hex(Y_DSA)}")
                elif cmd == 'GET_SIGNATURES':
                    self.send(f"msg1={MSG1.hex()}")
                    self.send(f"r1={hex(R1)}")
                    self.send(f"s1={hex(S1)}")
                    self.send(f"msg2={MSG2.hex()}")
                    self.send(f"r2={hex(R2)}")
                    self.send(f"s2={hex(S2)}")
                    self.send(f"challenge_msg={CHALLENGE_MSG.hex()}")
                    self.send(f"note=Both signatures share the same r value!")
                elif cmd == 'VERIFY_AUTH':
                    if len(parts) < 3:
                        self.send("ERROR: VERIFY_AUTH <r> <s>")
                        continue
                    try:
                        r = int(parts[1], 16)
                        s = int(parts[2], 16)
                    except Exception:
                        self.send("ERROR: invalid hex")
                        continue
                    if dsa_verify(CHALLENGE_MSG, r, s):
                        self.send(f"AUTHENTICATED! FLAG: {FLAG}")
                    else:
                        self.send("INVALID signature")
                else:
                    self.send("Unknown command")
            except Exception:
                break


if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(('0.0.0.0', 9999), Handler) as srv:
        print("DSA server running on port 9999")
        srv.serve_forever()
