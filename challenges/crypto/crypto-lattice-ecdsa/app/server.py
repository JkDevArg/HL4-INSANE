import os
import socket
import socketserver
import hashlib
import random
import threading

# secp256k1 parameters
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

FLAG = os.environ.get('FLAG', 'HL4{EJEMPLO_LOCAL}')

# Fixed lower 32 bits of nonce (the vulnerability)
FIXED_LOWER = 0xDEADBEEF

def modinv(a, m):
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("No inverse")
    return x % m

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def point_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    if P[0] == Q[0]:
        if P[1] != Q[1]: return None
        m = (3 * P[0] * P[0]) * modinv(2 * P[1], p) % p
    else:
        m = (Q[1] - P[1]) * modinv(Q[0] - P[0], p) % p
    x = (m * m - P[0] - Q[0]) % p
    y = (m * (P[0] - x) - P[1]) % p
    return (x, y)

def point_mul(k, P):
    R = None
    Q = P
    while k:
        if k & 1:
            R = point_add(R, Q)
        Q = point_add(Q, Q)
        k >>= 1
    return R

G = (Gx, Gy)

# Generate private key (retry on rare edge case in point_mul)
while True:
    try:
        PRIVATE_KEY = random.randint(1, n - 1)
        PUBLIC_KEY = point_mul(PRIVATE_KEY, G)
        break
    except ValueError:
        continue

def sign(msg_bytes):
    h = int(hashlib.sha256(msg_bytes).hexdigest(), 16)
    # Vulnerable nonce: upper 32 bits random, lower 32 bits FIXED
    upper = random.getrandbits(32)
    k = (upper << 32) | FIXED_LOWER
    k = k % n
    if k == 0:
        k = 1
    R = point_mul(k, G)
    r = R[0] % n
    if r == 0:
        return sign(msg_bytes)
    s = modinv(k, n) * (h + r * PRIVATE_KEY) % n
    if s == 0:
        return sign(msg_bytes)
    return r, s

def verify_sig(msg_bytes, r, s, pub_key):
    h = int(hashlib.sha256(msg_bytes).hexdigest(), 16)
    w = modinv(s, n)
    u1 = h * w % n
    u2 = r * w % n
    P = point_add(point_mul(u1, G), point_mul(u2, pub_key))
    if P is None:
        return False
    return P[0] % n == r

class Handler(socketserver.StreamRequestHandler):
    def send(self, msg):
        self.wfile.write((msg + "\n").encode())

    def handle(self):
        self.send("=== ECDSA Signing Oracle ===")
        self.send(f"Public Key: ({hex(PUBLIC_KEY[0])}, {hex(PUBLIC_KEY[1])})")
        self.send("Commands: SIGN <hex_msg> | VERIFY <hex_msg> <r> <s> | QUIT")
        sign_count = 0
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
                elif cmd == 'SIGN':
                    if sign_count >= 50:
                        self.send("ERROR: signature limit reached (50)")
                        continue
                    if len(parts) < 2:
                        self.send("ERROR: SIGN <hex_msg>")
                        continue
                    try:
                        msg_bytes = bytes.fromhex(parts[1])
                    except Exception:
                        self.send("ERROR: invalid hex")
                        continue
                    r, s = sign(msg_bytes)
                    self.send(f"r={hex(r)}")
                    self.send(f"s={hex(s)}")
                    sign_count += 1
                elif cmd == 'VERIFY':
                    if len(parts) < 4:
                        self.send("ERROR: VERIFY <hex_msg> <r> <s>")
                        continue
                    try:
                        msg_bytes = bytes.fromhex(parts[1])
                        r = int(parts[2], 16)
                        s = int(parts[3], 16)
                    except Exception:
                        self.send("ERROR: invalid input")
                        continue
                    # The challenge message that must be signed
                    challenge_msg = b"HACKL4BS_AUTH_2024"
                    if msg_bytes != challenge_msg:
                        self.send("ERROR: wrong challenge message. Sign: 4841434b4c3442535f415554485f32303234")
                        continue
                    if verify_sig(msg_bytes, r, s, PUBLIC_KEY):
                        self.send(f"CORRECT! FLAG: {FLAG}")
                    else:
                        self.send("WRONG signature")
                else:
                    self.send("Unknown command")
            except Exception as e:
                break

if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(('0.0.0.0', 9999), Handler) as srv:
        print("Server running on port 9999")
        srv.serve_forever()
