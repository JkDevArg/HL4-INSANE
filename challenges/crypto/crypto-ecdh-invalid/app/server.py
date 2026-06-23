import os
import socketserver
import hashlib
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

FLAG = os.environ.get('FLAG', 'HL4{EJEMPLO_LOCAL}')

# P-256 (secp256r1) parameters
P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P256_A = -3 % P256_P  # = P256_P - 3
P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
P256_GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
P256_GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5


def modinv(a, m):
    return pow(a, -1, m)


def point_add(P, Q, a, p):
    """Generic point addition on y^2 = x^3 + ax + b (mod p). b not needed for addition."""
    if P is None:
        return Q
    if Q is None:
        return P
    if P[0] == Q[0]:
        if P[1] != Q[1]:
            return None
        if P[1] == 0:
            return None
        m = (3 * P[0] ** 2 + a) * modinv(2 * P[1], p) % p
    else:
        m = (Q[1] - P[1]) * modinv(Q[0] - P[0], p) % p
    xr = (m ** 2 - P[0] - Q[0]) % p
    yr = (m * (P[0] - xr) - P[1]) % p
    return (xr, yr)


def point_mul(k, P, a, p):
    """Scalar multiplication using double-and-add."""
    R = None
    Q = P
    while k:
        if k & 1:
            R = point_add(R, Q, a, p)
        Q = point_add(Q, Q, a, p)
        k >>= 1
    return R


G_P256 = (P256_GX, P256_GY)

# Server's private key
SERVER_PRIV = random.randint(1, P256_N - 1)
SERVER_PUB = point_mul(SERVER_PRIV, G_P256, P256_A, P256_P)

# Encrypt flag with key derived from server's private key
FLAG_IV = os.urandom(16)
flag_key = hashlib.sha256(SERVER_PRIV.to_bytes(32, 'big')).digest()[:16]
cipher = AES.new(flag_key, AES.MODE_CBC, FLAG_IV)
ENCRYPTED_FLAG = cipher.encrypt(pad(FLAG.encode(), 16))


class Handler(socketserver.StreamRequestHandler):
    def send(self, msg):
        self.wfile.write((str(msg) + "\n").encode())

    def handle(self):
        self.send("=== ECDH Key Exchange (P-256) ===")
        self.send(f"SERVER_PUBLIC_X={hex(SERVER_PUB[0])}")
        self.send(f"SERVER_PUBLIC_Y={hex(SERVER_PUB[1])}")
        self.send(f"ENCRYPTED_FLAG={FLAG_IV.hex() + ENCRYPTED_FLAG.hex()}")
        self.send("Commands: EXCHANGE <hex_x> <hex_y> | DECRYPT <hex_16byte_key> | QUIT")

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
                elif cmd == 'EXCHANGE':
                    # VULNERABLE: no point-on-curve validation!
                    if len(parts) < 3:
                        self.send("ERROR: EXCHANGE <hex_x> <hex_y>")
                        continue
                    try:
                        cx = int(parts[1], 16)
                        cy = int(parts[2], 16)
                    except Exception:
                        self.send("ERROR: invalid hex")
                        continue

                    # Check coords are in field (basic sanity only, NOT curve membership)
                    if not (0 <= cx < P256_P and 0 <= cy < P256_P):
                        self.send("ERROR: coordinates out of field range")
                        continue

                    # Scalar multiply using P-256's 'a' parameter but with attacker's point
                    # If attacker sends a point on a DIFFERENT curve (same p, same a, different b),
                    # the multiplication still works and reveals SERVER_PRIV mod order_of_that_subgroup
                    client_point = (cx, cy)
                    shared = point_mul(SERVER_PRIV, client_point, P256_A, P256_P)

                    if shared is None:
                        self.send("SHARED_X=0")
                        self.send("SHARED_Y=0")
                    else:
                        self.send(f"SHARED_X={hex(shared[0])}")
                        self.send(f"SHARED_Y={hex(shared[1])}")
                elif cmd == 'DECRYPT':
                    if len(parts) < 2:
                        self.send("ERROR: DECRYPT <hex_16byte_key>")
                        continue
                    try:
                        key = bytes.fromhex(parts[1])
                        if len(key) != 16:
                            self.send("ERROR: key must be exactly 16 bytes")
                            continue
                        dc = AES.new(key, AES.MODE_CBC, FLAG_IV)
                        pt = unpad(dc.decrypt(ENCRYPTED_FLAG), 16)
                        self.send(f"FLAG: {pt.decode()}")
                    except Exception as e:
                        self.send(f"WRONG KEY: {str(e)[:50]}")
                else:
                    self.send("Unknown command")
            except Exception:
                break


if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(('0.0.0.0', 9999), Handler) as srv:
        print("ECDH Invalid Curve server on port 9999")
        print(f"Server private key: {hex(SERVER_PRIV)[:20]}... ({SERVER_PRIV.bit_length()} bits)")
        srv.serve_forever()
