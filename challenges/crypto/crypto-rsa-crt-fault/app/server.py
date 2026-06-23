import os
import socketserver
import random
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from math import gcd

FLAG = os.environ.get('FLAG', 'HL4{EJEMPLO_LOCAL}')


def gen_rsa_crt(bits=1024):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = pow(q, -1, p)
    return n, e, d, p, q, dp, dq, qinv


print("[*] Generating RSA-CRT key pair (1024-bit)...")
N, E, D, P, Q, DP, DQ, QINV = gen_rsa_crt(1024)
print(f"[*] N = {hex(N)[:20]}...")

CHALLENGE_MSG = b"SIGN_THIS_TO_AUTHENTICATE_HACKL4BS"
MSG_INT = bytes_to_long(CHALLENGE_MSG)


def sign_correct(m):
    """Correct CRT-based RSA signature."""
    sp = pow(m, DP, P)
    sq = pow(m, DQ, Q)
    h = QINV * (sp - sq) % P
    return sq + Q * h


def sign_faulty(m):
    """
    Faulty CRT signature: with 80% probability, introduces a random bit-flip
    in DP before computing sp = m^dp mod p.
    The resulting faulty signature sigma_f satisfies:
      sigma_f^e mod p != m mod p  (but sigma_f^e mod q == m mod q)
    Therefore: gcd(sigma_f^e - m, N) = Q  (or P)
    """
    fault_bit = random.randint(0, 511)
    faulty_dp = DP ^ (1 << fault_bit)
    sp = pow(m, faulty_dp, P)   # wrong
    sq = pow(m, DQ, Q)           # correct
    h = QINV * (sp - sq) % P
    return sq + Q * h


def verify(m, sig):
    return pow(sig, E, N) == m % N


class Handler(socketserver.StreamRequestHandler):
    def send(self, msg):
        self.wfile.write((str(msg) + "\n").encode())

    def handle(self):
        self.send("=== RSA-CRT Signing Service ===")
        self.send(f"CHALLENGE_MSG={CHALLENGE_MSG.hex()}")
        self.send("Commands: GET_PUBLIC_KEY | SIGN_NORMAL <hex_m> | SIGN_FAULT <hex_m> | AUTHENTICATE <hex_sig> | QUIT")

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
                    self.send(f"n={hex(N)}")
                    self.send(f"e={hex(E)}")
                elif cmd == 'SIGN_NORMAL':
                    if len(parts) < 2:
                        self.send("ERROR: SIGN_NORMAL <hex_m>")
                        continue
                    try:
                        m = int(parts[1], 16)
                    except Exception:
                        self.send("ERROR: invalid hex")
                        continue
                    if m <= 0 or m >= N:
                        self.send("ERROR: m out of range")
                        continue
                    sig = sign_correct(m)
                    self.send(f"SIG={hex(sig)}")
                    self.send(f"VALID={verify(m, sig)}")
                elif cmd == 'SIGN_FAULT':
                    if len(parts) < 2:
                        self.send("ERROR: SIGN_FAULT <hex_m>")
                        continue
                    try:
                        m = int(parts[1], 16)
                    except Exception:
                        self.send("ERROR: invalid hex")
                        continue
                    if m <= 0 or m >= N:
                        self.send("ERROR: m out of range")
                        continue
                    sig_f = sign_faulty(m)
                    is_valid = verify(m, sig_f)
                    self.send(f"SIG={hex(sig_f)}")
                    if is_valid:
                        self.send("STATUS=VALID (no fault this time)")
                    else:
                        self.send("STATUS=FAULTY (bit flip occurred in dp)")
                elif cmd == 'AUTHENTICATE':
                    if len(parts) < 2:
                        self.send("ERROR: AUTHENTICATE <hex_sig>")
                        continue
                    try:
                        sig = int(parts[1], 16)
                    except Exception:
                        self.send("ERROR: invalid hex")
                        continue
                    if verify(MSG_INT, sig):
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
        print("RSA-CRT Fault Injection server on port 9999")
        srv.serve_forever()
