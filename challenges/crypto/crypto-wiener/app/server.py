import os
import socketserver
import random
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

FLAG = os.environ.get('FLAG', 'HL4{EJEMPLO_LOCAL}')


def gen_wiener_rsa(bits):
    """
    Generate RSA key vulnerable to Wiener's attack: d < n^0.25 / 3.
    Strategy: pick small d first, then compute e = d^{-1} mod phi.
    Repeat until d < n^0.25 / 3.
    """
    while True:
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        # Ensure p != q and p > q (convention)
        if p == q:
            continue
        if p < q:
            p, q = q, p
        n = p * q
        phi = (p - 1) * (q - 1)
        # Wiener condition: d < n^0.25 / 3
        d_bound = max(2, int(n ** 0.25) // 3)
        if d_bound < 2:
            continue
        d = random.randint(2, d_bound)
        try:
            e = pow(d, -1, phi)
        except Exception:
            continue
        # Double-check Wiener condition
        if d >= n ** 0.25:
            continue
        # Verify encryption/decryption works
        test_m = 42
        if pow(pow(test_m, e, n), d, n) == test_m:
            return n, e, d, p, q


print("[*] Generating Wiener-vulnerable RSA instances...")
print("[*] Instance 1 (256-bit)...")
N1, E1, D1, P1, Q1 = gen_wiener_rsa(256)
print("[*] Instance 2 (384-bit)...")
N2, E2, D2, P2, Q2 = gen_wiener_rsa(384)
print("[*] Instance 3 (512-bit, contains flag)...")
N3, E3, D3, P3, Q3 = gen_wiener_rsa(512)

# Encrypt flag with instance 3
FLAG_INT = bytes_to_long(FLAG.encode())
FLAG_CIPHER_3 = pow(FLAG_INT, E3, N3)

# Dummy plaintexts for instances 1 and 2
DUMMY1 = bytes_to_long(b"WarmUp_Level_1_Easy")
DUMMY2 = bytes_to_long(b"WarmUp_Level_2_Med_")
CT1 = pow(DUMMY1, E1, N1)
CT2 = pow(DUMMY2, E2, N2)

print(f"[*] D1 = {hex(D1)} ({D1.bit_length()} bits), N1^0.25 = {int(N1**0.25)}")
print(f"[*] D2 = {hex(D2)} ({D2.bit_length()} bits), N2^0.25 = {int(N2**0.25)}")
print(f"[*] D3 = {hex(D3)} ({D3.bit_length()} bits), N3^0.25 = {int(N3**0.25)}")


class Handler(socketserver.StreamRequestHandler):
    def send(self, msg):
        self.wfile.write((str(msg) + "\n").encode())

    def handle(self):
        self.send("=== Multi-Key RSA Decryption Service ===")
        self.send("Commands: GET_CHALLENGES | DECRYPT_FLAG <hex_d3> | QUIT")

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
                elif cmd == 'GET_CHALLENGES':
                    self.send("=== INSTANCE 1 (256-bit warmup) ===")
                    self.send(f"n1={hex(N1)}")
                    self.send(f"e1={hex(E1)}")
                    self.send(f"ct1={hex(CT1)}")
                    self.send("=== INSTANCE 2 (384-bit warmup) ===")
                    self.send(f"n2={hex(N2)}")
                    self.send(f"e2={hex(E2)}")
                    self.send(f"ct2={hex(CT2)}")
                    self.send("=== INSTANCE 3 (512-bit, FLAG ENCRYPTED HERE) ===")
                    self.send(f"n3={hex(N3)}")
                    self.send(f"e3={hex(E3)}")
                    self.send(f"ct3={hex(FLAG_CIPHER_3)}")
                    self.send("HINT: All instances use d < n^0.25. Apply Wiener to e3/n3 to get d3.")
                elif cmd == 'DECRYPT_FLAG':
                    if len(parts) < 2:
                        self.send("ERROR: DECRYPT_FLAG <hex_d3>")
                        continue
                    try:
                        d_submitted = int(parts[1], 16)
                    except Exception:
                        self.send("ERROR: invalid hex")
                        continue
                    if d_submitted == D3:
                        pt = pow(FLAG_CIPHER_3, d_submitted, N3)
                        try:
                            flag_bytes = long_to_bytes(pt)
                            self.send(f"FLAG: {flag_bytes.decode()}")
                        except Exception:
                            self.send(f"FLAG: {FLAG}")
                    else:
                        # Also accept correct decryption
                        try:
                            pt = pow(FLAG_CIPHER_3, d_submitted, N3)
                            flag_bytes = long_to_bytes(pt)
                            if flag_bytes == FLAG.encode():
                                self.send(f"FLAG: {FLAG}")
                            else:
                                self.send("WRONG: incorrect d3")
                        except Exception:
                            self.send("WRONG: incorrect d3")
                else:
                    self.send("Unknown command")
            except Exception:
                break


if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(('0.0.0.0', 9999), Handler) as srv:
        print("Wiener RSA server on port 9999")
        srv.serve_forever()
