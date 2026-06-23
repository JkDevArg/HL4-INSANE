import os
import socketserver
import hashlib
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import sympy

FLAG = os.environ.get('FLAG', 'HL4{EJEMPLO_LOCAL}')

def build_smooth_prime():
    """
    Build a prime p where p-1 is B-smooth (all prime factors <= 97).
    This makes the discrete logarithm trivially solvable via Pohlig-Hellman.
    """
    small_primes = list(sympy.primerange(2, 101))
    phi = 1
    for pr in small_primes:
        phi *= pr
    k = 2
    while True:
        candidate = k * phi + 1
        if sympy.isprime(candidate):
            return candidate, phi, small_primes, k
        k += 2

print("[*] Generating smooth prime (this may take a moment)...")
SMOOTH_P, SMOOTH_PHI, SMALL_PRIMES, K_MULT = build_smooth_prime()
SMOOTH_G = 2
# Find a generator that has order dividing phi
while pow(SMOOTH_G, SMOOTH_PHI, SMOOTH_P) != 1:
    SMOOTH_G += 1

print(f"[*] P = {SMOOTH_P} ({SMOOTH_P.bit_length()} bits)")
print(f"[*] P-1 = {K_MULT} * product_of_primes_up_to_97")
print(f"[*] Small primes: {SMALL_PRIMES}")

# Server's private key
SERVER_B = random.randint(2, SMOOTH_P - 2)

# Encrypt flag with key derived from server private key
FLAG_IV = bytes.fromhex("deadbeefcafebabe" * 2)
flag_key = hashlib.sha256(str(SERVER_B).encode()).digest()[:16]
cipher_flag = AES.new(flag_key, AES.MODE_CBC, FLAG_IV)
ENCRYPTED_FLAG = cipher_flag.encrypt(pad(FLAG.encode(), 16))

class Handler(socketserver.StreamRequestHandler):
    def send(self, msg):
        self.wfile.write((str(msg) + "\n").encode())

    def handle(self):
        self.send("=== Secure DH Channel Protocol v2 ===")
        self.send(f"P={hex(SMOOTH_P)}")
        self.send(f"G={hex(SMOOTH_G)}")
        # Server public key B = G^b mod P
        B = pow(SMOOTH_G, SERVER_B, SMOOTH_P)
        self.send(f"SERVER_PUBLIC={hex(B)}")
        self.send(f"ENCRYPTED_FLAG={FLAG_IV.hex() + ENCRYPTED_FLAG.hex()}")
        self.send("Commands: EXCHANGE <hex_client_pub> | DECRYPT <hex_b> | QUIT")

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
                    if len(parts) < 2:
                        self.send("ERROR: EXCHANGE <hex_client_pub>")
                        continue
                    try:
                        A = int(parts[1], 16)
                    except Exception:
                        self.send("ERROR: invalid hex")
                        continue
                    # Compute shared secret (no subgroup validation - another vulnerability)
                    shared = pow(A, SERVER_B, SMOOTH_P)
                    self.send(f"SHARED={hex(shared)}")
                elif cmd == 'DECRYPT':
                    if len(parts) < 2:
                        self.send("ERROR: DECRYPT <hex_b>")
                        continue
                    try:
                        claimed_b = int(parts[1], 16)
                    except Exception:
                        self.send("ERROR: invalid hex")
                        continue
                    if claimed_b == SERVER_B:
                        self.send(f"CORRECT! FLAG: {FLAG}")
                    else:
                        # Check if they can derive the correct key
                        test_key = hashlib.sha256(str(claimed_b).encode()).digest()[:16]
                        try:
                            dc = AES.new(test_key, AES.MODE_CBC, FLAG_IV)
                            decrypted = unpad(dc.decrypt(ENCRYPTED_FLAG), 16)
                            if decrypted == FLAG.encode():
                                self.send(f"CORRECT! FLAG: {FLAG}")
                            else:
                                self.send("WRONG: decryption successful but wrong content")
                        except Exception:
                            self.send("WRONG: invalid key")
                else:
                    self.send("Unknown command")
            except Exception:
                break

if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(('0.0.0.0', 9999), Handler) as srv:
        print("Smooth DH server running on port 9999")
        srv.serve_forever()
