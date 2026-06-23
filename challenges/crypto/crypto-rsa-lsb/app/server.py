import os
import socketserver
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes, GCD

FLAG = os.environ.get('FLAG', 'HL4{EJEMPLO_LOCAL}')

def generate_rsa(bits=2048):
    while True:
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        n = p * q
        e = 65537
        phi = (p - 1) * (q - 1)
        if GCD(e, phi) == 1:
            d = pow(e, -1, phi)
            return n, e, d, p, q

N, E, D, P, Q = generate_rsa(2048)
FLAG_INT = bytes_to_long(FLAG.encode())
FLAG_CIPHER = pow(FLAG_INT, E, N)

class Handler(socketserver.StreamRequestHandler):
    def send(self, msg):
        self.wfile.write((str(msg) + "\n").encode())

    def handle(self):
        self.send("=== RSA LSB Oracle ===")
        self.send("Commands: GET_PUBLIC_KEY | GET_CIPHERTEXT | QUERY <hex_ct> | QUIT")
        query_count = 0
        MAX_QUERIES = 3000

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
                elif cmd == 'GET_CIPHERTEXT':
                    self.send(f"ct={hex(FLAG_CIPHER)}")
                elif cmd == 'QUERY':
                    if query_count >= MAX_QUERIES:
                        self.send("ERROR: query limit reached (3000)")
                        continue
                    if len(parts) < 2:
                        self.send("ERROR: QUERY <hex_ct>")
                        continue
                    try:
                        ct = int(parts[1], 16)
                    except Exception:
                        self.send("ERROR: invalid hex")
                        continue
                    pt = pow(ct, D, N)
                    lsb = pt & 1
                    self.send(f"LSB={lsb}")
                    query_count += 1
                else:
                    self.send("Unknown command")
            except Exception:
                break

if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(('0.0.0.0', 9999), Handler) as srv:
        print(f"RSA LSB Oracle on port 9999")
        print(f"n = {hex(N)[:20]}...")
        srv.serve_forever()
