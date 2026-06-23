# Solution: Lattice Strikes Back — HNP Attack on Biased ECDSA Nonces

## Vulnerability

The server's nonce generation is:
```
upper = random.getrandbits(32)
k = (upper << 32) | 0xDEADBEEF
```

This means the lower 32 bits of every nonce `k` are fixed to `0xDEADBEEF`. This is a classic **Hidden Number Problem (HNP)** instance solvable with LLL lattice reduction.

## Attack Overview

1. Collect 30+ signatures `(r_i, s_i)` for messages with known hashes `h_i`
2. From `s*k = h + r*x (mod n)` and `k = alpha*2^32 + 0xDEADBEEF`:
   - `s*(alpha*2^32 + FIXED) = h + r*x (mod n)`
   - `s*alpha*2^32 = h - s*FIXED + r*x (mod n)`
3. Build an HNP lattice and apply LLL to recover the private key `x`

## Full Attack Script

```python
#!/usr/bin/env python3
"""
HNP Attack on ECDSA with biased nonces
The lower 32 bits of each nonce k are fixed to 0xDEADBEEF
So k = (random_32 << 32) | 0xDEADBEEF
"""
import socket
import hashlib
import random

# secp256k1 order
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
FIXED_LOWER = 0xDEADBEEF
BASE = 2**32

def modinv(a, m):
    return pow(a, -1, m)

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
        if k & 1: R = point_add(R, Q)
        Q = point_add(Q, Q)
        k >>= 1
    return R

def collect_signatures(host, port, num_sigs=35):
    sigs = []
    s = socket.socket()
    s.connect((host, port))
    f = s.makefile('rb')

    def recv_line():
        return f.readline().decode().strip()

    def send(msg):
        s.sendall((msg + '\n').encode())

    # Read banner lines until we see the prompt
    for _ in range(5):
        line = recv_line()
        print(f"[banner] {line}")
        if line.startswith('>'):
            break

    for i in range(num_sigs):
        msg_bytes = hashlib.sha256(f"collect_{i}".encode()).digest()
        msg_hex = msg_bytes.hex()
        h = int(hashlib.sha256(msg_bytes).hexdigest(), 16)

        send(f"SIGN {msg_hex}")
        r_line = recv_line()
        s_line = recv_line()
        try:
            prompt = recv_line()  # consume prompt
        except:
            pass

        r = int(r_line.split('=')[1], 16)
        sig_s = int(s_line.split('=')[1], 16)
        sigs.append((h, r, sig_s))
        print(f"[*] Collected sig {i+1}/{num_sigs}: r={hex(r)[:10]}...")

    return sigs, s, f

def verify_private_key(x, sigs):
    """Check if x satisfies the signature equations (k mod BASE == FIXED_LOWER)"""
    for h, r, s in sigs[:5]:
        k = modinv(s, n) * (h + r * x) % n
        if k % BASE != FIXED_LOWER:
            return False
    return True

def hnp_attack(sigs):
    """
    HNP lattice attack to recover private key x from biased nonces.
    
    For each signature: s*k = h + r*x (mod n), k = alpha*BASE + FIXED_LOWER
    => s*alpha*BASE = h - s*FIXED_LOWER + r*x (mod n)
    
    Let:
      c_i = r_i * modinv(s_i, n) mod n   (coefficient of x)
      d_i = (h_i - s_i*FIXED_LOWER) * modinv(s_i, n) mod n
    
    Then: alpha_i * BASE = d_i + c_i * x (mod n)
    Short vector in lattice contains x.
    """
    try:
        from fpylll import IntegerMatrix, LLL
        HAS_FPYLLL = True
    except ImportError:
        HAS_FPYLLL = False
        print("[-] fpylll not available. Trying sage approach...")

    m = len(sigs)

    # Precompute c_i and d_i
    cs = []
    ds = []
    for h, r, s in sigs:
        sinv = modinv(s, n)
        c_i = r * sinv % n
        d_i = (h - s * FIXED_LOWER) * sinv % n
        cs.append(c_i)
        ds.append(d_i)

    # Build lattice matrix of dimension m+2
    # Rows 0..m-1: n * e_i (basis for modular arithmetic)
    # Row m:   [c_0, c_1, ..., c_{m-1}, 1, 0]
    # Row m+1: [d_0, d_1, ..., d_{m-1}, 0, BASE]
    # Target short vector ~ [alpha_0, ..., alpha_{m-1}, x/n_scale, BASE/BASE]

    if HAS_FPYLLL:
        dim = m + 2
        A = IntegerMatrix(dim, dim)

        # Fill modular rows
        for i in range(m):
            A[i, i] = n

        # Fill c_i row (contains x)
        for j in range(m):
            A[m, j] = cs[j]
        A[m, m] = 1
        A[m, m+1] = 0

        # Fill d_i row
        for j in range(m):
            A[m+1, j] = ds[j]
        A[m+1, m] = 0
        A[m+1, m+1] = BASE

        LLL.reduction(A)

        # Search reduced rows for x
        for i in range(dim):
            # x candidate is in column m (the 1/0 column)
            x_cand = A[i, m] % n
            if x_cand == 0:
                x_cand = (-A[i, m]) % n
            if x_cand != 0 and verify_private_key(x_cand, sigs):
                return x_cand
            # Also check negation
            x_neg = (n - x_cand) % n
            if x_neg != 0 and verify_private_key(x_neg, sigs):
                return x_neg

        # Try with scaling: sometimes x appears in the d column
        for i in range(dim):
            for col in [m, m+1]:
                x_cand = abs(A[i, col]) % n
                if x_cand != 0 and verify_private_key(x_cand, sigs):
                    return x_cand

        print("[-] LLL did not yield key directly, trying brute force on candidates...")
        return None
    else:
        # Fallback: use sage if available
        print("Install fpylll: pip install fpylll")
        print("Or run in SageMath:")
        print("  sage -c 'exec(open(\"attack.sage\").read())'")
        return None

def get_flag(conn, f, x):
    """Use recovered private key to sign the challenge message and get flag"""
    def recv_line():
        return f.readline().decode().strip()

    def send(msg):
        conn.sendall((msg + '\n').encode())

    G = (Gx, Gy)
    challenge_msg = b"HACKL4BS_AUTH_2024"
    msg_hex = challenge_msg.hex()
    h = int(hashlib.sha256(challenge_msg).hexdigest(), 16)

    # Sign with recovered key using a random valid nonce
    while True:
        k = random.randint(1, n - 1)
        R = point_mul(k, G)
        r = R[0] % n
        if r == 0:
            continue
        s = modinv(k, n) * (h + r * x) % n
        if s == 0:
            continue
        break

    send(f"VERIFY {msg_hex} {hex(r)} {hex(s)}")
    line1 = recv_line()
    print(f"[+] Server response: {line1}")
    if 'FLAG' in line1:
        print(f"[+] SUCCESS! Got flag!")
    else:
        # consume prompt
        try:
            recv_line()
        except:
            pass

if __name__ == '__main__':
    import sys
    HOST = sys.argv[1] if len(sys.argv) > 1 else '172.30.99.20'
    PORT = 9999

    print(f"[*] Connecting to {HOST}:{PORT}")
    print("[*] Collecting 35 signatures...")
    sigs, conn, f = collect_signatures(HOST, PORT, 35)

    print("[*] Running HNP lattice attack (requires fpylll)...")
    x = hnp_attack(sigs)

    if x:
        print(f"[+] Recovered private key: {hex(x)}")
        print("[*] Signing challenge message to get flag...")
        get_flag(conn, f, x)
    else:
        print("[-] Attack failed.")
        print("[*] Try installing fpylll: pip install fpylll")
        print("[*] Or use SageMath with the following:")
        print("""
# SageMath version:
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
FIXED_LOWER = 0xDEADBEEF
BASE = 2**32
# (paste sigs list here)
m = len(sigs)
cs = [(r * pow(s, -1, n) % n) for h, r, s in sigs]
ds = [((h - s*FIXED_LOWER) * pow(s_val, -1, n) % n) for h, r, s_val in sigs]
M = Matrix(ZZ, m+2, m+2)
for i in range(m): M[i,i] = n
for j in range(m): M[m,j] = cs[j]
M[m,m] = 1
for j in range(m): M[m+1,j] = ds[j]
M[m+1,m+1] = BASE
L = M.LLL()
for row in L:
    x_cand = abs(row[m]) % n
    if x_cand != 0:
        valid = all(pow(pow(s_val, -1, n)*(h + r*x_cand), 1, n) % BASE == FIXED_LOWER
                   for h, r, s_val in sigs[:3])
        if valid:
            print(f"Found x = {hex(x_cand)}")
            break
""")

    conn.close()
```

## Dependencies

```
pip install fpylll
# or use SageMath
```

## Key Insight

When 32 LSBs of a nonce are known, the HNP lattice has dimension `m+2` where `m` is the number of signatures. LLL reduction recovers the private key in polynomial time. With `BASE = 2^32` and `m >= 30` signatures, success rate is near 100%.
