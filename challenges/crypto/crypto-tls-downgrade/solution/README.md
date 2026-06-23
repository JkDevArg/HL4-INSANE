# Solution: Smooth Operator — Pohlig-Hellman DLP Attack

## Vulnerability

The server uses a Diffie-Hellman group where `p-1` is **B-smooth** (all prime factors ≤ 97). This makes the discrete logarithm problem (DLP) trivially solvable via the **Pohlig-Hellman algorithm**.

## Theory

Pohlig-Hellman reduces the DLP `G^b ≡ B (mod P)` to a system of DLPs in small subgroups:
- Factor `p-1 = q1^e1 * q2^e2 * ... * qk^ek`
- Solve `b mod qi^ei` for each factor using baby-step giant-step in each subgroup
- Combine with CRT to get `b mod (p-1)`

Since all factors are small (≤ 97), each sub-DLP is trivial.

## Attack Steps

1. Connect to server, get `P`, `G`, `SERVER_PUBLIC = G^b mod P`
2. Factor `P-1` (all factors ≤ 97, so this is instant)
3. Run Pohlig-Hellman to recover `b`
4. Decrypt the flag: key = SHA256(str(b))[:16]

## Full Attack Script

```python
#!/usr/bin/env python3
"""
Pohlig-Hellman attack on smooth-order DH group
"""
import sys
import socket
import hashlib
from sympy import factorint, isprime
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def modinv(a, m):
    return pow(a, -1, m)

def baby_step_giant_step(g, h, p, order):
    """Solve g^x = h (mod p) where x is in [0, order)"""
    m = int(order**0.5) + 1
    # Baby steps: compute g^j for j in [0, m)
    table = {}
    gj = 1
    for j in range(m):
        table[gj] = j
        gj = gj * g % p
    # Giant steps: compute h * (g^(-m))^i for i in [0, m)
    g_inv_m = pow(g, -m, p)
    gamma = h
    for i in range(m):
        if gamma in table:
            return i * m + table[gamma]
        gamma = gamma * g_inv_m % p
    return None

def pohlig_hellman(g, h, p, order, factors):
    """
    Solve g^x = h (mod p) using Pohlig-Hellman.
    factors: dict {prime: exponent} of order factorization
    """
    residues = []
    moduli = []

    for q, e in factors.items():
        q_e = q ** e
        # Work in subgroup of order q^e
        g_sub = pow(g, order // q_e, p)
        h_sub = pow(h, order // q_e, p)

        # Solve g_sub^x = h_sub (mod p) using p-adic lifting
        x_k = 0
        g_k = pow(g_sub, q**(e-1), p)

        for k in range(e):
            # h_k = (g_sub^(-x_k) * h_sub)^(q^(e-1-k)) mod p
            inner = modinv(pow(g_sub, x_k, p), p) * h_sub % p
            h_k = pow(inner, q**(e-1-k), p)
            # DL in subgroup of order q
            d_k = baby_step_giant_step(g_k, h_k, p, q)
            if d_k is None:
                d_k = 0
            x_k = (x_k + d_k * q**k) % q_e

        residues.append(x_k)
        moduli.append(q_e)

    # CRT to combine
    return crt(residues, moduli)

def crt(residues, moduli):
    """Chinese Remainder Theorem"""
    M = 1
    for m in moduli:
        M *= m
    result = 0
    for r, m in zip(residues, moduli):
        Mi = M // m
        result += r * Mi * modinv(Mi, m)
    return result % M

def connect(host, port):
    s = socket.socket()
    s.connect((host, port))
    f = s.makefile('rb')
    return s, f

def recv_line(f):
    return f.readline().decode().strip()

def send(s, msg):
    s.sendall((msg + '\n').encode())

def attack(host, port=9999):
    print(f"[*] Connecting to {host}:{port}...")
    s, f = connect(host, port)

    # Read banner and parameters
    params = {}
    encrypted_flag = None
    for _ in range(10):
        line = recv_line(f)
        print(f"[banner] {line}")
        if line.startswith('P='):
            params['P'] = int(line.split('=')[1], 16)
        elif line.startswith('G='):
            params['G'] = int(line.split('=')[1], 16)
        elif line.startswith('SERVER_PUBLIC='):
            params['B'] = int(line.split('=')[1], 16)
        elif line.startswith('ENCRYPTED_FLAG='):
            encrypted_flag = bytes.fromhex(line.split('=')[1])
        if line.startswith('>'):
            break

    P = params['P']
    G = params['G']
    B = params['B']

    print(f"[*] P = {P}")
    print(f"[*] G = {G}")
    print(f"[*] B = G^b mod P = {B}")
    print(f"[*] Encrypted flag: {encrypted_flag.hex() if encrypted_flag else 'not received'}")

    # Factor P-1
    order = P - 1
    print(f"[*] Factoring P-1 = {order}...")
    factors = factorint(order)
    print(f"[*] P-1 factors: {factors}")

    # Pohlig-Hellman
    print("[*] Running Pohlig-Hellman...")
    b = pohlig_hellman(G, B, P, order, factors)
    print(f"[+] Recovered server private key b = {b}")

    # Verify
    if pow(G, b, P) == B:
        print("[+] Verification: G^b mod P == B CORRECT")
    else:
        print("[-] Verification failed!")
        return

    # Decrypt flag
    if encrypted_flag:
        iv = encrypted_flag[:16]
        ct = encrypted_flag[16:]
        key = hashlib.sha256(str(b).encode()).digest()[:16]
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), 16)
            print(f"[+] FLAG: {pt.decode()}")
        except Exception as e:
            print(f"[-] Decryption error: {e}")

    # Submit to server
    send(s, f"DECRYPT {hex(b)}")
    resp = recv_line(f)
    print(f"[+] Server says: {resp}")

    s.close()

if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '172.30.99.22'
    attack(host)
```

## Dependencies

```bash
pip install pycryptodome sympy
```

## Key Insight

A B-smooth prime `p` with B=97 means `p-1 = 2*3*5*7*...*97*k`. The Pohlig-Hellman algorithm reduces the DLP to sub-DLPs of orders 2, 3, 5, ..., 97 — all of which are trivially solvable in milliseconds. Never use primes with smooth group orders for Diffie-Hellman!
