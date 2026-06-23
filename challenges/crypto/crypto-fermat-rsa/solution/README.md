# Solution: Too Close For Comfort — Fermat Factorization

## Vulnerability

The server generates RSA primes `p` and `q` such that `|p - q| < 2^20`. When primes are close to each other, Fermat's factorization method recovers them almost instantly.

## Theory: Fermat Factorization

For any odd composite `n = p * q`, we can write `n = a^2 - b^2 = (a+b)(a-b)` where `a = (p+q)/2` and `b = (p-q)/2`.

Since `|p-q| < 2^20`, we have `b < 2^19`. We simply try `a = ceil(sqrt(n)), ceil(sqrt(n))+1, ...` until `a^2 - n` is a perfect square.

With `|p-q| < 2^20` and a 1024-bit modulus, convergence happens in at most `~2^19` iterations — but in practice the gap is much smaller so it finds the factorization in milliseconds.

## Full Attack Script

```python
#!/usr/bin/env python3
"""
Fermat Factorization Attack on RSA with close primes
"""
import sys
import socket
import math
from Crypto.Util.number import long_to_bytes

def isqrt(n):
    """Integer square root"""
    if n < 0:
        raise ValueError("Square root not defined for negative numbers")
    if n == 0:
        return 0
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x

def is_perfect_square(n):
    """Check if n is a perfect square, return sqrt if yes"""
    s = isqrt(n)
    if s * s == n:
        return s
    return None

def fermat_factor(n):
    """
    Factor n using Fermat's method.
    Works fast when |p-q| is small.
    """
    a = isqrt(n)
    if a * a < n:
        a += 1
    
    b2 = a * a - n
    iterations = 0
    
    while True:
        b = is_perfect_square(b2)
        if b is not None:
            p = a + b
            q = a - b
            assert p * q == n
            return p, q
        a += 1
        b2 = a * a - n
        iterations += 1
        if iterations % 100000 == 0:
            print(f"[*] Fermat iteration {iterations}, a = {a}...")

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

    # Read banner
    for _ in range(3):
        line = recv_line(f)
        print(f"[banner] {line}")

    # Get public key
    send(s, "GET_PUBLIC_KEY")
    n_line = recv_line(f)
    e_line = recv_line(f)
    recv_line(f)  # prompt
    n = int(n_line.split('=')[1], 16)
    e = int(e_line.split('=')[1], 16)
    print(f"[*] n = {hex(n)[:20]}... ({n.bit_length()} bits)")
    print(f"[*] e = {e}")

    # Get encrypted flag
    send(s, "GET_ENCRYPTED_FLAG")
    ct_line = recv_line(f)
    recv_line(f)  # prompt
    ct = int(ct_line.split('=')[1], 16)
    print(f"[*] ct = {hex(ct)[:20]}...")

    # Fermat factorization
    print("[*] Running Fermat factorization...")
    p, q = fermat_factor(n)
    print(f"[+] p = {p}")
    print(f"[+] q = {q}")
    print(f"[+] |p-q| = {abs(p-q)}")
    assert p * q == n, "Factorization wrong!"

    # Compute private key
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    # Decrypt flag
    m = pow(ct, d, n)
    flag_bytes = long_to_bytes(m)
    print(f"[+] Decrypted flag: {flag_bytes.decode(errors='replace')}")

    # Submit to server
    send(s, f"DECRYPT_FLAG {hex(m)}")
    resp = recv_line(f)
    print(f"[+] Server: {resp}")

    s.close()

if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '172.30.99.21'
    attack(host)
```

## Performance

| `|p-q|` | Max iterations | Time (approx) |
|---------|---------------|---------------|
| < 2^10  | ~512          | < 1 ms        |
| < 2^20  | ~524,288      | < 1 second    |
| < 2^40  | ~5*10^11      | Hours         |
| > n^0.5 | infeasible    | Years         |

## Prevention

- Generate `p` and `q` independently with a proper CSPRNG
- Verify that `|p-q| > 2^(n_bits/2 - 100)` before using the keypair
- Modern RSA libraries (OpenSSL, etc.) perform this check automatically
