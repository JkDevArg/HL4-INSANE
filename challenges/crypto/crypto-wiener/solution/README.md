# Solution: Small Key Big Problem — Wiener's Attack

## Vulnerability

When the RSA private exponent `d` satisfies `d < n^0.25 / 3`, Michael Wiener's 1990 algorithm recovers `d` from the public key `(n, e)` alone using **continued fractions** in polynomial time.

## Theory: Wiener's Attack via Continued Fractions

From RSA: `e*d = 1 + k*phi(n)` for some integer `k`. Therefore:
```
e/n ≈ k/d  (since phi(n) ≈ n)
```

The fraction `k/d` appears as a **convergent** in the continued fraction expansion of `e/n`. Wiener showed that if `d < n^0.25 / 3`, then `k/d` is guaranteed to be a convergent, so we just enumerate all convergents until we find one where `phi = (e*d - 1) / k` is an integer and the resulting quadratic `x^2 - (n - phi + 1)*x + n = 0` has integer roots (which would be `p` and `q`).

## Algorithm

```
1. Compute continued fraction expansion of e/n: [a0, a1, a2, ...]
2. For each convergent k/d of that expansion:
   a. Check if e*d ≡ 1 (mod k) — i.e., (e*d - 1) % k == 0
   b. Compute phi = (e*d - 1) / k
   c. Solve x^2 - (n - phi + 1)*x + n = 0
   d. If roots are integers p, q with p*q == n → found it!
3. Return d
```

## Full Attack Script

```python
#!/usr/bin/env python3
"""
Wiener's Attack on RSA — Continued Fraction Method
"""
import sys
import socket
import math
from Crypto.Util.number import long_to_bytes

def connect(host, port):
    s = socket.socket()
    s.connect((host, port))
    f = s.makefile('rb')
    return s, f

def recv_line(f):
    return f.readline().decode().strip()

def send(s, msg):
    s.sendall((msg + '\n').encode())

def continued_fraction(n, d):
    """Compute continued fraction coefficients of n/d"""
    cf = []
    while d:
        cf.append(n // d)
        n, d = d, n % d
    return cf

def convergents(cf):
    """Compute convergents from continued fraction coefficients"""
    convs = []
    p_prev, p_curr = 1, cf[0]
    q_prev, q_curr = 0, 1
    convs.append((p_curr, q_curr))
    for i in range(1, len(cf)):
        p_prev, p_curr = p_curr, cf[i] * p_curr + p_prev
        q_prev, q_curr = q_curr, cf[i] * q_curr + q_prev
        convs.append((p_curr, q_curr))
    return convs

def isqrt(n):
    """Integer square root"""
    if n < 0:
        return None
    if n == 0:
        return 0
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x

def wiener_attack(n, e):
    """
    Apply Wiener's attack to RSA public key (n, e).
    Returns d if successful, None otherwise.
    """
    cf = continued_fraction(e, n)
    convs = convergents(cf)
    
    for k, d in convs:
        if k == 0:
            continue
        # Check if phi is an integer
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        
        # Solve x^2 - (n - phi + 1)*x + n = 0
        # p + q = n - phi + 1, p*q = n
        b = n - phi + 1
        discriminant = b * b - 4 * n
        if discriminant < 0:
            continue
        
        sqrt_disc = isqrt(discriminant)
        if sqrt_disc * sqrt_disc != discriminant:
            continue
        
        # Integer roots
        p = (b + sqrt_disc) // 2
        q = (b - sqrt_disc) // 2
        
        if p * q == n:
            print(f"[+] Found! k={k}, d={d}")
            print(f"[+] p={p}")
            print(f"[+] q={q}")
            return d
    
    return None

def attack(host, port=9999):
    print(f"[*] Connecting to {host}:{port}...")
    s, f = connect(host, port)

    # Read banner
    for _ in range(3):
        line = recv_line(f)
        print(f"[banner] {line}")

    # Get challenges
    send(s, "GET_CHALLENGES")
    data = {}
    current_inst = None
    for _ in range(25):
        line = recv_line(f)
        print(f"  {line}")
        if 'INSTANCE 1' in line:
            current_inst = 1
        elif 'INSTANCE 2' in line:
            current_inst = 2
        elif 'INSTANCE 3' in line:
            current_inst = 3
        elif '=' in line and current_inst:
            k, v = line.split('=', 1)
            data[f"{k.strip()}{current_inst}"] = int(v.strip(), 16)
        if line.startswith('>'):
            break

    # Sometimes the data keys need adjustment
    # Try both key formats
    def get_param(base, inst):
        key1 = f"{base}{inst}"
        return data.get(key1)

    n3 = get_param('n', 3)
    e3 = get_param('e', 3)
    ct3 = get_param('ct', 3)

    if not all([n3, e3, ct3]):
        print("[-] Failed to parse challenge data")
        print(f"[*] Raw data keys: {list(data.keys())}")
        s.close()
        return

    print(f"\n[*] Target: N3 = {hex(n3)[:20]}... ({n3.bit_length()} bits)")
    print(f"[*]         E3 = {hex(e3)[:20]}...")
    print(f"[*]         CT3= {hex(ct3)[:20]}...")

    # Warm up: attack instance 1 (easier)
    n1 = get_param('n', 1)
    e1 = get_param('e', 1)
    if n1 and e1:
        print(f"\n[*] Warmup: attacking instance 1 ({n1.bit_length()}-bit)...")
        d1 = wiener_attack(n1, e1)
        if d1:
            print(f"[+] Instance 1 d1 = {hex(d1)}")
        else:
            print("[-] Instance 1 failed (unexpected)")

    # Attack instance 3 (contains flag)
    print(f"\n[*] Attacking instance 3 ({n3.bit_length()}-bit)...")
    d3 = wiener_attack(n3, e3)

    if d3:
        print(f"[+] Recovered d3 = {hex(d3)}")
        
        # Decrypt locally
        pt = pow(ct3, d3, n3)
        try:
            flag = long_to_bytes(pt).decode()
            print(f"[+] Decrypted flag: {flag}")
        except Exception:
            print(f"[+] Decrypted (hex): {hex(pt)}")
            flag_bytes = long_to_bytes(pt)
            print(f"[+] Decrypted (bytes): {flag_bytes}")

        # Submit to server
        send(s, f"DECRYPT_FLAG {hex(d3)}")
        resp = recv_line(f)
        print(f"[+] Server: {resp}")
        
        if 'FLAG' in resp:
            print("[+] SUCCESS!")
    else:
        print("[-] Wiener's attack failed — d may not be small enough")
        print("[*] Try Boneh-Durfee attack for d < n^0.292")

    s.close()

if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '172.30.99.22'
    attack(host)
```

## Complexity

Wiener's attack runs in `O(log^2 n)` time — essentially instantaneous even for large n. It only requires the public key `(n, e)`.

## Conditions for Success

| Condition | Attack |
|-----------|--------|
| `d < n^0.25 / 3` | Wiener (1990) — guaranteed |
| `d < n^0.292` | Boneh-Durfee (1999) — lattice method |
| `d < n^0.5 / 2` | Small CRT exponents variant |

## Prevention

- Never use a private exponent smaller than `n^0.5`
- Standard practice: `d` should be roughly the same size as `n`
- Use `e = 65537` (standard). If you want fast decryption, use CRT with safe prime sizes, not a small `d`
