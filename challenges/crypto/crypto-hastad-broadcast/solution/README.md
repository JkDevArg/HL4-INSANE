# Solution: Broadcast Attack — Hastad's Broadcast Attack (e=3)

## Vulnerability

The same plaintext `m` was encrypted with RSA `e=3` for three different recipients:
- `c1 = m^3 mod n1`
- `c2 = m^3 mod n2`
- `c3 = m^3 mod n3`

By the Chinese Remainder Theorem, we can recover `m^3 mod (n1*n2*n3)`. Since `m < n_i` for each i, we have `m^3 < n1*n2*n3`, so `m^3 mod (n1*n2*n3) = m^3`. Taking the integer cube root gives `m`.

## Theory: Chinese Remainder Theorem

Given `x ≡ c1 (mod n1)`, `x ≡ c2 (mod n2)`, `x ≡ c3 (mod n3)` with pairwise coprime moduli:

```
N = n1 * n2 * n3
N1 = N / n1, N2 = N / n2, N3 = N / n3
x = (c1*N1*N1^{-1}_n1 + c2*N2*N2^{-1}_n2 + c3*N3*N3^{-1}_n3) mod N
```

Then `m = cbrt(x)` (integer cube root).

## Full Attack Script

```python
#!/usr/bin/env python3
"""
Hastad's Broadcast Attack on RSA with e=3
"""
import sys
import requests
from Crypto.Util.number import long_to_bytes

def modinv(a, m):
    return pow(a, -1, m)

def crt(residues, moduli):
    """Chinese Remainder Theorem"""
    N = 1
    for m in moduli:
        N *= m
    result = 0
    for r, m in zip(residues, moduli):
        Ni = N // m
        result += r * Ni * modinv(Ni, m)
    return result % N

def integer_cbrt(n):
    """Integer cube root via Newton's method"""
    if n < 0:
        return -integer_cbrt(-n)
    if n == 0:
        return 0
    # Initial estimate
    x = int(round(n ** (1/3)))
    # Newton's method for integer cube root
    while True:
        x1 = (2 * x + n // (x * x)) // 3
        if x1 >= x:
            return x
        x = x1

def attack(host, port=9999):
    base_url = f"http://{host}:{port}"

    print("[*] Collecting ciphertexts from all 3 recipients...")
    
    data = {}
    for rid in range(1, 4):
        r = requests.get(f"{base_url}/recipient/{rid}")
        d = r.json()
        data[rid] = {
            'n': int(d['n'], 16),
            'e': d['e'],
            'c': int(d['ciphertext'], 16),
        }
        print(f"[*] Recipient {rid}: n={hex(data[rid]['n'])[:20]}..., c={hex(data[rid]['c'])[:20]}...")

    n1, c1 = data[1]['n'], data[1]['c']
    n2, c2 = data[2]['n'], data[2]['c']
    n3, c3 = data[3]['n'], data[3]['c']

    # Verify e=3 for all
    assert data[1]['e'] == 3 == data[2]['e'] == data[3]['e'], "e is not 3!"

    # Step 1: CRT to find m^3 mod (n1*n2*n3)
    print("[*] Running CRT...")
    m3 = crt([c1, c2, c3], [n1, n2, n3])
    print(f"[*] m^3 mod N = {hex(m3)[:30]}...")

    # Step 2: Integer cube root
    print("[*] Computing integer cube root...")
    m = integer_cbrt(m3)

    # Verify
    assert m ** 3 == m3, "Cube root check failed — m^3 might overflow (unlikely with 1024-bit n)"

    # Step 3: Decode
    try:
        flag = long_to_bytes(m).decode()
        print(f"[+] FLAG: {flag}")
    except Exception as e:
        print(f"[+] Plaintext (hex): {hex(m)}")
        print(f"[+] Plaintext (bytes): {long_to_bytes(m)}")

if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '172.30.99.20'
    attack(host)
```

## Edge Cases

If `m^3 >= n1*n2*n3` (e.g., if the flag is very long), the cube root will not be exact. In that case, padding is used and the attack needs modification. For short flags (< ~300 bytes) with 1024-bit moduli, this is never an issue since `m < 2^(flag_len*8)` and `n1*n2*n3 > 2^(3*1024) = 2^3072`.

## Prevention

- Use `e=65537` (large public exponent) instead of `e=3`
- Use proper OAEP padding, which randomizes the message so the same plaintext produces different ciphertexts
- Never encrypt the same unpadded plaintext to multiple recipients
