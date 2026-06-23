# Solution: Nonce Sense — DSA Repeated Nonce Attack

## Vulnerability

Two DSA signatures were created with the **same nonce `k`**. This is catastrophic: an attacker who observes two signatures `(r1, s1)` and `(r2, s2)` on messages `m1` and `m2` can recover the private key `x` with simple arithmetic.

## Theory

DSA signing: `s = k^{-1} * (h + x*r) mod q`

With two signatures sharing nonce `k` (so `r1 == r2 = r`):
- `s1 = k^{-1} * (h1 + x*r) mod q`
- `s2 = k^{-1} * (h2 + x*r) mod q`

Subtracting: `s1 - s2 = k^{-1} * (h1 - h2) mod q`

Therefore: `k = (h1 - h2) * (s1 - s2)^{-1} mod q`

Then: `x = r^{-1} * (s1*k - h1) mod q`

## Attack Steps

1. GET_SIGNATURES: get `(msg1, r1, s1)` and `(msg2, r2, s2)` — note `r1 == r2`
2. Compute `h1 = SHA1(msg1)`, `h2 = SHA1(msg2)`
3. Recover `k = (h1 - h2) * modinv(s1 - s2, q) mod q`
4. Recover `x = modinv(r1, q) * (s1*k - h1) mod q`
5. Sign the challenge message with recovered `x` and any random `k`

## Full Attack Script

```python
#!/usr/bin/env python3
"""
DSA Repeated Nonce Attack — recovers private key from two signatures with same k
"""
import sys
import socket
import hashlib
import random
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

def modinv(a, m):
    return pow(a, -1, m)

def attack(host, port=9999):
    print(f"[*] Connecting to {host}:{port}...")
    s, f = connect(host, port)

    # Read banner
    for _ in range(3):
        line = recv_line(f)
        print(f"[banner] {line}")

    # Get DSA public key parameters
    send(s, "GET_PUBLIC_KEY")
    params = {}
    for _ in range(5):
        line = recv_line(f)
        if '=' in line and not line.startswith('>'):
            k, v = line.split('=', 1)
            params[k] = int(v, 16)
    recv_line(f)  # consume prompt

    p = params['p']
    q = params['q']
    g = params['g']
    y = params['y']
    print(f"[*] q = {hex(q)[:20]}... ({q.bit_length()} bits)")

    # Get signatures
    send(s, "GET_SIGNATURES")
    sigs = {}
    challenge_msg = None
    for _ in range(10):
        line = recv_line(f)
        if line.startswith('>'):
            break
        if '=' in line:
            k, v = line.split('=', 1)
            sigs[k.strip()] = v.strip()

    msg1 = bytes.fromhex(sigs['msg1'])
    r1 = int(sigs['r1'], 16)
    s1 = int(sigs['s1'], 16)
    msg2 = bytes.fromhex(sigs['msg2'])
    r2 = int(sigs['r2'], 16)
    s2 = int(sigs['s2'], 16)
    challenge_msg = bytes.fromhex(sigs['challenge_msg'])

    print(f"[*] msg1: {msg1}")
    print(f"[*] msg2: {msg2}")
    print(f"[*] r1 = {hex(r1)[:20]}...")
    print(f"[*] r2 = {hex(r2)[:20]}...")
    print(f"[*] r1 == r2: {r1 == r2}")

    if r1 != r2:
        print("[-] r values are different — nonce may not be reused directly")
        print("[*] Attempting attack anyway...")

    # Compute message hashes
    h1 = int(hashlib.sha1(msg1).hexdigest(), 16)
    h2 = int(hashlib.sha1(msg2).hexdigest(), 16)

    # Recover nonce k
    # s1 - s2 = k^{-1} * (h1 - h2) mod q
    # => k = (h1 - h2) * (s1 - s2)^{-1} mod q
    s_diff = (s1 - s2) % q
    if s_diff == 0:
        print("[-] s1 == s2, cannot divide")
        return

    k_recovered = (h1 - h2) * modinv(s_diff, q) % q
    print(f"[+] Recovered k = {hex(k_recovered)[:20]}...")

    # Recover private key x
    # s1 = k^{-1} * (h1 + x*r1) mod q
    # => x = r1^{-1} * (s1*k - h1) mod q
    x_recovered = modinv(r1, q) * (s1 * k_recovered - h1) % q
    print(f"[+] Recovered private key x = {hex(x_recovered)[:20]}...")

    # Verify: y should equal g^x mod p
    y_check = pow(g, x_recovered, p)
    if y_check == y:
        print("[+] Private key verified: g^x mod p == y ✓")
    else:
        print("[-] Private key verification failed!")
        # Try negation
        x_recovered = q - x_recovered
        y_check = pow(g, x_recovered, p)
        if y_check == y:
            print("[+] Private key verified (negated): g^x mod p == y ✓")
        else:
            print("[-] Still failed, something is wrong")
            return

    # Sign the challenge message with recovered key
    print(f"[*] Signing challenge: {challenge_msg}")
    h_chall = int(hashlib.sha1(challenge_msg).hexdigest(), 16)

    # Use a random valid nonce for signing
    while True:
        k_new = random.randint(1, q - 1)
        r_new = pow(g, k_new, p) % q
        if r_new == 0:
            continue
        s_new = modinv(k_new, q) * (h_chall + x_recovered * r_new) % q
        if s_new == 0:
            continue
        break

    print(f"[*] New signature: r={hex(r_new)}, s={hex(s_new)}")

    # Submit
    send(s, f"VERIFY_AUTH {hex(r_new)} {hex(s_new)}")
    resp = recv_line(f)
    print(f"[+] Server: {resp}")

    if 'FLAG' in resp:
        print("[+] SUCCESS!")

    s.close()

if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '172.30.99.22'
    attack(host)
```

## Why Sony PlayStation 3 Was Broken

This exact attack was used against the PS3 in 2010. Sony used the same nonce `k` for ALL ECDSA signatures (they had a bug in their RNG that always returned the same value), allowing hackers to recover the signing key for the entire console.

## Prevention

- Use a CSPRNG that properly generates unique nonces
- Use deterministic DSA/ECDSA (RFC 6979): `k = HMAC-SHA256(private_key, hash)`
- RFC 6979 is immune to nonce reuse because k is derived deterministically from the message
