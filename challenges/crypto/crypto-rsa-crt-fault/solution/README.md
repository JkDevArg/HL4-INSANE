# Solution: Bellcore's Revenge — RSA-CRT Fault Injection

## Background

The **Bellcore attack** (Boneh, DeMillo, Lipton, 1997) shows that a single faulty RSA-CRT signature leaks a prime factor of `N`, completely breaking the key.

## Theory: RSA-CRT Signature

Normal RSA-CRT signing of message `m`:
```
sp = m^dp mod p    (dp = d mod (p-1))
sq = m^dq mod q    (dq = d mod (q-1))
sig = CRT(sp, sq) = sq + q * (QINV * (sp - sq) mod p)
```
Verification: `sig^e mod N == m mod N`

## Faulty Signature Analysis

When a bit flip corrupts `dp` to `dp'`:
```
sp' = m^dp' mod p    (WRONG — different from m^dp mod p)
sq  = m^dq mod q     (CORRECT)
sig_f = CRT(sp', sq)
```

Now verify component-wise:
- `sig_f^e mod q = (m^dq * ...)^e mod q = m mod q` (correct, since sq is right)
- `sig_f^e mod p != m mod p` (wrong, since sp' is wrong)

Therefore:
```
sig_f^e - m ≡ 0 (mod q)  but  sig_f^e - m ≢ 0 (mod p)
gcd(sig_f^e - m, N) = q
```

## Attack Steps

1. GET_PUBLIC_KEY: get `(N, e)`
2. Compute `m = bytes_to_long(CHALLENGE_MSG)`
3. Call SIGN_FAULT repeatedly until STATUS=FAULTY
4. Also get a SIGN_NORMAL signature for the same message
5. Compute `gcd(sig_f^e - m, N)` to recover `q`
6. Recover `p = N // q`, compute `d`, forge correct signature
7. AUTHENTICATE with the forged signature

## Full Attack Script

```python
#!/usr/bin/env python3
"""
Bellcore RSA-CRT Fault Attack
"""
import sys
import socket
from math import gcd
from Crypto.Util.number import bytes_to_long, long_to_bytes

CHALLENGE_MSG = bytes.fromhex("5349474e5f544849535f544f5f41555448454e544943415445")  # filled in below

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

    # Read banner and get challenge message
    challenge_hex = None
    for _ in range(4):
        line = recv_line(f)
        print(f"[banner] {line}")
        if line.startswith('CHALLENGE_MSG='):
            challenge_hex = line.split('=')[1]

    challenge_msg = bytes.fromhex(challenge_hex)
    m = bytes_to_long(challenge_msg)
    print(f"[*] Challenge message: {challenge_msg}")
    print(f"[*] m = {hex(m)[:20]}...")

    # Get public key
    send(s, "GET_PUBLIC_KEY")
    n_line = recv_line(f)
    e_line = recv_line(f)
    recv_line(f)  # prompt
    N = int(n_line.split('=')[1], 16)
    E = int(e_line.split('=')[1], 16)
    print(f"[*] N = {hex(N)[:20]}... ({N.bit_length()} bits)")
    print(f"[*] E = {E}")

    # Get a correct signature for comparison
    send(s, f"SIGN_NORMAL {hex(m)}")
    sig_normal_line = recv_line(f)
    recv_line(f)  # VALID= line
    recv_line(f)  # prompt
    sig_correct = int(sig_normal_line.split('=')[1], 16)
    print(f"[*] Correct signature: {hex(sig_correct)[:20]}...")

    # Collect faulty signatures until we get one with STATUS=FAULTY
    print("[*] Requesting faulty signatures...")
    faulty_sigs = []
    
    for attempt in range(50):
        send(s, f"SIGN_FAULT {hex(m)}")
        sig_line = recv_line(f)
        status_line = recv_line(f)
        try:
            recv_line(f)  # prompt
        except:
            pass
        
        sig_f = int(sig_line.split('=')[1], 16)
        is_faulty = 'FAULTY' in status_line
        
        if is_faulty:
            faulty_sigs.append(sig_f)
            print(f"[+] Got faulty signature (attempt {attempt+1}): {hex(sig_f)[:20]}...")
            if len(faulty_sigs) >= 3:
                break
        else:
            print(f"[-] Attempt {attempt+1}: no fault, sig valid")

    if not faulty_sigs:
        print("[-] Could not get any faulty signatures in 50 attempts")
        s.close()
        return

    # Bellcore attack: gcd(sig_f^e - m, N)
    print("[*] Running Bellcore attack...")
    for i, sig_f in enumerate(faulty_sigs):
        diff = (pow(sig_f, E, N) - m) % N
        factor = gcd(diff, N)
        
        if factor not in (1, N) and N % factor == 0:
            print(f"[+] Found factor from faulty sig {i+1}!")
            q = factor
            p = N // q
            print(f"[+] p = {p}")
            print(f"[+] q = {q}")
            assert p * q == N
            
            # Compute private key
            phi = (p - 1) * (q - 1)
            d = pow(E, -1, phi)
            
            # Sign the challenge correctly
            sig_forged = pow(m, d, N)
            
            # Verify locally
            assert pow(sig_forged, E, N) == m % N, "Signature verification failed!"
            print(f"[+] Forged signature: {hex(sig_forged)[:20]}...")
            
            # Authenticate
            send(s, f"AUTHENTICATE {hex(sig_forged)}")
            resp = recv_line(f)
            print(f"[+] Server: {resp}")
            
            if 'FLAG' in resp:
                print("[+] SUCCESS!")
            
            s.close()
            return

    print("[-] Attack failed — gcd did not reveal a factor")
    print("[*] Try again: the faulty signature must actually be faulty (not just invalid padding)")
    s.close()

if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '172.30.99.20'
    attack(host)
```

## Why gcd Works

The faulty signature satisfies:
- `sig_f ≡ m^(1/e) (mod q)` (because the dq computation was correct)
- `sig_f ≢ m^(1/e) (mod p)` (because dp was corrupted)

Therefore `sig_f^e ≡ m (mod q)` but `sig_f^e ≢ m (mod p)`.

So `sig_f^e - m ≡ 0 (mod q)` and `gcd(sig_f^e - m, N) = q`.

## Historical Note

This attack was published in 1997 by Boneh, DeMillo, and Lipton. It applies to any implementation that uses CRT acceleration for RSA signatures — including smart cards, HSMs, and TLS implementations. The defence is to verify each signature before returning it.

## Prevention

- Verify every CRT signature before returning: `assert pow(sig, e, n) == m`
- Use error detection codes in CRT computations
- Physical shielding against fault injection (voltage glitching, laser fault injection)
