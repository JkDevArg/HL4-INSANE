# Solution: Million Messages — Bleichenbacher's Attack (BB'98)

## Background

Daniel Bleichenbacher's 1998 paper "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS#1" showed that a PKCS#1 v1.5 padding oracle is sufficient to decrypt any RSA ciphertext. The attack uses ~1 million adaptive chosen-ciphertext queries for 1024-bit RSA.

## Theory

PKCS#1 v1.5 encrypted message format (K = byte length of N):
```
0x00 0x02 <PS: K-3-mlen non-zero bytes> 0x00 <message>
```

The oracle tells us if `Decrypt(c)` starts with `0x00 0x02`. Call this set:
```
B = [2 * 256^(K-2), 3 * 256^(K-2) - 1]
```

## Algorithm (Bleichenbacher '98, simplified)

Given ciphertext `c0 = m^e mod n` where `m ∈ [2B, 3B-1]`:

1. **Blinding**: find `s1` such that `CHECK(c0 * s1^e mod n)` = VALID
   → `m * s1 mod n ∈ [2B, 3B-1]`
   
2. **Interval narrowing**: maintain interval `M = {[a,b]}` of possible `m` values.
   For each new valid `s`:
   ```
   For each [a,b] in M, for each r where ceil((a*s-3B+1)/n) <= r <= floor((b*s-2B)/n):
       new interval = [ceil((2B+r*n)/s), floor((3B-1+r*n)/s)]
   ```

3. **Repeat** with increasing `s` until `M = {[a,a]}` (single value = plaintext)

## Full Attack Script

```python
#!/usr/bin/env python3
"""
Bleichenbacher '98 RSA-PKCS#1 v1.5 Padding Oracle Attack
Warning: requires ~500k-2M oracle queries for 1024-bit RSA.
"""
import sys
import socket
import math

def connect(host, port):
    s = socket.socket()
    s.connect((host, port))
    f = s.makefile('rb')
    return s, f

def recv_line(f):
    return f.readline().decode().strip()

def send(s, msg):
    s.sendall((msg + '\n').encode())

def pkcs_oracle(s, f, ct_int, N, E):
    """Query the padding oracle. Returns True if PKCS conformant."""
    ct_hex = hex(ct_int)
    send(s, f"CHECK {ct_hex}")
    resp = recv_line(f)
    # Consume prompt character
    try:
        prompt = recv_line(f)
    except:
        pass
    return resp == "VALID_PADDING"

def ceildiv(a, b):
    return -(-a // b)

def floordiv(a, b):
    return a // b

def bleichenbacher(s, f, N, E, K, c0):
    """
    Bleichenbacher's attack.
    Returns the decrypted plaintext integer.
    """
    B = 2 ** (8 * (K - 2))
    B2 = 2 * B
    B3 = 3 * B

    query_count = 0

    def oracle(c):
        nonlocal query_count
        query_count += 1
        if query_count % 10000 == 0:
            print(f"  [*] Query count: {query_count}")
        return pkcs_oracle(s, f, c, N, E)

    # Step 1: Blinding (if c0 is already PKCS conformant, s0=1 works)
    print("[*] Step 1: Checking if c0 is already PKCS conformant...")
    if oracle(c0):
        print("[+] c0 is PKCS conformant, s0 = 1")
        c = c0
        s0 = 1
    else:
        print("[*] c0 not conformant, finding blinding factor...")
        s0 = 1
        while True:
            s0 += 1
            c = c0 * pow(s0, E, N) % N
            if oracle(c):
                print(f"[+] Found s0 = {s0}")
                break

    # Initial interval
    M = [(B2, B3 - 1)]

    # Step 2: Start searching
    si = ceildiv(N, B3)
    step = 2
    iteration = 0

    while True:
        iteration += 1
        print(f"[*] Iteration {iteration}, intervals: {len(M)}, step={step}")

        if step == 2:
            # Step 2a or 2b: search for si
            if iteration == 1:
                # Step 2a: start with si = ceil(n / 3B)
                si = ceildiv(N, B3)
            elif len(M) > 1:
                # Step 2b: multiple intervals, increment si
                si += 1
            else:
                # Step 2c: single interval, narrow search
                a, b = M[0]
                ri = ceildiv(2 * (b * si - B2), N)
                si = ceildiv(B2 + ri * N, b)
                step = 3

        if step in (2, 3):
            # Find si such that oracle returns True
            found = False
            max_attempts = N // 100  # safety limit
            attempts = 0

            if step == 3:
                # Step 2c: structured search
                a, b = M[0]
                ri = ceildiv(2 * (b * si - B2), N)
                si = ceildiv(B2 + ri * N, b)
                while si <= floordiv(B3 - 1 + ri * N, a):
                    c_test = c0 * pow(si * s0, E, N) % N
                    if oracle(c_test):
                        found = True
                        break
                    si += 1
                    if si > floordiv(B3 - 1 + ri * N, a):
                        ri += 1
                        si = ceildiv(B2 + ri * N, b)
            else:
                # Step 2a/2b: linear search
                while attempts < max_attempts:
                    c_test = c0 * pow(si * s0, E, N) % N
                    if oracle(c_test):
                        found = True
                        break
                    si += 1
                    attempts += 1

            if not found and step == 3:
                print("[-] Step 2c: no si found in range, continuing...")
                step = 2
                continue

        # Step 3: Narrow intervals
        new_M = []
        for a, b in M:
            ri_min = ceildiv(a * si - B3 + 1, N)
            ri_max = floordiv(b * si - B2, N)
            for ri in range(ri_min, ri_max + 1):
                new_a = max(a, ceildiv(B2 + ri * N, si))
                new_b = min(b, floordiv(B3 - 1 + ri * N, si))
                if new_a <= new_b:
                    new_M.append((new_a, new_b))

        # Merge overlapping intervals
        new_M.sort()
        merged = []
        for interval in new_M:
            if merged and merged[-1][1] >= interval[0] - 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], interval[1]))
            else:
                merged.append(list(interval))
        M = [tuple(i) for i in merged]

        print(f"  Intervals: {[(hex(a)[:10], hex(b)[:10]) for a, b in M[:3]]}")

        # Step 4: Check if done
        if len(M) == 1 and M[0][0] == M[0][1]:
            m = M[0][0] * pow(s0, -1, N) % N
            print(f"[+] Found m = {hex(m)[:20]}...")
            print(f"[+] Total oracle queries: {query_count}")
            return m

        if len(M) == 1:
            step = 3
        else:
            step = 2
            si += 1

def attack(host, port=9999):
    print(f"[*] Connecting to {host}:{port}...")
    s, f = connect(host, port)

    # Read banner and parameters
    params = {}
    for _ in range(8):
        line = recv_line(f)
        print(f"[banner] {line}")
        if line.startswith('n='):
            params['n'] = int(line.split('=')[1], 16)
        elif line.startswith('e='):
            params['e'] = int(line.split('=')[1], 16)
        elif line.startswith('k='):
            params['k'] = int(line.split('=')[1])
        elif line.startswith('CIPHERTEXT='):
            params['ct'] = int(line.split('=')[1], 16)

    N = params['n']
    E = params['e']
    K = params['k']
    c0 = params['ct']

    print(f"[*] N = {hex(N)[:20]}... ({N.bit_length()} bits)")
    print(f"[*] K = {K} bytes")
    print(f"[*] Starting Bleichenbacher attack (expect ~500k-1M queries)...")
    print(f"[*] This will take several minutes to hours depending on connection speed")

    m = bleichenbacher(s, f, N, E, K, c0)

    from Crypto.Util.number import long_to_bytes
    m_bytes = long_to_bytes(m, K)
    print(f"[*] Decrypted bytes: {m_bytes.hex()[:40]}...")

    # Strip PKCS#1 v1.5 padding: 0x00 0x02 <PS> 0x00 <message>
    if m_bytes[:2] == b'\x00\x02':
        null_pos = m_bytes.index(0x00, 2)
        plaintext = m_bytes[null_pos + 1:]
        print(f"[+] Plaintext: {plaintext.decode(errors='replace')}")
    else:
        print(f"[+] Plaintext (no valid PKCS header): {m_bytes}")

    s.close()

if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '172.30.99.21'
    attack(host)
```

## Performance Notes

- 1024-bit RSA: ~500k-2M queries, several minutes to hours
- Use a fast network connection (same datacenter = milliseconds per query)
- The server allows up to 2,000,000 queries per connection

## ROBOT Attack (Modern Variant)

The same vulnerability affected TLS implementations until 2017 (Return Of Bleichenbacher's Oracle Threat). Major vendors including F5, Citrix, Cisco, and others were found vulnerable. CVE-2017-13099 and related CVEs.

## Prevention

- Use OAEP padding instead of PKCS#1 v1.5 for RSA encryption
- If PKCS#1 v1.5 must be used, use constant-time padding validation that never reveals whether padding was valid
- TLS 1.3 removed RSA key exchange entirely
