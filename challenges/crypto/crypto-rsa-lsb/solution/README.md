# Solution: One Bit At A Time — RSA LSB Oracle Attack

## Vulnerability

The server decrypts any ciphertext and returns the **least significant bit** of the plaintext. This is sufficient to perform a binary search and recover the full plaintext in O(log n) queries — specifically, exactly `ceil(log2(n))` queries (≈ 2048 for a 2048-bit RSA key).

## Theory: LSB Oracle = Parity Oracle

For RSA with public key `(n, e)`:
- Given ciphertext `c = m^e mod n`
- Query `2^e * c mod n` = `(2m)^e mod n` → decrypts to `2m mod n`
- If `2m mod n` is even → `m < n/2`
- If `2m mod n` is odd → `m >= n/2`

This gives a 1-bit comparison at each step, enabling bisection search.

## Algorithm

```
lo = 0, hi = n
for i in range(2048):
    c = c * pow(2, e, n) % n  (double the ciphertext = double the plaintext)
    lsb = oracle(c)
    if lsb == 1:  (2^i * m mod n is odd => m >= midpoint)
        lo = (lo + hi) // 2
    else:
        hi = (lo + hi) // 2
plaintext = hi
```

## Full Attack Script

```python
#!/usr/bin/env python3
"""
RSA LSB Oracle Attack — recovers plaintext in ceil(log2(n)) queries
"""
import sys
import socket
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

def lsb_oracle(s, f, ct_hex):
    send(s, f"QUERY {ct_hex}")
    resp = recv_line(f)
    # consume prompt
    prompt = recv_line(f)
    return int(resp.split('=')[1])

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
    prompt = recv_line(f)
    n = int(n_line.split('=')[1], 16)
    e = int(e_line.split('=')[1], 16)
    print(f"[*] n = {hex(n)[:20]}... ({n.bit_length()} bits)")
    print(f"[*] e = {e}")

    # Get ciphertext
    send(s, "GET_CIPHERTEXT")
    ct_line = recv_line(f)
    prompt = recv_line(f)
    c = int(ct_line.split('=')[1], 16)
    print(f"[*] c = {hex(c)[:20]}...")

    # LSB oracle bisection attack
    print(f"[*] Starting bisection attack ({n.bit_length()} iterations)...")
    
    # f = 2^e mod n (multiplier for doubling plaintext)
    f_mult = pow(2, e, n)
    
    lo = 0
    hi = n
    c_curr = c

    bits = n.bit_length()
    for i in range(bits):
        c_curr = c_curr * f_mult % n
        lsb = lsb_oracle(s, f, hex(c_curr))
        mid = (lo + hi) // 2
        if lsb == 1:
            lo = mid
        else:
            hi = mid
        
        if i % 200 == 0:
            print(f"[*] Progress: {i}/{bits} ({100*i//bits}%)")

    # Recover plaintext
    m = hi
    try:
        pt_bytes = long_to_bytes(m)
        # Strip null bytes and try to decode
        pt = pt_bytes.lstrip(b'\x00').decode('utf-8', errors='replace')
        print(f"[+] Plaintext: {pt}")
    except Exception as e2:
        print(f"[+] Plaintext (hex): {hex(m)}")

    s.close()

if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '172.30.99.20'
    attack(host)
```

## Notes

- 2048-bit RSA requires ~2048 queries, well within the 3000 limit
- The attack uses only the LSB (parity) of the decrypted value
- This is the classic Coppersmith–Franklin parity oracle / LSB oracle attack
- Textbook RSA is used here (no OAEP padding), making this straightforward

## Prevention

- Never expose decryption oracles, even if output is limited
- Use OAEP padding (doesn't prevent the oracle but makes exploitation harder)
- Rate-limit decryption requests
