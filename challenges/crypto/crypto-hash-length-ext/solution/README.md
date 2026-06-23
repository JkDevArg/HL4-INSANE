# Solution: Secret Suffix? Prefix! — SHA-256 Length Extension Attack

## Vulnerability

The server computes `sig = SHA256(secret || message)`. Because SHA-256 uses Merkle-Damgård construction, if you know `SHA256(secret || message)`, you can compute `SHA256(secret || message || padding || extension)` without knowing `secret`. This is the **hash length extension attack**.

## Theory

SHA-256 processes input in 64-byte blocks. The padding appended is:
```
0x80 00 00 ... 00 <64-bit big-endian length>
```

If we know `H = SHA256(secret || msg)`, we can:
1. Treat `H` as the internal SHA-256 state after processing `secret || msg || padding`
2. Continue hashing from that state with `extension` bytes
3. The result equals `SHA256(secret || msg || padding || extension)`

The server will accept this because it verifies `SHA256(secret || (msg || padding || extension))` = our forged hash.

## Attack Steps

1. GET `/api/sample` → get `(msg, sig)` where `msg = "user=guest&action=read"`
2. Try secret lengths 8-16 to compute the SHA-256 padding for `secret || msg`
3. For each length, forge: `SHA256(secret || msg || padding || "&admin=true")`
4. Send to `/api/admin` with base64-encoded `(msg || padding || "&admin=true")`

## Full Attack Script

```python
#!/usr/bin/env python3
"""
SHA-256 Length Extension Attack
"""
import sys
import struct
import hashlib
import base64
import requests

def sha256_padding(msg_len):
    """Compute the SHA-256 padding for a message of msg_len bytes"""
    # Message length in bits
    bit_len = msg_len * 8
    # Padding: 0x80 followed by zeros, then 8-byte big-endian length
    padding = b'\x80'
    padding += b'\x00' * ((55 - msg_len) % 64)
    padding += struct.pack('>Q', bit_len)
    return padding

def sha256_extend(hash_hex, orig_len, extension):
    """
    Given SHA256(secret || msg) = hash_hex, where len(secret || msg) = orig_len,
    compute SHA256(secret || msg || padding || extension).
    orig_len = secret_len + len(msg)
    """
    # Parse the hash as SHA-256 internal state (8 x 32-bit words)
    h = [int(hash_hex[i*8:(i+1)*8], 16) for i in range(8)]

    # SHA-256 constants
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]

    def rotr(x, n):
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    def ch(x, y, z):
        return (x & y) ^ (~x & z)

    def maj(x, y, z):
        return (x & y) ^ (x & z) ^ (y & z)

    def sigma0(x):
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

    def sigma1(x):
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

    def gamma0(x):
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)

    def gamma1(x):
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)

    def sha256_block(block, state):
        w = list(struct.unpack('>16I', block))
        for i in range(16, 64):
            w.append((gamma1(w[i-2]) + w[i-7] + gamma0(w[i-15]) + w[i-16]) & 0xFFFFFFFF)
        a, b, c, d, e, f, g, hh = state
        for i in range(64):
            t1 = (hh + sigma1(e) + ch(e, f, g) + K[i] + w[i]) & 0xFFFFFFFF
            t2 = (sigma0(a) + maj(a, b, c)) & 0xFFFFFFFF
            hh = g; g = f; f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c; c = b; b = a
            a = (t1 + t2) & 0xFFFFFFFF
        return [
            (state[0] + a) & 0xFFFFFFFF,
            (state[1] + b) & 0xFFFFFFFF,
            (state[2] + c) & 0xFFFFFFFF,
            (state[3] + d) & 0xFFFFFFFF,
            (state[4] + e) & 0xFFFFFFFF,
            (state[5] + f) & 0xFFFFFFFF,
            (state[6] + g) & 0xFFFFFFFF,
            (state[7] + hh) & 0xFFFFFFFF,
        ]

    # The total length processed so far = orig_len + padding
    padding = sha256_padding(orig_len)
    processed_len = orig_len + len(padding)

    # Process extension
    ext_padded = extension + sha256_padding(processed_len + len(extension))
    assert len(ext_padded) % 64 == 0

    state = h[:]
    for i in range(0, len(ext_padded), 64):
        state = sha256_block(ext_padded[i:i+64], state)

    return ''.join(f'{x:08x}' for x in state)

def attack(host, port=9999):
    base_url = f"http://{host}:{port}"

    # Step 1: Get a valid signed sample
    print("[*] Getting sample signed request...")
    r = requests.get(f"{base_url}/api/sample")
    data = r.json()
    original_msg = data['raw_message'].encode('latin-1')
    original_sig = data['sig']
    print(f"[*] Message: {data['raw_message']}")
    print(f"[*] Sig: {original_sig}")

    extension = b"&admin=true"

    # Step 2: Try secret lengths 8-16
    for secret_len in range(8, 17):
        orig_len = secret_len + len(original_msg)
        padding = sha256_padding(orig_len)

        # Forged message (what the server will hash after prepending secret)
        forged_msg = original_msg + padding + extension
        forged_sig = sha256_extend(original_sig, orig_len, extension)

        # Encode forged message as base64
        params_b64 = base64.b64encode(forged_msg).decode()

        # Try the admin endpoint
        r2 = requests.get(
            f"{base_url}/api/admin",
            params={'params': params_b64, 'sig': forged_sig}
        )

        if r2.status_code == 200 and 'flag' in r2.json():
            print(f"[+] SUCCESS with secret_len={secret_len}!")
            print(f"[+] FLAG: {r2.json()['flag']}")
            return
        elif r2.status_code == 403 and 'Admin access' in r2.json().get('error', ''):
            print(f"[+] Signature accepted with secret_len={secret_len}, but admin=true not found in params")
        else:
            print(f"[-] secret_len={secret_len}: {r2.json()}")

    print("[-] Attack failed for all secret lengths 8-16")

if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '172.30.99.22'
    attack(host)
```

## Alternative: Using hashpumpy

```bash
pip install hashpumpy
```

```python
import hashpumpy, base64, requests

# hashpumpy.hashpump(sig, original_data, data_to_add, key_length)
for klen in range(8, 17):
    new_sig, new_data = hashpumpy.hashpump(original_sig, original_msg, b'&admin=true', klen)
    params_b64 = base64.b64encode(new_data).decode()
    r = requests.get(f"http://HOST/api/admin", params={'params': params_b64, 'sig': new_sig})
    if 'flag' in r.json():
        print(r.json()['flag'])
        break
```

## Prevention

- Use HMAC (keyed hash) instead of `SHA256(secret || msg)`: `HMAC-SHA256(secret, msg)`
- HMAC is immune to length extension attacks by design
- Never use plain SHA-2 family (SHA-256, SHA-512) for MACs
