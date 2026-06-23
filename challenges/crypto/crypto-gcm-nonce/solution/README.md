# Solution: GCM Groundhog Day — AES-GCM Nonce Reuse

## Vulnerability

AES-GCM uses a keystream derived from the key and nonce: `keystream = E(key, nonce || counter)`. The ciphertext is `CT = PT XOR keystream`. When the **same nonce** is reused with the same key, the **same keystream** is generated.

If we know `PT1` and `CT1 = PT1 XOR keystream`, we can recover the keystream: `keystream = CT1 XOR PT1`. Then decrypt `CT2`: `PT2 = CT2 XOR keystream`.

## Theory: GCM Nonce Reuse (Two-Time Pad)

```
keystream = AES_CTR(KEY, NONCE, counter=0)
CT1 = PT1 XOR keystream
CT2 = PT2 XOR keystream  (same keystream!)

keystream = CT1 XOR PT1  (known)
PT2 = CT2 XOR keystream = CT2 XOR CT1 XOR PT1
```

This reduces AES-GCM to a simple XOR with a known keystream — exactly the two-time pad problem.

## Attack Steps

1. GET_CIPHERTEXTS: get `(NONCE, CT1, TAG1, CT2, TAG2)`
2. GET_KNOWN_PLAINTEXT: get `PT1`
3. Recover keystream: `KS = CT1 XOR PT1`
4. Decrypt flag: `PT2 = CT2 XOR KS[:len(CT2)]`
5. SUBMIT the recovered flag

## Full Attack Script

```python
#!/usr/bin/env python3
"""
AES-GCM Nonce Reuse Attack — Two-Time Pad
"""
import sys
import socket

def connect(host, port):
    s = socket.socket()
    s.connect((host, port))
    f = s.makefile('rb')
    return s, f

def recv_line(f):
    return f.readline().decode().strip()

def send(s, msg):
    s.sendall((msg + '\n').encode())

def xor_bytes(a, b):
    """XOR two byte strings (truncated to shorter length)"""
    return bytes(x ^ y for x, y in zip(a, b))

def attack(host, port=9999):
    print(f"[*] Connecting to {host}:{port}...")
    s, f = connect(host, port)

    # Read banner
    for _ in range(3):
        line = recv_line(f)
        print(f"[banner] {line}")

    # Step 1: Get ciphertexts
    print("[*] Getting ciphertexts...")
    send(s, "GET_CIPHERTEXTS")
    ciphertexts = {}
    for _ in range(6):
        line = recv_line(f)
        if line.startswith('>'):
            break
        if '=' in line:
            k, v = line.split('=', 1)
            ciphertexts[k] = v
    
    nonce = bytes.fromhex(ciphertexts['NONCE'])
    ct1 = bytes.fromhex(ciphertexts['CT1'])
    ct2 = bytes.fromhex(ciphertexts['CT2'])
    print(f"[*] NONCE: {nonce.hex()}")
    print(f"[*] CT1 length: {len(ct1)} bytes")
    print(f"[*] CT2 length: {len(ct2)} bytes")

    # Step 2: Get known plaintext for CT1
    print("[*] Getting known plaintext...")
    send(s, "GET_KNOWN_PLAINTEXT")
    pt1 = None
    for _ in range(3):
        line = recv_line(f)
        if line.startswith('PT1='):
            pt1 = bytes.fromhex(line.split('=', 1)[1])
        if line.startswith('>'):
            break

    if pt1 is None:
        print("[-] Could not get PT1")
        s.close()
        return

    print(f"[*] PT1: {pt1.decode(errors='replace')[:80]}...")
    print(f"[*] PT1 length: {len(pt1)} bytes")

    # Verify lengths match
    if len(pt1) != len(ct1):
        print(f"[-] Length mismatch: PT1={len(pt1)}, CT1={len(ct1)}")
        s.close()
        return

    # Step 3: Recover keystream
    print("[*] Recovering keystream...")
    keystream = xor_bytes(ct1, pt1)
    print(f"[*] Keystream (first 16 bytes): {keystream[:16].hex()}")

    # Step 4: Decrypt CT2 (the flag)
    print("[*] Decrypting CT2 (the flag)...")
    if len(ct2) > len(keystream):
        print(f"[-] CT2 ({len(ct2)}) longer than keystream ({len(keystream)})")
        print("[*] Requesting additional keystream via ENCRYPT...")
        # Encrypt a zero plaintext to get more keystream
        zero_pt = bytes(len(ct2))
        send(s, f"ENCRYPT {zero_pt.hex()}")
        for _ in range(3):
            line = recv_line(f)
            if line.startswith('CT='):
                extra_keystream = bytes.fromhex(line.split('=', 1)[1])
                # For the ENCRYPT oracle: ct_of_zeros = 0 XOR keystream = keystream
                keystream = extra_keystream
                break
            if line.startswith('>'):
                break

    pt2 = xor_bytes(ct2, keystream[:len(ct2)])
    
    try:
        flag = pt2.decode('utf-8')
        print(f"[+] Decrypted flag: {flag}")
    except Exception:
        print(f"[+] Decrypted (hex): {pt2.hex()}")
        print(f"[+] Decrypted (raw): {pt2}")
        flag = pt2.decode('latin-1')

    # Step 5: Submit the flag
    print(f"[*] Submitting: {flag.strip()}")
    send(s, f"SUBMIT {flag.strip()}")
    resp = recv_line(f)
    print(f"[+] Server: {resp}")

    if 'CORRECT' in resp:
        print("[+] SUCCESS!")

    s.close()

if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '172.30.99.22'
    attack(host)
```

## Alternative: Use the ENCRYPT Oracle

If `CT2` is longer than `CT1` (i.e., the flag is longer than the known plaintext), use the ENCRYPT command:
- Send an all-zero plaintext of the required length
- The resulting ciphertext IS the keystream (since `0 XOR KS = KS`)
- XOR CT2 with this extended keystream

## Beyond Confidentiality: Authentication Forgery

GCM nonce reuse also breaks authentication. With two ciphertexts under the same nonce, you can recover the GHASH authentication key `H` and forge arbitrary authenticated ciphertexts. This is even more severe than the confidentiality break.

## Prevention

- **Never** reuse a nonce with the same key in GCM
- Use random 96-bit nonces (collisions negligible for < 2^32 messages)
- Or use AES-SIV (nonce-misuse resistant) for extra safety
- Modern protocols use sequence numbers or random nonces from CSPRNGs
