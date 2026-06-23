# Solution: Bit Surgeon — AES-CBC Bit Flipping Attack

## Vulnerability

AES-CBC decryption: `P[i] = Block_Decrypt(C[i]) XOR C[i-1]`

The plaintext has a predictable structure:
```
Block 0 (bytes  0-15): "user=hacker&role"
Block 1 (bytes 16-31): "=guest&ts=123456"
Block 2 (bytes 32-47): "7890" + padding
```

The string `"guest"` occupies bytes 17-21, which is in **block 1**. Decryption of block 1 is:
```
P[1] = Block_Decrypt(C[1]) XOR C[0]
```

We cannot change `Block_Decrypt(C[1])`, but we CAN change `C[0]` (the first ciphertext block, which we control). XORing `C[0][1:6]` with `xor_mask` will flip the corresponding bytes in `P[1][1:6]`.

## Computing the XOR Mask

```
target   = b'admin'
original = b'guest'
# P[1][1:6] = '=guest'... wait, let's be precise:
# Block1 decrypts to '=guest&ts=NNNNNN'
# So P[1][0] = '=', P[1][1] = 'g', P[1][2] = 'u', P[1][3] = 'e', P[1][4] = 's', P[1][5] = 't'
# We want P[1][1:6] = 'admin'
xor_mask = bytes(a ^ b for a, b in zip(b'guest', b'admin'))
# = bytes([ord('g')^ord('a'), ord('u')^ord('d'), ord('e')^ord('m'), ord('s')^ord('i'), ord('t')^ord('n')])
# = b'\x06\x11\x08\x1a\x1b'
```

XOR `C[0][1:6]` with this mask. The corrupted block 0 will produce garbled decryption for block 0's plaintext, but block 1 will decrypt to `"=admin&ts=..."`.

## Full Attack Script

```python
#!/usr/bin/env python3
"""
AES-CBC Bit Flipping Attack
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

def attack(host, port=9999):
    print(f"[*] Connecting to {host}:{port}...")
    s, f = connect(host, port)

    # Read banner
    for _ in range(4):
        line = recv_line(f)
        print(f"[banner] {line}")

    # Login to get a token
    username = "hacker"
    print(f"[*] Logging in as '{username}'...")
    send(s, f"LOGIN {username}")

    token_hex = None
    for _ in range(6):
        line = recv_line(f)
        print(f"  {line}")
        if line.startswith('TOKEN='):
            token_hex = line.split('=', 1)[1]
    recv_line(f)  # prompt

    token = bytearray(bytes.fromhex(token_hex))
    print(f"[*] Got token ({len(token)} bytes): {token_hex[:32]}...")

    # Token layout: IV(16) + CT_block0(16) + CT_block1(16) + CT_block2(16)
    # Plaintext after decryption:
    #   Block0: "user=hacker&role"  (username is "hacker" = 6 chars)
    #   Block1: "=guest&ts=NNNNNN"
    #   Block2: "NNNN" + PKCS7 padding
    #
    # "guest" is at P[1][1:6] (bytes 17-21 of plaintext)
    # To flip: XOR C[0][1:6] (bytes 17-21 of token, i.e. token[17:22])
    #
    # Wait: token = IV(16) + C[0](16) + C[1](16) + ...
    # C[0] is token[16:32]
    # "guest" in block1 means bytes 1-5 of block1's plaintext
    # P[1] = Decrypt(C[1]) XOR C[0]
    # P[1][1:6] = Decrypt(C[1])[1:6] XOR C[0][1:6]
    # To change P[1][1:6] from 'guest' to 'admin':
    # New C[0][1:6] = old C[0][1:6] XOR 'guest' XOR 'admin'

    original = b'guest'
    target   = b'admin'
    xor_mask = bytes(a ^ b for a, b in zip(original, target))
    print(f"[*] XOR mask: {xor_mask.hex()}")

    # C[0] starts at offset 16 in the token (after IV)
    # C[0][1:6] = token[17:22]
    for i, m in enumerate(xor_mask):
        token[17 + i] ^= m

    flipped_hex = token.hex()
    print(f"[*] Flipped token: {flipped_hex[:32]}...")

    # Verify the flip worked
    send(s, f"VERIFY {flipped_hex}")
    for _ in range(3):
        line = recv_line(f)
        print(f"  VERIFY: {line}")
        if 'admin' in line.lower():
            print("[+] role=admin confirmed!")
        elif 'guest' in line.lower():
            print("[-] Still guest — check offset calculation")
    recv_line(f)  # prompt

    # Get the flag
    send(s, f"FLAG {flipped_hex}")
    for _ in range(2):
        line = recv_line(f)
        print(f"  FLAG: {line}")
        if 'FLAG' in line and 'HL4{' in line:
            print(f"[+] SUCCESS! {line}")
    
    s.close()

if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '172.30.99.21'
    attack(host)
```

## Why the Garbling Doesn't Matter

Flipping bytes in `C[0]` corrupts the decryption of **block 0** only. Block 0's plaintext becomes garbage (it will look like `"user=XJ\x07\x1a\x15\x02hacker&role"` instead of `"user=hacker&role"`). But the server only checks for `role=admin` anywhere in the decrypted text — and block 1 decrypts correctly as `"=admin&ts=..."`. So the check passes.

## Prevention

- Use AES-GCM (authenticated encryption) — any bit flip is detected
- Include a MAC over the ciphertext and reject modified tokens
- Never check plaintext fields parsed from CBC-encrypted data without authentication
