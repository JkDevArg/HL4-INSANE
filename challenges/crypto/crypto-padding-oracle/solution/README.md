# Solution: Byte by Byte — AES-CBC Padding Oracle Attack

## Vulnerability

The DECRYPT command reveals whether AES-CBC decryption produces valid PKCS#7 padding. This single bit of information is enough to decrypt the entire ciphertext and forge arbitrary plaintexts.

## Theory: CBC Padding Oracle

AES-CBC decryption: `P[i] = Block_Decrypt(C[i]) XOR C[i-1]`

By manipulating `C[i-1]` and querying for valid padding, we can recover `Block_Decrypt(C[i])` one byte at a time. Then XOR with original `C[i-1]` gives us `P[i]`.

To forge, we XOR the intermediate values with our desired plaintext.

## Attack in 3 Phases

1. **Decrypt** the admin cookie byte by byte using the padding oracle
2. **Understand** the plaintext structure: `role=guest&user=hacker&admin=false`
3. **Forge** a new cookie where `admin=false` becomes `admin=true`

## Full Attack Script

```python
#!/usr/bin/env python3
"""
AES-CBC Padding Oracle Attack
"""
import sys
import socket
import time

def connect(host, port):
    s = socket.socket()
    s.connect((host, port))
    f = s.makefile('rb')
    return s, f

def recv_line(f):
    return f.readline().decode().strip()

def send(s, msg):
    s.sendall((msg + '\n').encode())

def padding_oracle(s, f, ciphertext_hex):
    """Returns True if padding is valid"""
    send(s, f"DECRYPT {ciphertext_hex}")
    resp = recv_line(f)
    # consume prompt
    try:
        prompt = recv_line(f)
    except:
        pass
    return resp == "VALID_PADDING"

def decrypt_block(s, f, prev_block, curr_block):
    """Decrypt one 16-byte block using the padding oracle"""
    intermediate = bytearray(16)
    
    for byte_pos in range(15, -1, -1):
        padding_val = 16 - byte_pos
        
        # Build crafted previous block
        crafted_prev = bytearray(16)
        # Set already-known bytes to produce correct padding
        for k in range(byte_pos + 1, 16):
            crafted_prev[k] = intermediate[k] ^ padding_val
        
        # Brute force the current byte
        found = False
        for guess in range(256):
            crafted_prev[byte_pos] = guess
            crafted = bytes(crafted_prev) + curr_block
            if padding_oracle(s, f, crafted.hex()):
                # Verify it's not a false positive (only for last byte)
                if byte_pos == 15:
                    # Double-check by modifying byte before
                    crafted_prev2 = bytearray(crafted_prev)
                    crafted_prev2[byte_pos - 1] ^= 1
                    crafted2 = bytes(crafted_prev2) + curr_block
                    if not padding_oracle(s, f, crafted2.hex()):
                        continue  # false positive
                intermediate[byte_pos] = guess ^ padding_val
                found = True
                print(f"  [*] Byte {byte_pos}: 0x{intermediate[byte_pos]:02x} ({chr(intermediate[byte_pos]) if 32 <= intermediate[byte_pos] < 127 else '?'})")
                break
        
        if not found:
            print(f"  [-] Failed to find byte {byte_pos}")
            intermediate[byte_pos] = 0
    
    # XOR with original prev_block to get plaintext
    plaintext = bytes(intermediate[i] ^ prev_block[i] for i in range(16))
    return plaintext, intermediate

def forge_block(desired_plaintext, intermediate):
    """Create a ciphertext block that decrypts to desired_plaintext"""
    assert len(desired_plaintext) == 16
    crafted = bytes(intermediate[i] ^ desired_plaintext[i] for i in range(16))
    return crafted

def attack(host, port=9999):
    print(f"[*] Connecting to {host}:{port}...")
    s, f = connect(host, port)

    # Read banner and get admin cookie
    cookie_hex = None
    for _ in range(5):
        line = recv_line(f)
        print(f"[banner] {line}")
        if line.startswith('ADMIN_COOKIE='):
            cookie_hex = line.split('=')[1]

    cookie = bytes.fromhex(cookie_hex)
    print(f"[*] Admin cookie ({len(cookie)} bytes): {cookie_hex[:32]}...")
    
    # Split into IV + blocks
    num_blocks = len(cookie) // 16
    blocks = [cookie[i*16:(i+1)*16] for i in range(num_blocks)]
    iv = blocks[0]
    ct_blocks = blocks[1:]
    
    print(f"[*] IV: {iv.hex()}")
    print(f"[*] {len(ct_blocks)} ciphertext blocks")

    # Phase 1: Decrypt all blocks
    print("\n[*] Phase 1: Decrypting ciphertext...")
    intermediates = []
    plaintexts = []
    
    prev = iv
    for i, block in enumerate(ct_blocks):
        print(f"\n[*] Decrypting block {i+1}/{len(ct_blocks)}...")
        pt, intermediate = decrypt_block(s, f, prev, block)
        plaintexts.append(pt)
        intermediates.append(intermediate)
        prev = block
        print(f"  Block {i+1}: {pt}")

    full_pt = b''.join(plaintexts)
    # Remove PKCS7 padding
    pad_len = full_pt[-1]
    if pad_len <= 16:
        full_pt = full_pt[:-pad_len]
    print(f"\n[+] Decrypted: {full_pt}")

    # Phase 2: Forge admin cookie
    print("\n[*] Phase 2: Forging admin cookie...")
    # Target: replace 'admin=false' with 'admin=true\x06\x06\x06\x06\x06\x06'
    # Original: "role=guest&user=hacker&admin=false"
    # We need to change the last block to contain 'admin=true' + padding
    
    original = full_pt.decode('latin-1')
    print(f"[*] Original plaintext: {original}")
    
    # Find 'admin=false' and replace with 'admin=true '
    target = original.replace('admin=false', 'admin=true\x00\x00')
    
    # Build desired plaintext with proper padding
    target_bytes = target.encode('latin-1')
    # Pad to block boundary
    pad_needed = 16 - (len(target_bytes) % 16)
    target_padded = target_bytes + bytes([pad_needed] * pad_needed)
    
    # Rebuild ciphertext with forged blocks
    forged_ct_blocks = []
    for i in range(len(ct_blocks)):
        desired_pt_block = target_padded[i*16:(i+1)*16]
        forged_prev = forge_block(desired_pt_block, intermediates[i])
        forged_ct_blocks.append(forged_prev)
    
    # The forged ciphertext: iv + forged_prev_blocks + last_real_block
    # Actually we need to forge all but the first block's "previous" to be the IV
    # Simpler approach: forge the IV to change the first block
    
    # Strategy: change only the last block's content
    # The last plaintext block is ct_blocks[-1] decrypted with intermediate[-1] XOR ct_blocks[-2]
    # To make last block = desired, craft ct_blocks[-2] (the new "prev" for last block)
    
    last_block_desired = target_padded[-16:]
    forged_prev_last = forge_block(last_block_desired, intermediates[-1])
    
    forged_cookie = iv
    for i in range(len(ct_blocks) - 2):
        forged_cookie += ct_blocks[i]
    forged_cookie += forged_prev_last + ct_blocks[-1]
    
    print(f"[*] Forged cookie: {forged_cookie.hex()[:32]}...")

    # Phase 3: Submit forged cookie
    print("\n[*] Phase 3: Submitting forged cookie...")
    send(s, f"GET_FLAG {forged_cookie.hex()}")
    resp = recv_line(f)
    print(f"[+] Server: {resp}")
    
    if 'FLAG' in resp:
        print(f"\n[+] SUCCESS!")
    
    s.close()

if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '172.30.99.21'
    attack(host)
```

## Notes

- The attack requires `O(256 * len)` oracle queries where len is the ciphertext length in bytes
- For a 48-byte ciphertext (3 blocks), that's at most ~12,288 queries
- No rate limit is implemented on DECRYPT, only GET_FLAG
- The forging technique works by manipulating the previous ciphertext block to control the XOR in CBC decryption

## Prevention

- Never return different error messages for padding vs decryption errors
- Use authenticated encryption (AES-GCM) instead of AES-CBC
- Use encrypt-then-MAC to detect tampering before decryption
