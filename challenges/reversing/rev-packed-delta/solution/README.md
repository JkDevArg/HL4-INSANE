# Solution: PackedDelta (rev-packeddelta)

## Overview

A C binary that stores the correct password XOR-encrypted in a static byte
array. A 4-byte rolling key `{0xCA, 0xFE, 0xBA, 0xBE}` is used for
encryption. A checksum-based "anti-tamper" mechanism is present but is a decoy
— it XOR's and immediately un-XOR's the last key byte, so the net effect is zero.

## Reversing Steps

### 1. Initial recon

```bash
file delta_checker        # ELF 64-bit, not stripped (-O1)
strings delta_checker     # shows "CORRECT", "INCORRECT", "Usage:"
```

### 2. Open in Ghidra

Find `main()`. Identify:
- `xor_key[4]`   — static const: `{0xCA, 0xFE, 0xBA, 0xBE}`
- `encrypted_target[17]` — static const byte array
- `compute_checksum()` — reads first 512 bytes of the binary, sums them
- `decode_target()` — XOR decrypts `encrypted_target` using runtime key

### 3. Spot the decoy

In `decode_target()`:
```c
runtime_key[3] = xor_key[3] ^ checksum ^ checksum;  // = xor_key[3]
```
The checksum is XOR'd in and then XOR'd out — net effect zero. The key is
always exactly `{0xCA, 0xFE, 0xBA, 0xBE}`.

### 4. Extract the encrypted target

From `.rodata` / binary:
```
encrypted_target = {
    0x8E, 0xBB, 0xF6, 0xEA,
    0x8B, 0xA1, 0xEA, 0xFF,
    0x89, 0xB5, 0xE5, 0xF5,
    0x8F, 0xA7, 0xE5, 0x8A,
    0xF8
}
```

### 5. Decrypt the password

```python
key = [0xCA, 0xFE, 0xBA, 0xBE]
enc = [0x8E,0xBB,0xF6,0xEA,0x8B,0xA1,0xEA,0xFF,
       0x89,0xB5,0xE5,0xF5,0x8F,0xA7,0xE5,0x8A,0xF8]
password = ''.join(chr(e ^ key[i % 4]) for i, e in enumerate(enc))
print(password)  # DELTA_PACK_KEY_42
```

## Submit

```bash
curl -s -X POST http://<host>:6004/check \
     -H 'Content-Type: application/json' \
     -d '{"answer":"DELTA_PACK_KEY_42"}'
```

## Answer

`DELTA_PACK_KEY_42`
