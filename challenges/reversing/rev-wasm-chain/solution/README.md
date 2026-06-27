# Solution: WASMcrack (rev-wasmcrack)

## Overview

A Rust binary (stripped, opt-level 3) named `wasmcrack` — the name is a red
herring. It is a standard ELF x86-64, not a WASM module. The password check
applies a 3-step byte transform and compares to a stored 12-byte hash.

## Reversing Steps

### 1. Initial recon

```bash
file wasmcrack          # ELF 64-bit LSB pie executable, stripped
strings wasmcrack       # reveals "CORRECT", "WRONG", usage strings
./wasmcrack test        # WRONG
```

### 2. Disassemble in Ghidra / Binary Ninja

Look for the string "CORRECT" cross-reference. The validation function
(`check_password` / unnamed in stripped binary) will be nearby.

The critical inner loop compares each transformed input byte against
the 12-byte constant array.

### 3. Identify the hash function

`hash_byte(b, i)`:
1. `rotated = b.rotate_left(3)`  — circular left shift 3 bits in u8
2. `xored   = rotated ^ 0x5A`
3. `result  = xored.wrapping_add(i)` — add index with u8 wrap

### 4. Extract the stored hash

From the binary (`.rodata` or inline in the function):
```
HASH = [0xC8, 0xC4, 0xEA, 0xA3, 0xE4, 0x00, 0xC6, 0x37,
        0xA8, 0xE1, 0xEA, 0x83]
```

### 5. Invert the hash to recover the password

```python
def invert_hash(h, i):
    # reverse: xored = h - i (mod 256)
    xored   = (h - i) & 0xFF
    # reverse XOR: rotated = xored ^ 0x5A
    rotated = xored ^ 0x5A
    # reverse rotate_left(3) = rotate_right(3)
    b = ((rotated >> 3) | (rotated << 5)) & 0xFF
    return b

HASH = [0xC8,0xC4,0xEA,0xA3,0xE4,0x00,0xC6,0x37,0xA8,0xE1,0xEA,0x83]
password = ''.join(chr(invert_hash(h, i)) for i, h in enumerate(HASH))
print(password)  # R3V_W4SM_PWD
```

## Submit

```bash
curl -s -X POST http://<host>:6003/check \
     -H 'Content-Type: application/json' \
     -d '{"answer":"R3V_W4SM_PWD"}'
```

## Answer

`R3V_W4SM_PWD`
