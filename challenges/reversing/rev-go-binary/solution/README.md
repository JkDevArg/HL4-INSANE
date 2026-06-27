# Solution: Go License Kracker (rev-gobinary)

## Overview

A stripped Go binary (`-ldflags="-s -w" -trimpath`) validates a 17-character
license key using a rotating XOR cipher with magic constant `0xDEADBEEF`.

## Reversing Steps

### 1. Initial recon

```bash
file go_checker       # ELF 64-bit, stripped
strings go_checker    # reveals "VALID", "INVALID", "Usage: ./go_checker"
```

### 2. Load in Ghidra / Binary Ninja

Go binaries retain function names in the pclntab (runtime symbol table) even
when stripped with `-s -w`. Use the Go loader plugin or manually find
`runtime.pclntab` to recover function names.

Key functions to locate:
- `main.check` — the validation logic
- `main.main` — entry point, calls `check`

### 3. Analyse `main.check`

Pseudo-C:
```c
bool check(string input) {
    if (len(input) != 17) return false;
    for (int i = 0; i < 17; i++) {
        if (input[i] ^ magic[i%4] != expected[i]) return false;
    }
    return true;
}
```

### 4. Extract constants

From the data section (global variables `main.magic` and `main.expected`):

```
magic    = { 0xDE, 0xAD, 0xBE, 0xEF }
expected = { 0x96,0xEC,0xFD,0xA4, 0x92,0x99,0xFC,0xBC,
             0x81,0xEA,0x8E,0xB0, 0x9D,0xFF,0xFF,0xAC, 0x95 }
```

### 5. Recover the license key

`key[i] = expected[i] XOR magic[i % 4]`

```python
magic    = [0xDE,0xAD,0xBE,0xEF]
expected = [0x96,0xEC,0xFD,0xA4,0x92,0x99,0xFC,0xBC,
            0x81,0xEA,0x8E,0xB0,0x9D,0xFF,0xFF,0xAC,0x95]
key = ''.join(chr(e ^ magic[i%4]) for i,e in enumerate(expected))
print(key)  # HACKL4BS_G0_CRACK
```

## Submit

```bash
curl -s -X POST http://<host>:6002/check \
     -H 'Content-Type: application/json' \
     -d '{"answer":"HACKL4BS_G0_CRACK"}'
```

## Answer

`HACKL4BS_G0_CRACK`
