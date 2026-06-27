# Solution: DotNetObf (rev-dotnetobf)

## Overview

The binary is a compiled Python 3.11 `.pyc` file. The "DotNet" name is a
red herring. Players must decompile the bytecode and reverse the obfuscated
variable names to extract a 14-character key.

## Reversing Steps

### 1. Identify the file

```bash
file checker.pyc
# Python bytecode, version 3.11 (magic 3495)
```

### 2. Inspect with `dis` (quick method)

```python
import dis, marshal, struct

with open('checker.pyc', 'rb') as f:
    f.read(16)               # skip magic (4) + flags (4) + mtime (4) + size (4)
    code = marshal.loads(f.read())

dis.dis(code)
# Inspect all co_consts and nested code objects
```

### 3. Decompile with uncompyle6 / decompyle3 / pycdc

```bash
pip install uncompyle6
uncompyle6 checker.pyc
```

Decompiled output (approximate):
```python
import sys as _s

__0 = (0x44, 0x4F, 0x54, 0x4E, 0x45, 0x54, 0x5F, 0x4F,
       0x42, 0x46, 0x5F, 0x4B, 0x45, 0x59)

__1 = bytes(__0)  # b'DOTNET_OBF_KEY'

def __2(__3):
    if len(__3) != 14:
        return False
    __4 = __3.encode() if isinstance(__3, str) else __3
    return __4 == __1
```

### 4. Recover the key

The tuple `__0` contains ASCII codes: convert directly:
```python
key = bytes([0x44,0x4F,0x54,0x4E,0x45,0x54,0x5F,0x4F,
             0x42,0x46,0x5F,0x4B,0x45,0x59]).decode()
print(key)  # DOTNET_OBF_KEY
```

Alternatively, scan `co_consts` in the bytecode for a bytes or tuple constant
of length 14 and convert each element to chr().

### 5. Alternative: strings approach

```bash
strings checker.pyc | grep -E '^[A-Z_]{14}$'
# Won't work because the key is stored as individual integers, not a string literal.
# Must decompile or parse co_consts.
```

## Submit

```bash
curl -s -X POST http://<host>:6005/check \
     -H 'Content-Type: application/json' \
     -d '{"answer":"DOTNET_OBF_KEY"}'
```

## Answer

`DOTNET_OBF_KEY`
