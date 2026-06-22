# crypto-lengthext — Solución: MD5 Length Extension Attack

## Vulnerabilidad
MAC = MD5(secret || message) es vulnerable a ataques de extensión de longitud.
MD5 usa la construcción Merkle-Damgard: el estado interno al terminar de hashear
un mensaje puede reutilizarse para continuar el hashing con datos adicionales,
SIN conocer el secreto.

## Exploit: MD5 Length Extension Manual

### Principio
MD5 de (secret || msg) produce un estado interno (a,b,c,d) de 128 bits.
Dado el output MD5 = hex(a||b||c||d), podemos restaurar ese estado y
continuar el algoritmo MD5 para hashear datos adicionales.

El mensaje efectivo que se autentica se convierte en:
  secret || "role=user" || MD5_padding || "&role=admin"

Y el MAC forjado es:
  MD5_extended = MD5_continue_from_state(original_mac, "&role=admin")

### Implementación

```python
import struct
import math
import requests
import urllib.parse

HOST = "http://172.30.X.37:9999"

def md5_padding(msg_len):
    """Padding MD5 para un mensaje de msg_len bytes."""
    bit_len = msg_len * 8
    pad_len = (55 - msg_len) % 64
    return b'\x80' + b'\x00' * pad_len + struct.pack('<Q', bit_len)

def md5_compress(block, state):
    """Un bloque de compresión MD5."""
    T = [int(2**32 * abs(math.sin(i + 1))) & 0xFFFFFFFF for i in range(64)]
    S = [
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
    ]
    A, B, C, D = state
    M = struct.unpack('<16I', block)
    for i in range(64):
        if i < 16:   F, g = (B & C) | (~B & D), i
        elif i < 32: F, g = (D & B) | (~D & C), (5*i+1)%16
        elif i < 48: F, g = B ^ C ^ D, (3*i+5)%16
        else:        F, g = C ^ (B | ~D), (7*i)%16
        F = (F + A + T[i] + M[g]) & 0xFFFFFFFF
        A, D, C = D, C, B
        B = (B + ((F << S[i]) | (F >> (32-S[i]))) & 0xFFFFFFFF) & 0xFFFFFFFF
    return tuple((x+y)&0xFFFFFFFF for x,y in zip(state, (A,B,C,D)))

def md5_length_extend(mac_hex, original_total_len, extension):
    """Extiende un MAC MD5 sin conocer el secreto."""
    state = struct.unpack('<4I', bytes.fromhex(mac_hex))
    
    # La longitud procesada hasta ahora incluye secret||msg||padding
    processed = original_total_len + len(md5_padding(original_total_len))
    
    # Calcular el padding para la extensión
    total_new = processed + len(extension)
    bit_len = total_new * 8
    pad_len = (55 - total_new) % 64
    ext_with_pad = extension + b'\x80' + b'\x00'*pad_len + struct.pack('<Q', bit_len)
    
    for i in range(0, len(ext_with_pad), 64):
        state = md5_compress(ext_with_pad[i:i+64], state)
    
    return struct.pack('<4I', *state).hex()

# 1. Obtener info
info = requests.get(f"{HOST}/info").json()
secret_len = info["secret_length"]  # 16

# 2. Obtener mensaje y MAC originales
msg_data = requests.get(f"{HOST}/message").json()
original_msg = msg_data["msg"]       # "role=user"
original_mac = msg_data["mac"]       # hex MD5

# 3. Calcular la extensión
extension = b"&role=admin"

# 4. Calcular el padding que MD5 insertó
total_original = secret_len + len(original_msg.encode())
glue_padding = md5_padding(total_original)

# 5. Forjar el MAC
forged_mac = md5_length_extend(
    original_mac,
    total_original,
    extension
)

print(f"Original msg: {original_msg}")
print(f"Original MAC: {original_mac}")
print(f"Glue padding: {glue_padding.hex()}")
print(f"Extension: {extension}")
print(f"Forged MAC: {forged_mac}")

# 6. Construir la URL del endpoint /admin
# El parámetro ext debe ser la extensión en texto
ext_str = urllib.parse.quote(extension.decode())
url = (f"{HOST}/admin"
       f"?msg={urllib.parse.quote(original_msg)}"
       f"&mac={original_mac}"
       f"&ext={ext_str}"
       f"&newmac={forged_mac}")

response = requests.get(url)
print(f"\nRespuesta: {response.json()}")
```

## Herramientas alternativas
- `hash_extender` (C): `./hash_extender -d "role=user" -s 16 -a "&role=admin" --secret-length=16 -f md5`
- `hashpump` (Python): `hashpump -s "ORIGINAL_MAC" -d "role=user" -a "&role=admin" -k 16`
- `hlextend` (Python): `pip install hlextend`

## Notas
- El padding MD5 incluye la longitud del mensaje EN BITS en little-endian.
- La longitud que cuenta es la del secreto (16) + mensaje original (9) = 25 bytes.
- El MAC forjado autentica: secret || "role=user" || padding || "&role=admin".
- El servidor verifica que "role=admin" esté en el mensaje final extendido.
