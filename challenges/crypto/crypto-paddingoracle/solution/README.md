# crypto-paddingoracle — Solución: Noisy CBC Padding Oracle

## Vulnerabilidad
AES-256-CBC padding oracle con 5% de tasa de error. El servidor responde
VALID/INVALID al comprobar el padding PKCS#7, pero miente en 1 de cada 20
consultas. Requiere análisis estadístico (voto mayoritario) para operar.

## Ataque: CBC Padding Oracle con Voto Mayoritario

### Fundamento del CBC Padding Oracle estándar
Para descifrar el byte i del bloque B_j, manipulamos el bloque previo B_{j-1}:
  - Ponemos los últimos k bytes de B_{j-1} a valores conocidos que produzcan padding \x0k
  - Iteramos el byte i buscando que el oráculo diga VALID
  - El byte correcto satisface: modified[i] XOR decrypt(B_j)[i] = \x0k
  - Por lo tanto: decrypt(B_j)[i] = modified[i] XOR \x0k
  - Y el plaintext: P[i] = decrypt(B_j)[i] XOR B_{j-1}[i]

### Manejo del ruido
Para cada candidato de byte, consultamos el oráculo N veces y usamos mayoría:
```python
SAMPLES = 7  # consultas por candidato

def noisy_check(blob):
    votes = sum(query(blob) for _ in range(SAMPLES))
    return votes > SAMPLES // 2  # mayoría simple
```

Con 5% de error y 7 muestras, la probabilidad de error por decisión es:
P(mayoría incorrecta) = sum(C(7,k) * 0.05^k * 0.95^(7-k), k=4..7) ≈ 0.001%

## Exploit

```python
import socket

HOST = "172.30.X.35"
PORT = 9999
BLOCK = 16
SAMPLES = 9  # votos por consulta para reducir error

def solve():
    s = socket.socket()
    s.connect((HOST, PORT))
    f = s.makefile("rw")

    token_hex = ""
    for line in f:
        line = line.strip()
        if line.startswith("TOKEN "):
            token_hex = line[6:]
            break
    for line in f:
        if line.strip() == "":
            break

    token = bytes.fromhex(token_hex)
    iv = token[:BLOCK]
    ct = token[BLOCK:]

    def query(blob):
        f.write(f"VERIFY {blob.hex()}\n")
        f.flush()
        return f.readline().strip() == "VALID"

    def noisy_check(blob):
        votes = sum(1 for _ in range(SAMPLES) if query(blob))
        return votes > SAMPLES // 2

    # Descifrar bloque por bloque
    plaintext = b""
    blocks = [ct[i:i+BLOCK] for i in range(0, len(ct), BLOCK)]

    for blk_idx, block in enumerate(blocks):
        prev = iv if blk_idx == 0 else blocks[blk_idx - 1]
        intermediate = bytearray(BLOCK)

        for byte_pos in range(BLOCK - 1, -1, -1):
            pad_val = BLOCK - byte_pos
            # Fijar los bytes ya conocidos
            prefix = bytearray(BLOCK)
            for k in range(byte_pos + 1, BLOCK):
                prefix[k] = intermediate[k] ^ pad_val

            # Buscar el byte correcto
            found = False
            for candidate in range(256):
                prefix[byte_pos] = candidate
                blob = bytes(prefix) + block
                if noisy_check(blob):
                    intermediate[byte_pos] = candidate ^ pad_val
                    found = True
                    break

            if not found:
                print(f"  [!] No encontrado byte {byte_pos} en bloque {blk_idx}")

        # XOR con bloque previo para obtener plaintext
        pt_block = bytes(intermediate[i] ^ prev[i] for i in range(BLOCK))
        plaintext += pt_block
        print(f"  Bloque {blk_idx}: {pt_block}")

    # Quitar padding PKCS#7
    pad = plaintext[-1]
    plaintext = plaintext[:-pad]
    print(f"\nFlag: {plaintext.decode(errors='replace')}")

if __name__ == "__main__":
    solve()
```

## Notas
- Con SAMPLES=9 la tasa de error por byte cae a ~0.001%.
- El exploit tarda ~10-15 minutos en recuperar la flag completa.
- Optimización: paralelizar las consultas al oráculo (asyncio).
- Para AES-256 la clave es más larga pero el ataque al padding es idéntico.
