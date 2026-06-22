# crypto-rsalsb — Solución: RSA LSB Oracle

## Vulnerabilidad
RSA-2048 LSB oracle. El servidor descifra cualquier ciphertext pero solo
revela el bit menos significativo (paridad) del plaintext resultante.

## Ataque: Binary Search via LSB Oracle

### Principio matemático
Dado:
- n, e, ct = flag_pt^e mod n (conocidos)
- f(c) = (c^d mod n) & 1  (el oráculo)

Si multiplicamos el ciphertext por 2^e mod n:
  c' = (2^e mod n) * ct mod n
  decrypt(c') = 2 * flag_pt mod n

El LSB de (2 * flag_pt mod n) nos dice:
- Si flag_pt < n/2: 2*flag_pt < n → LSB=0 (número par)
- Si flag_pt >= n/2: 2*flag_pt >= n → 2*flag_pt - n es impar → LSB=1

Esto divide [0, n) en dos mitades. Repetimos 2048 veces para converger.

## Exploit

```python
import json
import socket

def solve():
    HOST = "172.30.X.34"
    PORT = 9999

    s = socket.socket()
    s.connect((HOST, PORT))
    f = s.makefile("rw")

    # Leer banner hasta línea vacía
    data = {}
    for line in f:
        line = line.strip()
        if line.startswith("PUBKEY "):
            data = json.loads(line[7:])
            break

    n = int(data["n"], 16)
    e = data["e"]
    ct = int(data["ct"], 16)

    # Consumir resto del banner
    for line in f:
        if line.strip() == "":
            break

    def oracle(c_int):
        f.write(f"ORACLE {hex(c_int)}\n")
        f.flush()
        return int(f.readline().strip())

    # Binary search
    lo = 0
    hi = n
    factor = pow(2, e, n)  # 2^e mod n
    c = ct

    for i in range(2048):
        c = (c * factor) % n
        lsb = oracle(c)
        mid = (lo + hi) // 2
        if lsb == 0:
            hi = mid
        else:
            lo = mid
        if i % 100 == 0:
            print(f"  [{i}/2048] intervalo: [{lo.bit_length()} bits]")

    # El plaintext está en [lo, hi]
    from Crypto.Util.number import long_to_bytes
    pt_int = (lo + hi) // 2
    pt = long_to_bytes(pt_int)
    print(f"Plaintext recuperado: {pt}")

    # Enviar respuesta
    f.write(f"ANSWER {pt.hex()}\n")
    f.flush()
    print(f.readline().strip())

if __name__ == "__main__":
    solve()
```

## Notas
- 2048 queries son suficientes para RSA-2048.
- El límite es 4096 queries: hay margen para errores.
- El flag está PKCS#1 v1.5 padded internamente al cifrarse, así que el
  plaintext recuperado puede incluir bytes de padding. Buscar el FLAG dentro.
- Tiempo estimado: ~30 segundos con buena conexión TCP.
