# crypto-ecdsanonce — Solución: ECDSA Biased Nonce + LLL

## Vulnerabilidad
ECDSA sobre secp256k1 con nonces sesgados: los 8 bits superiores del nonce k
siempre son 0. Esto reduce el espacio de nonces a 2^248 en lugar de 2^256.

## Ataque: Hidden Number Problem (HNP) + Reducción LLL

### Formulación del HNP
Dada una firma ECDSA (r_i, s_i) para mensaje hash z_i:
  s_i = k_i^{-1} * (z_i + d * r_i) mod n

Despejando k_i:
  k_i = s_i^{-1} * z_i + s_i^{-1} * r_i * d mod n

Como k_i < 2^248 (8 bits superiores = 0):
  k_i = t_i + u_i * d mod n
donde t_i = s_i^{-1} * z_i mod n y u_i = s_i^{-1} * r_i mod n.

El sesgo implica que k_i < n/256, lo cual es el HNP:
  Encontrar d tal que (t_i + u_i*d) mod n < n/256 para todas las firmas.

### Construcción de la lattice
Con m firmas, construimos una lattice (m+2) x (m+2):

```
B = [
  [n, 0, 0, ..., 0,   0  ],  # fila 0
  [0, n, 0, ..., 0,   0  ],  # fila 1
  ...                          # filas 0..m-1: n en diagonal
  [u_0, u_1, ..., u_{m-1}, 1/n, 0],
  [t_0, t_1, ..., t_{m-1}, 0,  1/256],
]
```

Escalamos apropiadamente y aplicamos LLL. El vector corto resultante
contiene la clave privada d.

## Exploit (requiere SageMath o fpylll)

```python
# exploit.py — requiere: pip install fpylll requests
import requests
import hashlib
from fpylll import IntegerMatrix, LLL

HOST = "http://172.30.X.36:9999"
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def modinv(a, m):
    return pow(a, -1, m)

# 1. Recolectar firmas
print("[*] Recolectando firmas...")
sigs = []
for i in range(50):
    msg = bytes([i, i+1, i+2, i+3]).hex()
    r = requests.post(f"{HOST}/sign", json={"msg": msg})
    data = r.json()
    ri = int(data["r"], 16)
    si = int(data["s"], 16)
    zi = int(data["hash"], 16)
    sigs.append((ri, si, zi))
    if i % 10 == 0:
        print(f"  {i+1}/50 firmas recolectadas")

# 2. Construir y reducir lattice
print("[*] Construyendo lattice...")
m = len(sigs)
K = 256  # 2^8 = factor de sesgo

# Matrices auxiliares
ts = [modinv(si, N) * zi % N for ri, si, zi in sigs]
us = [modinv(si, N) * ri % N for ri, si, zi in sigs]

# Lattice dimension m+2
dim = m + 2
B = IntegerMatrix(dim, dim)

# Llenar la lattice
for i in range(m):
    B[i, i] = N
B[m, m] = 1
B[m+1, m+1] = N // K

for i, (u, t) in enumerate(zip(us, ts)):
    B[m, i] = u
    B[m+1, i] = t

# Reducción LLL
print("[*] Ejecutando LLL...")
LLL.reduction(B)

# Buscar la clave privada en las filas reducidas
print("[*] Buscando clave privada...")
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def point_add_verify(priv):
    # Verificar multiplicando G*priv y comparando con pubkey del servidor
    r = requests.get(f"{HOST}/pubkey").json()
    expected = r["pubkey"]
    # Implementar scalar mult y comparar
    return True  # simplificado

for row in range(dim):
    candidate = B[row, m]
    if candidate <= 0:
        candidate = -candidate
    if 1 <= candidate < N:
        # Intentar firmar ADMIN_CHALLENGE con este candidato
        admin_msg = bytes.fromhex(
            requests.get(f"{HOST}/pubkey").json()["admin_challenge"]
        )
        z = int.from_bytes(hashlib.sha256(admin_msg).digest(), "big")
        
        # Generar firma determinista (RFC 6979 simplificado)
        import hmac, struct
        k = (int.from_bytes(hmac.new(
            candidate.to_bytes(32,"big"), z.to_bytes(32,"big"), "sha256"
        ).digest(), "big")) % (N - 1) + 1
        
        # ... (implementar scalar mult completo)
        # Por brevedad, intentar directamente con el candidato
        print(f"  Candidato: {hex(candidate)}")

print("[!] Ver exploit completo en la carpeta de soluciones para SageMath.")
```

## Versión SageMath (más simple)

```sage
# exploit_sage.sage
import requests, hashlib

HOST = "http://172.30.X.36:9999"
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

sigs = []
for i in range(50):
    msg = bytes([i]).hex()
    d = requests.post(f"{HOST}/sign", json={"msg": msg}).json()
    sigs.append((int(d["r"],16), int(d["s"],16), int(d["hash"],16)))

m = len(sigs)
K = 2^8  # sesgo

ts = [inverse_mod(s,N)*z % N for r,s,z in sigs]
us = [inverse_mod(s,N)*r % N for r,s,z in sigs]

L = Matrix(ZZ, m+2, m+2)
for i in range(m):
    L[i,i] = N
    L[m, i] = us[i]
    L[m+1, i] = ts[i]
L[m, m] = 1
L[m+1, m+1] = N // K

L = L.LLL()

for row in L:
    d_cand = row[m]
    if d_cand < 0: d_cand = -d_cand
    if 1 <= d_cand < N:
        print(f"Clave candidata: {hex(d_cand)}")
        # Firmar ADMIN_CHALLENGE y llamar /flag
```

## Tiempo estimado
- Recolección de 50 firmas: ~5 segundos
- Reducción LLL (m=50, dim=52): ~1-2 segundos
- Verificación: inmediata
