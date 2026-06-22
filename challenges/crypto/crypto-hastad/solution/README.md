# crypto-hastad — Solución: Ataque de Hastad sobre Broadcast RSA

## Vulnerabilidad
RSA con e=3 (exponente público pequeño) aplicado al mismo plaintext con 3
claves distintas. Esto permite recuperar el plaintext usando solo operaciones
modulares elementales: CRT + raíz cúbica entera.

## Principio Matemático
Tenemos:
  ct_1 = m^3 mod n_1
  ct_2 = m^3 mod n_2
  ct_3 = m^3 mod n_3

Si los n_i son coprimos entre sí (lo son, son primos distintos), el CRT garantiza
que existe un único X mod (n_1 * n_2 * n_3) tal que:
  X ≡ ct_1 (mod n_1)
  X ≡ ct_2 (mod n_2)
  X ≡ ct_3 (mod n_3)

Y ese X = m^3 (en los enteros, no módulo nada), porque m < n_i para todo i.
Entonces m = cbrt(X) es la raíz cúbica entera exacta.

## Exploit

```python
import requests
from Crypto.Util.number import long_to_bytes

HOST = "http://172.30.X.38:9999"

def extended_gcd(a, b):
    if a == 0: return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def crt(remainders, moduli):
    result, mod = remainders[0], moduli[0]
    for r, m in zip(remainders[1:], moduli[1:]):
        g, x, _ = extended_gcd(mod, m)
        lcm = mod * m // g
        result = (result + mod * ((r - result) // g * x % (m // g))) % lcm
        mod = lcm
    return result

def integer_cbrt(n):
    """Raiz cubica entera de n usando Newton-Raphson para bigints."""
    if n == 0: return 0
    x = int(round(n ** (1.0/3)))
    # Ajustar con Newton
    while True:
        x1 = (2*x + n//(x*x)) // 3
        if x1 >= x: break
        x = x1
    # Verificar vecinos
    for c in [x-1, x, x+1, x+2]:
        if c >= 0 and c**3 == n:
            return c
    raise ValueError("No es cubo perfecto")

# 1. Obtener los ciphertexts
data = requests.get(f"{HOST}/ciphertexts").json()
keys = data["keys"]
ns = [int(k["n"], 16) for k in keys]
cts = [int(k["ct"], 16) for k in keys]

print(f"n1 bits: {ns[0].bit_length()}")
print(f"n2 bits: {ns[1].bit_length()}")
print(f"n3 bits: {ns[2].bit_length()}")

# 2. CRT
X = crt(cts, ns)
print(f"X = m^3 tiene {X.bit_length()} bits")

# 3. Raiz cubica entera
m = integer_cbrt(X)
print(f"m tiene {m.bit_length()} bits")

# 4. Convertir a bytes
plaintext = long_to_bytes(m)
print(f"Plaintext: {plaintext}")

# 5. Enviar respuesta
resp = requests.post(f"{HOST}/answer", json={"plaintext": plaintext.hex()})
print(f"Respuesta: {resp.json()}")
```

## Variante con sympy

```python
from sympy.ntheory.modular import crt as sympy_crt
from sympy import integer_nthroot

X, _ = sympy_crt(ns, cts)
m, is_exact = integer_nthroot(X, 3)
assert is_exact, "No es cubo perfecto"
print(long_to_bytes(m))
```

## Por qué funciona
- n_i = 1024 bits => n_1 * n_2 * n_3 ≈ 3072 bits
- La flag tiene <128 bytes = 1024 bits, así que m^3 < 3072 bits
- El CRT da m^3 exacto (no reducido módulo nada)
- cbrt de ese entero gigante da m exactamente

## Notas
- Si la flag es más larga que ~340 bits, m^3 podría ser >= n_1*n_2*n_3 y el
  ataque fallaría. Por eso el servidor verifica flag_pt < n_i al generar claves.
- Con padding OAEP esto no funcionaría (el padding aleatorio rompe el ataque).
- Con e=65537 necesitarías 65537 servidores, lo cual es impracticable.
