"""BroadcastRSA — crypto-hastad (Crypto INSANE, HTTP/Flask).

Vulnerabilidad central: ATAQUE DE HASTAD SOBRE BROADCAST RSA.

Tres pares de claves RSA-1024 con e=3 cifran el MISMO plaintext (la FLAG):
  ct_i = flag_pt^3 mod n_i  para i = 1, 2, 3

Por el Teorema Chino del Resto (CRT):
  X = CRT([ct_1, ct_2, ct_3], [n_1, n_2, n_3])
  => X = flag_pt^3  (en enteros, no modular, porque flag_pt < n_i para todo i)
  => flag_pt = cbrt(X)  (raíz cúbica entera exacta)

El atacante solo necesita:
  1. GET /ciphertexts → obtener (n_i, ct_i) para i=1,2,3
  2. Calcular X = CRT
  3. Calcular cbrt(X) exacto
  4. Convertir a bytes → FLAG

Endpoints:
  GET /ciphertexts  → {"keys": [{"n": hex, "e": 3, "ct": hex}, ...]}
  GET /info         → hint sobre el ataque
  POST /answer      → {"plaintext": hex} → si coincide con FLAG, devuelve éxito

La FLAG se inyecta por equipo vía env FLAG.
Las claves RSA se generan al iniciar el proceso (puede tardar ~30s).
"""
import os
import hashlib

from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime

from siem import emit
from reqlog import reqlog_http

FLAG = os.environ.get("FLAG", "HL4{EJEMPLO_LOCAL}").encode()
CHALLENGE_ID = os.environ.get("CHALLENGE_ID", "crypto-hastad")

app = Flask(__name__)

E = 3  # Exponente público pequeño


def generate_rsa_key_with_e3(bits=1024):
    """Genera clave RSA con e=3 (p,q escogidos tal que gcd(e, lambda(n)) = 1)."""
    print(f"  Generando clave RSA-{bits} con e=3...", flush=True)
    while True:
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        if p == q:
            continue
        n = p * q
        # phi = (p-1)(q-1); necesitamos gcd(3, phi) = 1
        phi = (p - 1) * (q - 1)
        if phi % 3 != 0:
            # e=3 es válido
            return n, E
    # No llega aquí


def crt(remainders, moduli):
    """Teorema Chino del Resto: encuentra x tal que x = r_i mod m_i."""
    from functools import reduce

    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

    def crt_two(r1, m1, r2, m2):
        g, x, _ = extended_gcd(m1, m2)
        if (r2 - r1) % g != 0:
            raise ValueError("No hay solución CRT")
        lcm = m1 * m2 // g
        return ((r1 + m1 * ((r2 - r1) // g * x % (m2 // g))) % lcm, lcm)

    result, mod = remainders[0], moduli[0]
    for r, m in zip(remainders[1:], moduli[1:]):
        result, mod = crt_two(result, mod, r, m)
    return result, mod


def integer_cbrt(n):
    """Raíz cúbica entera exacta de n. Lanza si n no es un cubo perfecto."""
    if n < 0:
        return -integer_cbrt(-n)
    if n == 0:
        return 0
    # Estimación inicial usando float
    guess = int(round(n ** (1/3)))
    # Newton-Raphson para enteros grandes
    for candidate in [guess - 1, guess, guess + 1, guess + 2]:
        if candidate >= 0 and candidate ** 3 == n:
            return candidate
    # Si falla con la estimación cercana, buscar más ampliamente
    x = guess
    while True:
        x1 = (2 * x + n // (x * x)) // 3
        if x1 >= x:
            break
        x = x1
    # Verificar vecinos
    for candidate in range(max(0, x - 2), x + 3):
        if candidate ** 3 == n:
            return candidate
    raise ValueError(f"No es un cubo perfecto: {n}")


# Generar las tres claves RSA al iniciar
print("[*] Generando 3 claves RSA-1024 con e=3 (puede tardar ~30s)...", flush=True)
KEYS = []
FLAG_PT = bytes_to_long(FLAG)

for i in range(3):
    n, e = generate_rsa_key_with_e3(1024)
    # Asegurar que flag_pt < n (necesario para el ataque)
    while FLAG_PT >= n:
        n, e = generate_rsa_key_with_e3(1024)
    ct = pow(FLAG_PT, e, n)
    KEYS.append({"n": n, "e": e, "ct": ct})
    print(f"  Clave {i+1}/3 lista: n={n.bit_length()} bits", flush=True)

print("[*] Claves RSA listas.", flush=True)


@app.before_request
def log_request():
    try:
        body = request.get_data(as_text=True)
        reqlog_http(
            src_ip=request.remote_addr,
            method=request.method,
            path=request.path,
            query=request.query_string.decode(errors="replace"),
            headers=dict(request.headers),
            body=body,
        )
    except Exception:
        pass


@app.route("/ciphertexts", methods=["GET"])
def ciphertexts():
    return jsonify({
        "e": E,
        "keys": [
            {"n": hex(k["n"]), "e": k["e"], "ct": hex(k["ct"])}
            for k in KEYS
        ],
        "hint": "Tres modulos, mismo e=3, mismo plaintext. CRT + cbrt.",
    })


@app.route("/info", methods=["GET"])
def info():
    return jsonify({
        "attack": "Hastad Broadcast Attack",
        "steps": [
            "1. Obtener (n1,ct1), (n2,ct2), (n3,ct3) de /ciphertexts",
            "2. Calcular X = CRT([ct1,ct2,ct3], [n1,n2,n3])",
            "3. Calcular m = cbrt(X) (raiz cubica entera exacta)",
            "4. Convertir m a bytes",
            "5. POST /answer con {'plaintext': hex(m)}",
        ],
        "note": "flag_pt < n_i para todos los modulos. CRT da flag_pt^3 exacto.",
    })


@app.route("/answer", methods=["POST"])
def answer():
    data = request.get_json(force=True, silent=True) or {}
    pt_hex = data.get("plaintext", "")
    try:
        candidate = bytes.fromhex(pt_hex)
    except ValueError:
        return jsonify({"error": "plaintext debe ser hex"}), 400

    if candidate == FLAG:
        emit("scan_detected", "critical",
             src_ip=request.remote_addr,
             detail={"event": "hastad-broadcast-solved"})
        return jsonify({"success": True, "flag": FLAG.decode()})

    # Pista adicional: mostrar los primeros bytes para debugging
    return jsonify({
        "error": "Plaintext incorrecto",
        "hint": f"Primeros 4 bytes de tu respuesta: {candidate[:4].hex() if candidate else 'vacio'}",
    }), 403


if __name__ == "__main__":
    print(f"[*] BroadcastRSA escuchando en 0.0.0.0:9999", flush=True)
    app.run(host="0.0.0.0", port=9999, debug=False)
