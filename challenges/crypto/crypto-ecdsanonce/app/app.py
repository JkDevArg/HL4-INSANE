"""SignOracle — crypto-ecdsanonce (Crypto INSANE, HTTP/Flask).

Vulnerabilidad central: ECDSA NONCE SESGADO + ATAQUE LLL.

ECDSA sobre secp256k1 (la misma curva de Bitcoin). El servidor genera
firmas ECDSA pero los nonces k tienen los 8 bits superiores siempre en 0:
  k < 2^(256-8) = 2^248

Con esta información, el atacante puede plantear el sistema de firmas
como un problema de red lattice (CVB / HNP — Hidden Number Problem)
y usar el algoritmo LLL para recuperar la clave privada en tiempo polinomial.

Se necesitan aproximadamente 40-50 firmas para una tasa de éxito alta.

Endpoints:
  GET  /pubkey       → {"pubkey": "<hex compressed pubkey>", "curve": "secp256k1"}
  POST /sign         → {"msg": "<hex>"} → {"r": "<hex>","s": "<hex>","hash": "<hex>"}
  POST /flag         → {"r": "<hex>","s": "<hex>","msg": "admin_challenge"}
                       Verifica que la firma de ADMIN_CHALLENGE sea válida.
                       Si lo es, devuelve la flag (el atacante ya tiene la private key).

La clave privada se genera aleatoriamente al iniciar el proceso.
La FLAG se inyecta por equipo vía env FLAG.
"""
import os
import hashlib
import json
import secrets

from flask import Flask, request, jsonify

from siem import emit
from reqlog import reqlog_http

FLAG = os.environ.get("FLAG", "flag{EJEMPLO_LOCAL}")
CHALLENGE_ID = os.environ.get("CHALLENGE_ID", "crypto-ecdsanonce")

app = Flask(__name__)

# ── secp256k1 parameters ──────────────────────────────────────────────────────
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A  = 0
B  = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G  = (Gx, Gy)

BIAS_BITS = 8  # los 8 bits MSB del nonce siempre son 0


def modinv(a, m):
    """Inverso modular via algoritmo extendido de Euclides."""
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise ValueError("No existe inverso")
    return x % m


def _egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = _egcd(b % a, a)
    return g, y - (b // a) * x, x


def point_add(P1, P2):
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    x1, y1 = P1
    x2, y2 = P2
    if x1 == x2:
        if y1 != y2:
            return None
        # Point doubling
        lam = (3 * x1 * x1 + A) * modinv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * modinv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return x3, y3


def scalar_mult(k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


# Generar clave privada
PRIVATE_KEY = int.from_bytes(os.urandom(32), "big") % (N - 1) + 1
PUBLIC_KEY = scalar_mult(PRIVATE_KEY, G)

# Mensaje de desafío admin (conocido por el atacante desde el código fuente)
ADMIN_CHALLENGE = b"admin:reveal_flag:v1"


def biased_nonce() -> int:
    """Genera un nonce con 8 bits superiores siempre en 0: k < 2^248."""
    # Los 8 bits superiores son 0: generamos 31 bytes aleatorios (248 bits)
    k = int.from_bytes(secrets.token_bytes(31), "big") % N
    # Asegurar que k != 0
    while k == 0:
        k = int.from_bytes(secrets.token_bytes(31), "big") % N
    return k


def ecdsa_sign(msg_bytes: bytes):
    """Firma ECDSA con nonce sesgado."""
    z = int.from_bytes(hashlib.sha256(msg_bytes).digest(), "big")
    while True:
        k = biased_nonce()
        R = scalar_mult(k, G)
        if R is None:
            continue
        r = R[0] % N
        if r == 0:
            continue
        k_inv = modinv(k, N)
        s = k_inv * (z + PRIVATE_KEY * r) % N
        if s == 0:
            continue
        return r, s, z


def ecdsa_verify(msg_bytes: bytes, r: int, s: int) -> bool:
    """Verifica firma ECDSA contra la clave pública."""
    if not (1 <= r < N and 1 <= s < N):
        return False
    z = int.from_bytes(hashlib.sha256(msg_bytes).digest(), "big")
    w = modinv(s, N)
    u1 = z * w % N
    u2 = r * w % N
    point = point_add(scalar_mult(u1, G), scalar_mult(u2, PUBLIC_KEY))
    if point is None:
        return False
    return point[0] % N == r


sign_count = 0


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


@app.route("/pubkey", methods=["GET"])
def pubkey():
    # Retornar clave pública en formato comprimido hex
    prefix = "02" if PUBLIC_KEY[1] % 2 == 0 else "03"
    compressed = prefix + hex(PUBLIC_KEY[0])[2:].zfill(64)
    return jsonify({
        "pubkey": compressed,
        "curve": "secp256k1",
        "bias_hint": f"Los nonces tienen {BIAS_BITS} bits superiores siempre en 0",
        "admin_challenge": ADMIN_CHALLENGE.hex(),
        "n_bits": N.bit_length(),
    })


@app.route("/sign", methods=["POST"])
def sign():
    global sign_count
    data = request.get_json(force=True, silent=True) or {}
    msg_hex = data.get("msg", "")
    try:
        msg = bytes.fromhex(msg_hex)
    except ValueError:
        return jsonify({"error": "msg debe ser hex"}), 400

    if len(msg) > 256:
        return jsonify({"error": "msg demasiado largo (max 256 bytes)"}), 400

    r, s, z = ecdsa_sign(msg)
    sign_count += 1

    if sign_count == 40:
        emit("scan_detected", "alert",
             src_ip=request.remote_addr,
             detail={"vuln": "ecdsa-biased-nonce", "signatures": sign_count})

    return jsonify({
        "r": hex(r),
        "s": hex(s),
        "hash": hex(z),
        "msg": msg_hex,
    })


@app.route("/flag", methods=["POST"])
def get_flag():
    data = request.get_json(force=True, silent=True) or {}
    try:
        r = int(data.get("r", "0"), 16)
        s = int(data.get("s", "0"), 16)
    except (ValueError, TypeError):
        return jsonify({"error": "r y s deben ser hex"}), 400

    # La firma debe ser de ADMIN_CHALLENGE con la clave privada del servidor.
    if ecdsa_verify(ADMIN_CHALLENGE, r, s):
        emit("scan_detected", "critical",
             src_ip=request.remote_addr,
             detail={"event": "private-key-recovered-ecdsa"})
        return jsonify({"success": True, "flag": FLAG})

    return jsonify({"error": "Firma invalida"}), 403


if __name__ == "__main__":
    print(f"[*] SignOracle escuchando en 0.0.0.0:9999", flush=True)
    app.run(host="0.0.0.0", port=9999, debug=False)
