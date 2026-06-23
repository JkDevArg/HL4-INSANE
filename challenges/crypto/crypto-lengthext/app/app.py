"""HashForge — crypto-lengthext (Crypto INSANE, HTTP/Flask).

Vulnerabilidad central: MD5 LENGTH EXTENSION ATTACK.

El servidor usa MAC = MD5(secret || message) para autenticar mensajes.
Esto es INSEGURO porque MD5 (como SHA-1 y SHA-256) usa construcción
Merkle-Damgard: dado MD5(secret || msg), se puede calcular
MD5(secret || msg || padding || extension) sin conocer el secreto.

El atacante:
  1. Obtiene un MAC válido para "role=user" via GET /message.
  2. Conoce que el secreto es 16 bytes (via GET /info).
  3. Implementa MD5 length extension para calcular:
       nuevo_mac = MD5_extended(secret || "role=user" || padding || "&role=admin")
  4. Llama GET /admin?msg=ORIGINAL&mac=ORIGINAL_MAC&ext=%26role%3Dadmin&newmac=FORGED
  5. Si la validación pasa y el mensaje final contiene "role=admin", recibe la flag.

Endpoints:
  GET /info    → {"secret_length": 16, "hash_algo": "md5"}
  GET /message → {"msg": "role=user", "mac": "<hex>"}
  GET /admin   → ?msg=<orig>&mac=<orig_mac>&ext=<extension>&newmac=<forged_mac>
                 Valida: md5(secret || msg || md5_glue_padding || ext) == newmac
                 Si válido Y "role=admin" en el mensaje final: devuelve flag.

La FLAG se inyecta por equipo vía env FLAG.
El secreto es aleatorio al iniciar el proceso.
"""
import os
import hashlib
import struct

from flask import Flask, request, jsonify

from siem import emit
from reqlog import reqlog_http

FLAG = os.environ.get("FLAG", "HL4{EJEMPLO_LOCAL}")
SECRET = os.urandom(16)  # 16 bytes, aleatorio por instancia
SECRET_LEN = len(SECRET)

app = Flask(__name__)


# ── MD5 length extension implementation ──────────────────────────────────────

def md5_padding(msg_len: int) -> bytes:
    """Calcula el padding MD5 para un mensaje de longitud msg_len bytes.

    Padding: 0x80 + zeros + longitud en 64 bits little-endian.
    Total longitud = múltiplo de 64 bytes.
    """
    # Bit length
    bit_len = msg_len * 8
    # Bytes necesarios de relleno (sin el byte 0x80)
    pad_len = (55 - msg_len) % 64
    padding = b'\x80' + b'\x00' * pad_len
    # Longitud en little-endian de 8 bytes
    padding += struct.pack('<Q', bit_len)
    return padding


def md5_extend(original_mac_hex: str, original_msg_len: int, extension: bytes) -> str:
    """Calcula el MAC extendido sin conocer el secreto.

    Dado MAC = MD5(secret || original_msg) donde len(secret || original_msg) = original_msg_len,
    calcula MD5(secret || original_msg || padding || extension).

    Restaura el estado interno de MD5 desde el MAC y continúa el hashing.
    """
    # Extraer estado interno de MD5 del MAC
    mac_bytes = bytes.fromhex(original_mac_hex)
    a, b, c, d = struct.unpack('<4I', mac_bytes)

    # La longitud total del mensaje ya procesado por MD5 es:
    # secret_len + original_msg_len + len(padding_for_that_total)
    total_before = original_msg_len + len(md5_padding(original_msg_len))

    # Inicializar MD5 con el estado interno restaurado
    import ctypes

    # Usamos hashlib con un hack para inyectar el estado interno
    # Implementación manual de MD5 para extensión de longitud
    return _md5_from_state(a, b, c, d, total_before, extension)


def _md5_from_state(a, b, c, d, processed_len, data):
    """Continúa MD5 desde un estado interno dado."""
    # Implementación MD5 completa (RFC 1321)
    import math

    # Tabla T: floor(2^32 * abs(sin(i+1))) para i = 0..63
    T = [int(2**32 * abs(math.sin(i + 1))) & 0xFFFFFFFF for i in range(64)]

    def left_rotate(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    # Constantes de desplazamiento
    S = [
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
    ]

    def process_block(block, state):
        A, B, C, D = state
        M = struct.unpack('<16I', block)
        for i in range(64):
            if i < 16:
                F = (B & C) | (~B & D)
                g = i
            elif i < 32:
                F = (D & B) | (~D & C)
                g = (5 * i + 1) % 16
            elif i < 48:
                F = B ^ C ^ D
                g = (3 * i + 5) % 16
            else:
                F = C ^ (B | ~D)
                g = (7 * i) % 16
            F = (F + A + T[i] + M[g]) & 0xFFFFFFFF
            A = D
            D = C
            C = B
            B = (B + left_rotate(F, S[i])) & 0xFFFFFFFF
        return (
            (state[0] + A) & 0xFFFFFFFF,
            (state[1] + B) & 0xFFFFFFFF,
            (state[2] + C) & 0xFFFFFFFF,
            (state[3] + D) & 0xFFFFFFFF,
        )

    # Aplicar padding a los datos de extensión, considerando la longitud ya procesada
    ext_padded = data
    total_len = processed_len + len(data)
    bit_len = total_len * 8
    pad_len = (55 - total_len) % 64
    ext_padded = data + b'\x80' + b'\x00' * pad_len + struct.pack('<Q', bit_len)

    state = (a, b, c, d)
    for i in range(0, len(ext_padded), 64):
        state = process_block(ext_padded[i:i+64], state)

    return struct.pack('<4I', *state).hex()


def compute_mac(msg: bytes) -> str:
    """Calcula el MAC real: MD5(secret || msg)."""
    return hashlib.md5(SECRET + msg).hexdigest()


def verify_extended_mac(original_msg: bytes, original_mac_hex: str,
                         extension: bytes, new_mac_hex: str) -> bool:
    """Verifica que new_mac == MD5(secret || original_msg || padding || extension).

    Lo verificamos calculando el MAC real del mensaje completo.
    """
    # El padding que MD5 insertó al hashear (secret || original_msg)
    total_original_len = SECRET_LEN + len(original_msg)
    padding = md5_padding(total_original_len)
    # El mensaje completo que realmente se hasheó
    full_extended = original_msg + padding + extension
    expected_mac = compute_mac(full_extended)
    return expected_mac == new_mac_hex.lower()


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


@app.route("/info", methods=["GET"])
def info():
    return jsonify({
        "secret_length": SECRET_LEN,
        "hash_algo": "md5",
        "hint": "MAC = MD5(secret || message). La extension de longitud es tu amiga.",
        "admin_endpoint": "GET /admin?msg=ORIGINAL&mac=ORIGINAL_MAC&ext=EXTENSION&newmac=FORGED",
    })


@app.route("/message", methods=["GET"])
def message():
    msg = b"role=user"
    mac = compute_mac(msg)
    return jsonify({
        "msg": msg.decode(),
        "mac": mac,
        "msg_hex": msg.hex(),
    })


@app.route("/admin", methods=["GET"])
def admin():
    msg_param = request.args.get("msg", "")
    mac_param = request.args.get("mac", "")
    ext_param = request.args.get("ext", "")
    newmac_param = request.args.get("newmac", "")

    if not all([msg_param, mac_param, ext_param, newmac_param]):
        return jsonify({"error": "Parametros requeridos: msg, mac, ext, newmac"}), 400

    try:
        original_msg = msg_param.encode()
        extension = ext_param.encode()
    except Exception:
        return jsonify({"error": "Encoding invalido"}), 400

    # Verificar que el MAC original es válido
    expected_original_mac = compute_mac(original_msg)
    if expected_original_mac != mac_param.lower():
        return jsonify({"error": "MAC original invalido"}), 403

    # Verificar el MAC forjado
    if not verify_extended_mac(original_msg, mac_param, extension, newmac_param):
        return jsonify({"error": "MAC forjado invalido"}), 403

    # Construir el mensaje final extendido
    total_original_len = SECRET_LEN + len(original_msg)
    padding = md5_padding(total_original_len)
    final_msg = original_msg + padding + extension

    # Verificar que "role=admin" está en el mensaje final
    if b"role=admin" not in final_msg:
        return jsonify({"error": "El mensaje extendido no contiene role=admin"}), 403

    emit("scan_detected", "critical",
         src_ip=request.remote_addr,
         detail={"event": "md5-length-extension-success"})

    return jsonify({
        "success": True,
        "flag": FLAG,
        "final_msg_hex": final_msg.hex(),
    })


if __name__ == "__main__":
    print(f"[*] HashForge escuchando en 0.0.0.0:9999", flush=True)
    app.run(host="0.0.0.0", port=9999, debug=False)
