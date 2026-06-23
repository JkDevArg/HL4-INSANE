import os
from flask import Flask, jsonify
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

FLAG = os.environ.get('FLAG', 'HL4{EJEMPLO_LOCAL}')

app = Flask(__name__)

E = 3

def generate_rsa_e3(bits=1024):
    """Generate RSA modulus compatible with e=3"""
    while True:
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        if p % 3 != 1 and q % 3 != 1:
            n = p * q
            phi = (p - 1) * (q - 1)
            if phi % E != 0:
                return n

# Generate 3 different moduli
print("[*] Generating RSA parameters...")
N1 = generate_rsa_e3(1024)
N2 = generate_rsa_e3(1024)
N3 = generate_rsa_e3(1024)

# Encrypt the flag (same message to all 3 recipients)
MSG = bytes_to_long(FLAG.encode())

# Ensure MSG^3 < N1*N2*N3 — with 1024-bit moduli and short flag, this holds
C1 = pow(MSG, E, N1)
C2 = pow(MSG, E, N2)
C3 = pow(MSG, E, N3)

print(f"[*] Flag encrypted for 3 recipients with e={E}")
print(f"[*] N1 = {hex(N1)[:20]}...")
print(f"[*] MSG^3 < N1*N2*N3: {MSG**3 < N1*N2*N3}")


@app.route('/')
def index():
    return jsonify({
        'message': 'RSA Broadcast Encryption Service',
        'description': 'The same secret was encrypted for 3 recipients with RSA e=3',
        'recipients': ['/recipient/1', '/recipient/2', '/recipient/3'],
        'hint': 'Collect all 3 ciphertexts. The same message^3 was reduced mod different n values.'
    })


@app.route('/recipient/<int:rid>')
def recipient(rid):
    if rid == 1:
        return jsonify({'n': hex(N1), 'e': E, 'ciphertext': hex(C1), 'recipient': 1})
    elif rid == 2:
        return jsonify({'n': hex(N2), 'e': E, 'ciphertext': hex(C2), 'recipient': 2})
    elif rid == 3:
        return jsonify({'n': hex(N3), 'e': E, 'ciphertext': hex(C3), 'recipient': 3})
    else:
        return jsonify({'error': 'Unknown recipient (1, 2, or 3)'}), 404


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9999, debug=False)
