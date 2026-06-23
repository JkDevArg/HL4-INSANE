import os
import jwt
import json
import base64
import time
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

FLAG = os.environ.get('FLAG', 'HL4{EJEMPLO_LOCAL}')

app = Flask(__name__)

# Generate RSA key pair at startup
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

PRIVATE_PEM = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
PUBLIC_PEM = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

def get_public_numbers():
    pub_nums = public_key.public_numbers()
    n = pub_nums.n
    e = pub_nums.e
    def to_base64url(num):
        length = (num.bit_length() + 7) // 8
        b = num.to_bytes(length, 'big')
        return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
    return to_base64url(n), to_base64url(e)

# Users DB
USERS = {
    'guest': {'password': 'guest123', 'role': 'guest'},
}

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON required'}), 400
    username = data.get('username', '')
    password = data.get('password', '')
    user = USERS.get(username)
    if not user or user['password'] != password:
        return jsonify({'error': 'Invalid credentials'}), 401

    payload = {
        'sub': username,
        'role': user['role'],
        'iat': int(time.time()),
        'exp': int(time.time()) + 3600
    }
    token = jwt.encode(payload, PRIVATE_PEM, algorithm='RS256')
    return jsonify({'token': token, 'message': 'Login successful'})

@app.route('/jwks.json')
def jwks():
    n_b64, e_b64 = get_public_numbers()
    return jsonify({
        'keys': [{
            'kty': 'RSA',
            'use': 'sig',
            'alg': 'RS256',
            'n': n_b64,
            'e': e_b64,
        }]
    })

@app.route('/pubkey')
def pubkey():
    return PUBLIC_PEM, 200, {'Content-Type': 'text/plain'}

@app.route('/admin')
def admin():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'error': 'No token'}), 401
    token = auth[7:]

    # VULNERABLE: accepts algorithm from header, including HS256
    try:
        header = jwt.get_unverified_header(token)
        alg = header.get('alg', 'RS256')

        if alg == 'HS256':
            # Vulnerable: use public key as HMAC secret
            decoded = jwt.decode(token, PUBLIC_PEM, algorithms=['HS256'])
        elif alg == 'RS256':
            decoded = jwt.decode(token, PUBLIC_PEM, algorithms=['RS256'])
        else:
            return jsonify({'error': 'Unsupported algorithm'}), 400
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({'error': f'Invalid token: {str(e)}'}), 401

    role = decoded.get('role', 'guest')
    if role != 'admin':
        return jsonify({'error': 'Admin access required', 'your_role': role}), 403

    return jsonify({'message': 'Welcome admin!', 'flag': FLAG})

@app.route('/profile')
def profile():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'error': 'No token'}), 401
    token = auth[7:]
    try:
        decoded = jwt.decode(token, PUBLIC_PEM, algorithms=['RS256'])
        return jsonify({'user': decoded})
    except Exception:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/')
def index():
    return jsonify({
        'endpoints': ['/login [POST]', '/jwks.json [GET]', '/pubkey [GET]', '/admin [GET]', '/profile [GET]'],
        'hint': 'Login as guest/guest123 to get a token'
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9999, debug=False)
