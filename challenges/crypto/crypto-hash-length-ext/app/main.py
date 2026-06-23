import os
import hashlib
import base64
import random
from flask import Flask, request, jsonify

FLAG = os.environ.get('FLAG', 'HL4{EJEMPLO_LOCAL}')

app = Flask(__name__)

# Random secret of unknown length (8-16 bytes)
SECRET = os.urandom(random.randint(8, 16))
SECRET_LEN = len(SECRET)


def sign(msg):
    """MAC = SHA256(secret || msg)"""
    if isinstance(msg, str):
        msg = msg.encode()
    return hashlib.sha256(SECRET + msg).hexdigest()


def verify(msg, sig):
    if isinstance(msg, str):
        msg = msg.encode()
    return hashlib.sha256(SECRET + msg).hexdigest() == sig


@app.route('/')
def index():
    return jsonify({
        'endpoints': {
            '/api/sample': 'GET - Get a valid signed request',
            '/api/data': 'GET - Request data with params+sig',
            '/api/admin': 'GET - Admin endpoint, requires admin=true in params',
        },
        'hint': 'Start at /api/sample to get a valid signed request to extend'
    })


@app.route('/api/sample')
def api_sample():
    """Returns a valid signed request for the player to extend"""
    msg = "user=guest&action=read"
    sig = sign(msg)
    params_b64 = base64.b64encode(msg.encode()).decode()
    return jsonify({
        'params': params_b64,
        'sig': sig,
        'raw_message': msg,
        'hint': 'sig = SHA256(secret || raw_message). Extend raw_message to add &admin=true'
    })


@app.route('/api/data')
def api_data():
    params_b64 = request.args.get('params', '')
    sig = request.args.get('sig', '')
    try:
        params = base64.b64decode(params_b64).decode('latin-1')
    except Exception:
        return jsonify({'error': 'Invalid base64'}), 400

    if not verify(params, sig):
        return jsonify({'error': 'Invalid signature'}), 403

    return jsonify({'data': f'Data for: {params}'})


@app.route('/api/admin')
def api_admin():
    params_b64 = request.args.get('params', '')
    sig = request.args.get('sig', '')
    try:
        params = base64.b64decode(params_b64).decode('latin-1')
    except Exception:
        return jsonify({'error': 'Invalid base64'}), 400

    if not verify(params, sig):
        return jsonify({'error': 'Invalid signature'}), 403

    if 'admin=true' not in params:
        return jsonify({'error': 'Admin access required', 'hint': 'Need admin=true in params'}), 403

    return jsonify({'flag': FLAG, 'message': 'Welcome, admin!'})


@app.route('/api/secret_length_hint')
def secret_length_hint():
    """Gives a range hint — in a real CTF you'd brute-force this"""
    return jsonify({
        'hint': 'Secret length is between 8 and 16 bytes (inclusive)',
        'try_all': 'Try secret_len from 8 to 16 until the forged signature verifies'
    })


if __name__ == '__main__':
    print(f"[*] Secret length: {SECRET_LEN} (hidden from players)")
    app.run(host='0.0.0.0', port=9999, debug=False)
