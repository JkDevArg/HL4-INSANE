import os
import subprocess
from flask import Flask, send_file, request, jsonify

app = Flask(__name__)
FLAG   = os.environ.get('FLAG', 'HL4{placeholder_wasmcrack}')
ANSWER = "R3V_W4SM_PWD"
PORT   = 6003


@app.route('/binary')
def get_binary():
    return send_file(
        '/app/wasmcrack',
        as_attachment=True,
        download_name='wasmcrack',
        mimetype='application/octet-stream'
    )


@app.route('/check', methods=['POST'])
def check():
    data   = request.get_json(silent=True) or {}
    answer = str(data.get('answer', ''))

    if answer == ANSWER:
        return jsonify({'success': True, 'flag': FLAG})

    return jsonify({'success': False, 'message': 'WRONG password'})


@app.route('/')
def index():
    return jsonify({
        'challenge': 'WASMcrack — Rust Hash Validator',
        'endpoints': {
            'GET /binary': 'Download the stripped Rust binary (named wasmcrack)',
            'POST /check': 'Submit answer: {"answer": "<password>"}'
        }
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT)
