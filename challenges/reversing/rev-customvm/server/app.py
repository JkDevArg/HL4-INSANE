import os
import subprocess
from flask import Flask, send_file, request, jsonify

app = Flask(__name__)
FLAG   = os.environ.get('FLAG', 'HL4{placeholder_customvm}')
ANSWER = "CTF_VM_R3V3RS3R"
PORT   = 6001


@app.route('/binary')
def get_binary():
    return send_file(
        '/app/vm_checker',
        as_attachment=True,
        download_name='vm_checker',
        mimetype='application/octet-stream'
    )


@app.route('/check', methods=['POST'])
def check():
    data   = request.get_json(silent=True) or {}
    answer = str(data.get('answer', ''))

    # Constant-time-ish server-side check (binary is the real challenge)
    if answer == ANSWER:
        return jsonify({'success': True, 'flag': FLAG})

    # Optional: actually run the binary for extra authenticity
    # (kept here for extensibility but not required for scoring)
    return jsonify({'success': False, 'message': 'ACCESS DENIED — wrong password'})


@app.route('/')
def index():
    return jsonify({
        'challenge': 'CustomVM Crackme',
        'endpoints': {
            'GET /binary': 'Download the VM crackme binary',
            'POST /check': 'Submit answer: {"answer": "<password>"}'
        }
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT)
