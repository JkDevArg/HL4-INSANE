import os
import subprocess
from flask import Flask, send_file, request, jsonify

app = Flask(__name__)
FLAG   = os.environ.get('FLAG', 'HL4{placeholder_gobinary}')
ANSWER = "HACKL4BS_G0_CRACK"
PORT   = 6002


@app.route('/binary')
def get_binary():
    return send_file(
        '/app/go_checker',
        as_attachment=True,
        download_name='go_checker',
        mimetype='application/octet-stream'
    )


@app.route('/check', methods=['POST'])
def check():
    data   = request.get_json(silent=True) or {}
    answer = str(data.get('answer', ''))

    if answer == ANSWER:
        return jsonify({'success': True, 'flag': FLAG})

    return jsonify({'success': False, 'message': 'INVALID license key'})


@app.route('/')
def index():
    return jsonify({
        'challenge': 'Go XOR License Checker',
        'endpoints': {
            'GET /binary': 'Download the stripped Go binary',
            'POST /check': 'Submit answer: {"answer": "<license-key>"}'
        }
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT)
