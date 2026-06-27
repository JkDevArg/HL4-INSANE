import os
import subprocess
from flask import Flask, send_file, request, jsonify

app = Flask(__name__)
FLAG   = os.environ.get('FLAG', 'HL4{placeholder_packeddelta}')
ANSWER = "DELTA_PACK_KEY_42"
PORT   = 6004


@app.route('/binary')
def get_binary():
    return send_file(
        '/app/delta_checker',
        as_attachment=True,
        download_name='delta_checker',
        mimetype='application/octet-stream'
    )


@app.route('/check', methods=['POST'])
def check():
    data   = request.get_json(silent=True) or {}
    answer = str(data.get('answer', ''))

    if answer == ANSWER:
        return jsonify({'success': True, 'flag': FLAG})

    return jsonify({'success': False, 'message': 'INCORRECT password'})


@app.route('/')
def index():
    return jsonify({
        'challenge': 'PackedDelta XOR Crackme',
        'endpoints': {
            'GET /binary': 'Download the delta_checker binary',
            'POST /check': 'Submit answer: {"answer": "<password>"}'
        }
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT)
