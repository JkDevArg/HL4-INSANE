import os
import subprocess
from flask import Flask, send_file, request, jsonify

app = Flask(__name__)
FLAG   = os.environ.get('FLAG', 'HL4{placeholder_dotnetobf}')
ANSWER = "DOTNET_OBF_KEY"
PORT   = 6005


@app.route('/binary')
def get_binary():
    """Serve the compiled Python bytecode (.pyc) as the reversing target."""
    return send_file(
        '/app/checker.pyc',
        as_attachment=True,
        download_name='checker.pyc',
        mimetype='application/octet-stream'
    )


@app.route('/check', methods=['POST'])
def check():
    data   = request.get_json(silent=True) or {}
    answer = str(data.get('answer', ''))

    if answer == ANSWER:
        return jsonify({'success': True, 'flag': FLAG})

    return jsonify({'success': False, 'message': 'WRONG key'})


@app.route('/')
def index():
    return jsonify({
        'challenge': 'DotNetObf — Python Bytecode Reversing',
        'endpoints': {
            'GET /binary': 'Download checker.pyc (compiled Python bytecode)',
            'POST /check': 'Submit answer: {"answer": "<key>"}'
        }
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT)
