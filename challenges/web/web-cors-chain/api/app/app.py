from flask import Flask, request, jsonify, session, make_response
import os

app = Flask(__name__)
app.secret_key = 'cors-secret-key-xyz'
FLAG = os.environ.get('FLAG', 'HL4{EJEMPLO_LOCAL}')

users = {
    'admin': {'password': 'adminpass', 'token': 'admin-api-token-secret-abc', 'role': 'admin'},
    'user1': {'password': 'user1pass', 'token': 'user1-token-xyz', 'role': 'user'}
}


def get_cors_headers():
    origin = request.headers.get('Origin', '')
    # VULNERABILITY: Reflects any Origin with credentials - classic CORS misconfiguration
    if origin:
        return {
            'Access-Control-Allow-Origin': origin,
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
        }
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
    }


@app.after_request
def add_cors(response):
    cors = get_cors_headers()
    for k, v in cors.items():
        response.headers[k] = v
    return response


@app.route('/', methods=['GET', 'OPTIONS'])
def index():
    if request.method == 'OPTIONS':
        return make_response('', 204)
    return jsonify({
        'message': 'Corporate API v2.1',
        'endpoints': [
            'POST /api/login',
            'GET /api/me',
            'GET /api/admin/export',
            'POST /api/report-url',
            'GET /cors-demo',
            'GET /captured'
        ]
    })


@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return make_response('', 204)
    data = request.get_json() or {}
    u = data.get('username')
    p = data.get('password')
    if u in users and users[u]['password'] == p:
        session['user'] = u
        session['token'] = users[u]['token']
        return jsonify({'success': True, 'token': users[u]['token']})
    return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/api/me', methods=['GET', 'OPTIONS'])
def me():
    if request.method == 'OPTIONS':
        return make_response('', 204)
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    for u, info in users.items():
        if info['token'] == token:
            return jsonify({'username': u, 'role': info['role']})
    return jsonify({'error': 'Unauthorized'}), 401


@app.route('/api/admin/export', methods=['GET', 'OPTIONS'])
def admin_export():
    if request.method == 'OPTIONS':
        return make_response('', 204)
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if users.get('admin', {}).get('token') == token:
        return jsonify({'flag': FLAG, 'data': 'sensitive admin export data', 'users': list(users.keys())})
    return jsonify({'error': 'Admin access required'}), 403


@app.route('/api/report-url', methods=['POST', 'OPTIONS'])
def report_url():
    """Submit URL for admin bot to visit"""
    if request.method == 'OPTIONS':
        return make_response('', 204)
    data = request.get_json() or {}
    url = data.get('url')
    if not url:
        return jsonify({'error': 'URL required'}), 400
    with open('/tmp/pending_urls.txt', 'a') as f:
        f.write(url + '\n')
    return jsonify({'success': True, 'message': 'URL submitted for admin review'})


@app.route('/cors-demo', methods=['GET'])
def cors_demo():
    """
    A page served by the API that can be used as a CORS pivot.
    The admin bot visits this URL with the admin Authorization header.
    The page fetches /api/admin/export (same origin - works always)
    and sends the result to /capture.
    """
    target_url = request.args.get('target', '/api/admin/export')
    steal_to = request.args.get('to', '/capture')

    html = f"""<!DOCTYPE html>
<html>
<head><title>CORS Demo</title></head>
<body>
<script>
(function() {{
    var targetUrl = '{target_url}';
    var stealTo = '{steal_to}';

    fetch(targetUrl, {{
        method: 'GET',
        headers: {{
            'Authorization': 'Bearer admin-api-token-secret-abc'
        }},
        credentials: 'include'
    }}).then(function(r) {{
        return r.text();
    }}).then(function(data) {{
        // Send captured data to /capture endpoint
        fetch(stealTo, {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify({{data: data}})
        }});
        document.body.innerHTML = '<pre>' + data + '</pre>';
    }}).catch(function(e) {{
        document.body.innerHTML = 'Error: ' + e;
    }});
}})();
</script>
<p>Loading...</p>
</body>
</html>"""
    return html


@app.route('/capture', methods=['GET', 'POST', 'OPTIONS'])
def capture():
    """Endpoint to receive stolen data"""
    if request.method == 'OPTIONS':
        return make_response('', 204)
    if request.method == 'POST':
        data = request.get_json() or {}
        captured = data.get('data', '')
        with open('/tmp/captured.txt', 'w') as f:
            f.write(captured)
        return jsonify({'ok': True})
    # GET: check via query param too (for simple GET-based exfil)
    captured_data = request.args.get('data', '')
    if captured_data:
        with open('/tmp/captured.txt', 'w') as f:
            f.write(captured_data)
        return 'ok'
    return jsonify({'message': 'Use POST with JSON body {data: ...}'})


@app.route('/captured', methods=['GET'])
def get_captured():
    """Check if admin data has been captured"""
    try:
        with open('/tmp/captured.txt') as f:
            content = f.read()
        return content if content else jsonify({'message': 'Nothing captured yet'})
    except FileNotFoundError:
        return jsonify({'message': 'Nothing captured yet. Submit a URL first via /api/report-url'})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
