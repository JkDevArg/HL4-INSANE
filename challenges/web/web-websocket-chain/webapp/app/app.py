from flask import Flask, render_template, request, session, redirect
from flask_socketio import SocketIO, emit, join_room
import os
import subprocess

app = Flask(__name__)
app.secret_key = 'ws-secret-key-xyz'
FLAG = os.environ.get('FLAG', 'HL4{EJEMPLO_LOCAL}')

# VULNERABLE: no origin check in SocketIO - CSWSH vulnerability
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='eventlet')

users = {
    'admin': 'adminpass123',
    'alice': 'alice123',
    'bob': 'bob456'
}

# Fixed admin token - intentionally visible in JS source
ADMIN_TOKEN = 'admin-static-token-abc123'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form.get('username')
        p = request.form.get('password')
        if u in users and users[u] == p:
            session['user'] = u
            session['token'] = ADMIN_TOKEN if u == 'admin' else f'user-token-{u}'
            return redirect('/chat')
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/chat')
def chat():
    if 'user' not in session:
        return redirect('/login')
    return render_template('chat.html', username=session['user'])

# WebSocket events
@socketio.on('connect')
def on_connect(auth):
    # VULNERABILITY: No Origin header validation
    token = auth.get('token') if auth else None
    if token == ADMIN_TOKEN:
        session['ws_user'] = 'admin'
        session['ws_role'] = 'admin'
    else:
        session['ws_user'] = session.get('user', 'anonymous')
        session['ws_role'] = 'user'
    join_room(session.get('ws_user', 'anonymous'))
    join_room('public')
    emit('status', {'message': f"Connected as {session.get('ws_user', 'anonymous')}"})

@socketio.on('disconnect')
def on_disconnect():
    pass

@socketio.on('message')
def on_message(data):
    msg = data.get('message', '')
    room = data.get('room', 'public')
    emit('message', {
        'user': session.get('ws_user', 'anonymous'),
        'message': msg
    }, room=room)

@socketio.on('admin_command')
def on_admin_command(data):
    # Only admin can run commands
    if session.get('ws_role') != 'admin':
        emit('error', {'message': 'Permission denied'})
        return
    cmd = data.get('command', 'echo hello')
    allowed = ['status', 'uptime', 'whoami', 'flag']
    if cmd == 'flag':
        emit('command_result', {'output': FLAG})
    elif cmd == 'status':
        emit('command_result', {'output': 'All systems operational'})
    elif cmd == 'uptime':
        output = subprocess.run('uptime', shell=True, capture_output=True, text=True).stdout.strip()
        emit('command_result', {'output': output})
    elif cmd == 'whoami':
        output = subprocess.run('whoami', shell=True, capture_output=True, text=True).stdout.strip()
        emit('command_result', {'output': output})
    else:
        emit('command_result', {'output': f'Command not allowed. Available: {", ".join(allowed)}'})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8080, debug=False)
