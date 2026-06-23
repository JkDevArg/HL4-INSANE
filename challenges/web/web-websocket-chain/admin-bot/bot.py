import socketio
import time
import sys

sio = socketio.Client(logger=False, engineio_logger=False)

@sio.on('connect')
def on_connect():
    print('[bot] Connected to webapp as admin', flush=True)

@sio.on('status')
def on_status(data):
    print(f'[bot] Status: {data}', flush=True)

@sio.on('command_result')
def on_result(data):
    print(f'[bot] Command result: {data}', flush=True)

@sio.on('disconnect')
def on_disconnect():
    print('[bot] Disconnected, will reconnect...', flush=True)

def connect_with_retry():
    while True:
        try:
            sio.connect('http://webapp:8080', auth={'token': 'admin-static-token-abc123'})
            break
        except Exception as e:
            print(f'[bot] Connection failed: {e}, retrying in 5s...', flush=True)
            time.sleep(5)

connect_with_retry()

# Send periodic status commands
try:
    while True:
        time.sleep(60)
        try:
            sio.emit('admin_command', {'command': 'status'})
        except Exception as e:
            print(f'[bot] Error sending command: {e}', flush=True)
            connect_with_retry()
except KeyboardInterrupt:
    sio.disconnect()
