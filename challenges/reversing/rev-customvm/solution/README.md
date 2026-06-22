# Solution: CustomVM Crackme (rev-customvm)

## Overview

The binary implements a custom 8-instruction virtual machine. The password check
is performed entirely in VM bytecode.

## Reversing Steps

### 1. Identify the VM structure

Open `vm_checker` in Ghidra or IDA. The `VM` struct has:
- `stack[256]` — byte array
- `sp` — stack pointer (int)
- `mem[512]` — memory (password loaded at addresses 0..14)
- `pc` — program counter (uint16)
- `halted`, `result` flags

### 2. Find the opcode dispatch

The `vm_execute()` function contains a switch on the opcode byte. Map opcodes:
```
0x01 = PUSH <imm>
0x02 = POP
0x03 = ADD
0x04 = XOR
0x05 = CMP (push 1 if equal, 0 otherwise)
0x06 = JNZ <offset>   (conditional forward jump)
0x07 = LOAD <addr>    (push mem[addr])
0x08 = HALT           (result = top-of-stack)
```

### 3. Trace the bytecode

The `build_bytecode()` function generates bytecode that, for each character i:
```
LOAD i           ; push input[i]
PUSH xor_key[i]  ; push the XOR key
XOR              ; XOR them together
PUSH expected[i] ; push stored expected value
CMP              ; compare
JNZ +2           ; if match, skip FAIL block
PUSH 0           ; FAIL
HALT             ; result = 0
```
After all 15 checks pass: `PUSH 1; HALT`

### 4. Extract the key material

From the binary (static arrays in BSS/data):
```c
xor_keys[]  = { 0x17,0x2A,0x3B,0x4C,0x55,0x66,0x77,0x08,
                0x19,0x2A,0x3B,0x4C,0x55,0x66,0x77 }
expected[]  = { 0x54,0x7E,0x7D,0x13,0x03,0x2B,0x28,0x5A,
                0x2A,0x7C,0x08,0x1E,0x06,0x55,0x25 }
```

### 5. Recover the password

`password[i] = expected[i] XOR xor_keys[i]`

```python
xor_keys = [0x17,0x2A,0x3B,0x4C,0x55,0x66,0x77,0x08,
            0x19,0x2A,0x3B,0x4C,0x55,0x66,0x77]
expected = [0x54,0x7E,0x7D,0x13,0x03,0x2B,0x28,0x5A,
            0x2A,0x7C,0x08,0x1E,0x06,0x55,0x25]
password = ''.join(chr(e^k) for e,k in zip(expected, xor_keys))
print(password)  # CTF_VM_R3V3RS3R
```

## Submit

```bash
curl -s -X POST http://<host>:6001/check \
     -H 'Content-Type: application/json' \
     -d '{"answer":"CTF_VM_R3V3RS3R"}'
```

## Answer

`CTF_VM_R3V3RS3R`
