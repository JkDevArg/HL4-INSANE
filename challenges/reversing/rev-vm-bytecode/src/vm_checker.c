/*
 * CustomVM Crackme - CTF Challenge
 * A password checker implemented as a custom virtual machine.
 *
 * VM Opcodes:
 *   0x01 val   - PUSH: push immediate byte value onto stack
 *   0x02       - POP:  pop top of stack (discard)
 *   0x03       - ADD:  pop two values, push their sum
 *   0x04       - XOR:  pop two values, push their XOR
 *   0x05       - CMP:  pop two values; push 1 if equal, 0 otherwise
 *   0x06 off   - JNZ:  pop top; if != 0, jump forward by offset bytes
 *   0x07 addr  - LOAD: push byte from memory[addr]
 *   0x08       - HALT: stop execution
 *
 * The VM checks a 15-character password.
 * For each character at index i:
 *   memory[i] XOR xor_key[i] must equal expected[i]
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define STACK_SIZE   256
#define MEM_SIZE     512
#define MAX_PC       4096
#define PASS_LEN     15

/* VM state */
typedef struct {
    uint8_t  stack[STACK_SIZE];
    int      sp;          /* stack pointer, -1 = empty */
    uint8_t  mem[MEM_SIZE];
    uint16_t pc;
    int      halted;
    int      result;      /* 1 = pass, 0 = fail */
} VM;

/* ---- stack helpers ---- */
static void vm_push(VM *vm, uint8_t val) {
    if (vm->sp >= STACK_SIZE - 1) {
        fprintf(stderr, "VM stack overflow\n");
        vm->halted = 1;
        return;
    }
    vm->stack[++(vm->sp)] = val;
}

static uint8_t vm_pop(VM *vm) {
    if (vm->sp < 0) {
        fprintf(stderr, "VM stack underflow\n");
        vm->halted = 1;
        return 0;
    }
    return vm->stack[(vm->sp)--];
}

/* ---- fetch next byte from bytecode ---- */
static uint8_t fetch(VM *vm, const uint8_t *code, size_t code_len) {
    if (vm->pc >= code_len) {
        vm->halted = 1;
        return 0;
    }
    return code[(vm->pc)++];
}

/* ---- execute bytecode ---- */
void vm_execute(VM *vm, const uint8_t *code, size_t code_len) {
    vm->halted = 0;
    vm->result = 0;

    while (!vm->halted) {
        uint8_t op = fetch(vm, code, code_len);
        uint8_t a, b, addr, off;

        switch (op) {
            case 0x01: /* PUSH val */
                a = fetch(vm, code, code_len);
                vm_push(vm, a);
                break;

            case 0x02: /* POP */
                vm_pop(vm);
                break;

            case 0x03: /* ADD */
                a = vm_pop(vm);
                b = vm_pop(vm);
                vm_push(vm, (uint8_t)(a + b));
                break;

            case 0x04: /* XOR */
                a = vm_pop(vm);
                b = vm_pop(vm);
                vm_push(vm, a ^ b);
                break;

            case 0x05: /* CMP */
                a = vm_pop(vm);
                b = vm_pop(vm);
                vm_push(vm, (a == b) ? 1 : 0);
                break;

            case 0x06: /* JNZ offset */
                off = fetch(vm, code, code_len);
                a   = vm_pop(vm);
                if (a != 0) {
                    if (vm->pc + off >= code_len) { vm->halted = 1; break; }
                    vm->pc += off;
                }
                break;

            case 0x07: /* LOAD addr */
                addr = fetch(vm, code, code_len);
                vm_push(vm, vm->mem[addr]);
                break;

            case 0x08: /* HALT */
                /* top of stack is the final pass/fail result */
                vm->result = (vm->sp >= 0) ? vm_pop(vm) : 0;
                vm->halted = 1;
                break;

            default:
                fprintf(stderr, "VM illegal opcode 0x%02X at pc=%u\n", op, vm->pc - 1);
                vm->halted = 1;
                break;
        }
    }
}

/*
 * Bytecode: for each of the 15 input bytes, do:
 *   LOAD i           -- push mem[i]          (the i-th input char)
 *   PUSH xor_key[i]  -- push the XOR key byte
 *   XOR              -- pop two, push XOR result
 *   PUSH expected[i] -- push the expected value
 *   CMP              -- push 1 if equal, 0 if not
 *   JNZ 2            -- if OK, skip the FAIL block
 *   PUSH 0           -- FAIL: push 0
 *   HALT             --   and halt (result=0)
 *
 * After all 15 checks pass we push 1 and HALT.
 *
 * XOR keys and expected values derived from password "CTF_VM_R3V3RS3R":
 *   expected[i] = password[i] XOR xor_key[i]
 */

/* xor_key and expected pre-computed */
static const uint8_t xor_keys[PASS_LEN] = {
    0x17, 0x2A, 0x3B, 0x4C, 0x55, 0x66, 0x77, 0x08,
    0x19, 0x2A, 0x3B, 0x4C, 0x55, 0x66, 0x77
};

static const uint8_t expected[PASS_LEN] = {
    0x54, 0x7E, 0x7D, 0x13, 0x03, 0x2B, 0x28, 0x5A,
    0x2A, 0x7C, 0x08, 0x1E, 0x06, 0x55, 0x25
};

/* Build bytecode dynamically so it reflects the arrays above */
static size_t build_bytecode(uint8_t *buf) {
    size_t pos = 0;

    for (int i = 0; i < PASS_LEN; i++) {
        buf[pos++] = 0x07; buf[pos++] = (uint8_t)i; /* LOAD i          */
        buf[pos++] = 0x01; buf[pos++] = xor_keys[i]; /* PUSH xor_key[i] */
        buf[pos++] = 0x04;                             /* XOR             */
        buf[pos++] = 0x01; buf[pos++] = expected[i];  /* PUSH expected[i]*/
        buf[pos++] = 0x05;                             /* CMP             */
        buf[pos++] = 0x06; buf[pos++] = 0x02;          /* JNZ +2          */
        /* FAIL path */
        buf[pos++] = 0x01; buf[pos++] = 0x00;          /* PUSH 0          */
        buf[pos++] = 0x08;                             /* HALT (result=0) */
    }

    /* All checks passed */
    buf[pos++] = 0x01; buf[pos++] = 0x01; /* PUSH 1          */
    buf[pos++] = 0x08;                    /* HALT (result=1) */

    return pos;
}

int main(int argc, char *argv[]) {
    char password[PASS_LEN + 2];
    memset(password, 0, sizeof(password));

    /* Read password from stdin (supports piped input) */
    if (fgets(password, sizeof(password), stdin) == NULL) {
        fprintf(stderr, "Usage: echo <password> | ./vm_checker\n");
        return 1;
    }

    /* Strip trailing newline */
    size_t plen = strlen(password);
    if (plen > 0 && password[plen - 1] == '\n') {
        password[--plen] = '\0';
    }

    if (plen != PASS_LEN) {
        puts("ACCESS DENIED");
        return 1;
    }

    /* Initialise VM */
    VM vm;
    memset(&vm, 0, sizeof(vm));
    vm.sp = -1;

    /* Load password into VM memory starting at address 0 */
    for (int i = 0; i < PASS_LEN; i++) {
        vm.mem[i] = (uint8_t)password[i];
    }

    /* Build and run bytecode */
    uint8_t bytecode[MAX_PC];
    size_t  bc_len = build_bytecode(bytecode);

    vm_execute(&vm, bytecode, bc_len);

    if (vm.result == 1) {
        puts("ACCESS GRANTED");
        return 0;
    } else {
        puts("ACCESS DENIED");
        return 1;
    }
}
