/*
 * Simple bytecode VM with OOB write vulnerability.
 *
 * ISA (each instruction = 1 byte opcode + optional operands):
 *   0x01 PUSH <val:int64>   - push 8-byte value onto stack
 *   0x02 POP               - pop and discard top of stack
 *   0x03 ADD               - pop a,b; push a+b
 *   0x04 SUB               - pop a,b; push a-b
 *   0x05 MUL               - pop a,b; push a*b
 *   0x06 LOAD <addr:int32>  - push vm_mem[addr]
 *   0x07 STORE <addr:int32> - pop val; vm_mem[addr] = val  [NO BOUNDS CHECK]
 *   0x08 PRINT             - pop and print top of stack
 *   0x09 HALT              - stop execution
 *   0x0A CALL_CB           - call the vm_state.callback function pointer
 *   0x0B DUP               - duplicate top of stack
 *   0x0C SWAP              - swap top two stack elements
 *   0x0D JMP <off:int32>   - jump to offset in bytecode
 *   0x0E JZ  <off:int32>   - jump if top==0
 *   0x0F NEG               - negate top of stack
 *   0x10 MOD               - pop a,b; push a%b
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#define VM_MEM_SIZE  256
#define VM_STK_SIZE  64
#define MAX_BYTECODE 1024

typedef struct {
    int64_t  mem[VM_MEM_SIZE];       /* offset 0     */
    void    (*callback)(void);       /* offset 2048  (256 * 8 bytes) */
    int64_t  stack[VM_STK_SIZE];
    int      sp;
    uint8_t  code[MAX_BYTECODE];
    int      ip;
    int      running;
} vm_state_t;

static vm_state_t vm;

void default_cb(void) {
    puts("[VM] callback invoked (default)");
}

void win(void) {
    puts("[VM] *** ESCAPE DETECTED — executing win() ***");
    system("cat /home/ctf/flag.txt");
}

static void vm_push(int64_t v) {
    if (vm.sp >= VM_STK_SIZE) { puts("Stack overflow!"); exit(1); }
    vm.stack[vm.sp++] = v;
}

static int64_t vm_pop(void) {
    if (vm.sp <= 0) { puts("Stack underflow!"); exit(1); }
    return vm.stack[--vm.sp];
}

static int64_t read_i64(void) {
    int64_t v;
    memcpy(&v, &vm.code[vm.ip], 8);
    vm.ip += 8;
    return v;
}

static int32_t read_i32(void) {
    int32_t v;
    memcpy(&v, &vm.code[vm.ip], 4);
    vm.ip += 4;
    return v;
}

void vm_run(void) {
    vm.running = 1;
    vm.ip      = 0;
    vm.sp      = 0;

    while (vm.running && vm.ip < MAX_BYTECODE) {
        uint8_t op = vm.code[vm.ip++];
        int64_t a, b;
        int32_t addr;

        switch (op) {
            case 0x01: /* PUSH */
                vm_push(read_i64());
                break;
            case 0x02: /* POP */
                vm_pop();
                break;
            case 0x03: /* ADD */
                b = vm_pop(); a = vm_pop(); vm_push(a + b);
                break;
            case 0x04: /* SUB */
                b = vm_pop(); a = vm_pop(); vm_push(a - b);
                break;
            case 0x05: /* MUL */
                b = vm_pop(); a = vm_pop(); vm_push(a * b);
                break;
            case 0x06: /* LOAD */
                addr = read_i32();
                if (addr < 0 || addr >= VM_MEM_SIZE) {
                    puts("LOAD out of bounds"); vm.running = 0; break;
                }
                vm_push(vm.mem[addr]);
                break;
            case 0x07: /* STORE — BUG: no bounds check on addr */
                addr = read_i32();
                a = vm_pop();
                /* BUG: addr can be >= VM_MEM_SIZE — writes beyond vm.mem[] */
                /* vm.callback is at mem[256] (offset = 256 int64s = index 256) */
                vm.mem[addr] = a;
                break;
            case 0x08: /* PRINT */
                a = vm_pop();
                printf("[VM] %lld (0x%llx)\n", (long long)a, (unsigned long long)a);
                break;
            case 0x09: /* HALT */
                vm.running = 0;
                break;
            case 0x0A: /* CALL_CB */
                if (vm.callback) vm.callback();
                break;
            case 0x0B: /* DUP */
                a = vm_pop(); vm_push(a); vm_push(a);
                break;
            case 0x0C: /* SWAP */
                a = vm_pop(); b = vm_pop(); vm_push(a); vm_push(b);
                break;
            case 0x0D: /* JMP */
                addr = read_i32(); vm.ip = addr;
                break;
            case 0x0E: /* JZ */
                addr = read_i32(); a = vm_pop();
                if (a == 0) vm.ip = addr;
                break;
            case 0x0F: /* NEG */
                a = vm_pop(); vm_push(-a);
                break;
            case 0x10: /* MOD */
                b = vm_pop(); a = vm_pop();
                if (b == 0) { puts("Division by zero"); exit(1); }
                vm_push(a % b);
                break;
            default:
                printf("Unknown opcode: 0x%02x\n", op);
                vm.running = 0;
        }
    }
}

int main(void) {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    memset(&vm, 0, sizeof(vm));
    vm.callback = default_cb;

    puts("=== ByteVM v1.0 ===");
    printf("[info] win()=%p  callback@%p  vm_mem@%p\n",
           (void*)win, (void*)&vm.callback, (void*)vm.mem);

    puts("Enter bytecode length then bytecode (binary):");
    uint32_t blen;
    scanf("%u", &blen);
    getchar();
    if (blen > MAX_BYTECODE) { puts("Too long"); return 1; }

    ssize_t n = read(STDIN_FILENO, vm.code, blen);
    if (n < 0) { perror("read"); return 1; }
    vm.code[n] = 0x09; /* auto-HALT at end */

    printf("[info] loaded %zd bytes of bytecode\n", n);
    puts("Executing...");
    vm_run();
    puts("Done.");
    return 0;
}
