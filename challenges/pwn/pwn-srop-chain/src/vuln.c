/*
 * pwn-srop-chain — SROP challenge
 *
 * Gadgets disponibles en el binario:
 *   pop rax; ret                (0x40101c)
 *   syscall; ret                (0x40101f)
 *
 * Objetivo: forjar un rt_sigreturn frame para ejecutar execve("/bin/sh",0,0)
 *   1. Poner "/bin/sh\0" en algún lugar del payload (en el buffer del stack)
 *   2. Cadena ROP:  [pop rax] [15] [syscall]  ← invoca rt_sigreturn
 *   3. Inmediatamente después del syscall: el frame completo de señal
 *      con rax=59, rdi=addr_of_binsh, rsi=0, rdx=0, rip=syscall_addr
 *
 * Compilar (sin libc, entry manual, solo 2 gadgets):
 *   gcc -o vuln vuln.c -nostdlib -static -fno-stack-protector \
 *       -no-pie -Wl,-N -Wl,--entry=main
 */
#include <sys/syscall.h>

/* Escribe msg en stdout directamente via syscall write */
static void write_str(const char *s, int len) {
    asm volatile (
        "syscall"
        :
        : "a"(SYS_write), "D"(1L), "S"(s), "d"((long)len)
        : "rcx", "r11", "memory"
    );
}

/* Gadget 1: pop rax; ret  — quedará en el binario por uso en asm */
static void __attribute__((used, noinline)) gadget_pop_rax(void) {
    asm volatile("pop %rax; ret");
}

/* Gadget 2: syscall; ret */
static void __attribute__((used, noinline)) gadget_syscall(void) {
    asm volatile("syscall; ret");
}

void __attribute__((noreturn)) main(void) {
    static const char banner[] =
        "=== SROP Challenge ===\n"
        "Only two gadgets. No libc. No execve shortcut.\n"
        "Buffer starts at RSP. You have 1024 bytes.\n"
        "> ";

    write_str(banner, sizeof(banner) - 1);

    /* Leer directamente en el stack — el caller's return address está
     * a 8 bytes sobre el buffer (frame minimalista sin variables locales) */
    asm volatile (
        "xor  %%rdi, %%rdi\n"    /* fd = 0 (stdin) */
        "mov  %%rsp, %%rsi\n"    /* buf = rsp       */
        "sub  $8,    %%rsi\n"    /* ajuste: no pisemos el return addr antes de leer */
        "mov  $1024, %%edx\n"    /* count           */
        "mov  $0,    %%eax\n"    /* SYS_read        */
        "syscall\n"
        ::: "rax", "rdi", "rsi", "rdx", "memory"
    );

    /* ret: el jugador controla la dirección de retorno */
    asm volatile("ret");

    __builtin_unreachable();
}
