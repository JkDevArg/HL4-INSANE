/*
 * pwn-aarch64-rop — AArch64 buffer overflow + ROP chain
 *
 * Compilar para AArch64:
 *   aarch64-linux-gnu-gcc -o vuln vuln.c -no-pie -fno-stack-protector
 *
 * Protecciones: NX, ASLR (sin PIE para gadgets fijos)
 * Sin stack canary → overflow directo al saved x30 (link register)
 *
 * ROP en AArch64:
 *   - Argumentos: x0, x1, x2 (como rdi, rsi, rdx en x86)
 *   - Gadget para cargar x0: "ldr x0, [sp, #N]; ldp x29, x30, [sp, #M]; ret"
 *   - O buscar: "mov x0, xN; ldp x29, x30, [sp, #M]; ret"
 *   - Gadget ret: "ldp x29, x30, [sp], #16; ret" es el gadget epilogo clásico
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void setup(void) {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

/* Función de autenticación con buffer overflow */
int authenticate(void) {
    char username[32];
    char password[64];   /* ← overflow aquí */

    printf("Username: ");
    fgets(username, sizeof(username), stdin);

    printf("Password: ");
    /* BUG: lee mucho más de lo que cabe en password */
    read(0, password, 512);

    if (strcmp(username, "admin\n") == 0 &&
        strcmp(password, "s3cr3t\n") == 0) {
        return 1;
    }
    return 0;
}

int main(void) {
    setup();
    puts("=== AArch64 Authentication Service ===");
    puts("Login to access the system.");

    if (authenticate()) {
        puts("Access granted!");
    } else {
        puts("Access denied.");
    }
    return 0;
}
