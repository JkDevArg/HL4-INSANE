/*
 * pwn-off-by-one — Off-by-one heap exploitation
 *
 * Un gestor de strings que tiene un off-by-one clásico:
 * str_copy() usa `i <= len` en vez de `i < len`, escribiendo
 * el null terminator un byte más allá del buffer asignado.
 *
 * El byte extra (0x00) sobrescribe el LSB del campo `prev_size` o `size`
 * del siguiente chunk del heap, según el layout.
 *
 * Cadena de explotación:
 *   1. Crear chunk A (0x18 bytes) y chunk B (0x18 bytes) adyacentes
 *   2. Llenar chunk A con 0x18 bytes → el null byte sobrescribe size[B]
 *   3. Si size[B] era 0x21 → pasa a 0x20 (pierde el "prev_inuse" bit)
 *      O: size[B] era 0x31 → pasa a 0x30 → cuando se libera B, el allocator
 *      intenta consolidar con el chunk "anterior" (que controlamos)
 *   4. Overlapping chunks → dos punteros al mismo chunk (tcache dup effect)
 *   5. Tcache poisoning → arbitrary write → overwrite __free_hook (glibc <2.34)
 *      o usar la primitive de escritura para sobreescribir una función ptr
 *
 * Compilar:
 *   gcc -o vuln vuln.c -pie -fPIE -fstack-protector-all -Wl,-z,relro,-z,now
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_STRINGS 16
#define MAX_SIZE    0x100

typedef struct {
    size_t  size;
    char   *data;
    int     in_use;
} StringEntry;

static StringEntry table[MAX_STRINGS];

static void setup(void) {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

/* ── VULNERABILIDAD: off-by-one (i <= len, debería ser i < len) ── */
static void str_copy(char *dst, const char *src, size_t len) {
    for (size_t i = 0; i <= len; i++) {   /* <= es el bug */
        dst[i] = src[i];
    }
}

static int read_int(const char *prompt) {
    int v = 0;
    printf("%s", prompt);
    scanf("%d", &v);
    getchar();
    return v;
}

static void cmd_alloc(void) {
    int idx = read_int("Index [0-15]: ");
    if (idx < 0 || idx >= MAX_STRINGS) { puts("Bad index"); return; }
    if (table[idx].in_use)             { puts("Slot taken"); return; }

    int sz = read_int("Size [1-255]: ");
    if (sz <= 0 || sz > MAX_SIZE - 1)  { puts("Bad size"); return; }

    table[idx].data   = (char *)malloc((size_t)sz + 1);
    table[idx].size   = (size_t)sz;
    table[idx].in_use = 1;
    if (!table[idx].data) { puts("OOM"); return; }

    printf("Content (%d bytes): ", sz);
    fgets(table[idx].data, sz + 1, stdin);
    puts("Allocated.");
}

static void cmd_set(void) {
    int idx = read_int("Index [0-15]: ");
    if (idx < 0 || idx >= MAX_STRINGS) { puts("Bad index"); return; }
    if (!table[idx].in_use)            { puts("Empty"); return; }

    printf("New content (%zu bytes max): ", table[idx].size);
    char buf[MAX_SIZE + 2] = {0};
    fgets(buf, (int)table[idx].size + 1, stdin);

    /* ── Bug aquí: str_copy hace off-by-one ── */
    str_copy(table[idx].data, buf, table[idx].size);
    puts("Updated.");
}

static void cmd_free(void) {
    int idx = read_int("Index [0-15]: ");
    if (idx < 0 || idx >= MAX_STRINGS) { puts("Bad index"); return; }
    if (!table[idx].in_use)            { puts("Empty"); return; }

    free(table[idx].data);
    table[idx].data   = NULL;
    table[idx].in_use = 0;
    table[idx].size   = 0;
    puts("Freed.");
}

static void cmd_show(void) {
    int idx = read_int("Index [0-15]: ");
    if (idx < 0 || idx >= MAX_STRINGS) { puts("Bad index"); return; }
    if (!table[idx].in_use)            { puts("Empty"); return; }
    printf("Content: %s\n", table[idx].data);
}

static void cmd_info(void) {
    for (int i = 0; i < MAX_STRINGS; i++) {
        if (table[i].in_use)
            printf("  [%2d] size=%zu ptr=%p\n", i, table[i].size, (void *)table[i].data);
    }
}

int main(void) {
    setup();
    puts("=== String Manager ===");
    puts("1) alloc  2) set  3) free  4) show  5) info  6) exit");

    for (;;) {
        int c = read_int("\n> ");
        switch (c) {
            case 1: cmd_alloc(); break;
            case 2: cmd_set();   break;
            case 3: cmd_free();  break;
            case 4: cmd_show();  break;
            case 5: cmd_info();  break;
            case 6: return 0;
            default: puts("Unknown command");
        }
    }
}
