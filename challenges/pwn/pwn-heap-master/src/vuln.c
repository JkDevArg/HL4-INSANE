/*
 * pwn-heap-master — Heap exploitation chain
 *
 * Vulnerabilidades:
 *  1. Use-After-Free: free() no nullifica el puntero
 *  2. Leak de libc via unsorted bin (chunk > 0x80 bytes no va a tcache)
 *  3. Tcache poisoning via overlapping chunks + overwrite tcache next ptr
 *  4. Arbitrary write → __malloc_hook → one_gadget
 *
 * Protecciones activas: NX, FULL RELRO, PIE, Stack Canary
 * glibc 2.35 (Ubuntu 22.04)
 *
 * Compilar:
 *   gcc -o vuln vuln.c -pie -fPIE -fstack-protector-all \
 *       -Wl,-z,relro,-z,now -no-plt
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_NOTES 16
#define NOTE_SMALL 0x38   /* fits in tcache bin 0x40 */
#define NOTE_LARGE 0x88   /* fits in tcache bin 0x90 */

typedef struct {
    char  *data;
    size_t size;
    int    in_use;
} Note;

static Note notes[MAX_NOTES];

static void setup(void) {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

static void menu(void) {
    puts("\n=== Heap Notes ===");
    puts("1. Alloc note (small 0x40)");
    puts("2. Alloc note (large 0x90)");
    puts("3. Write note");
    puts("4. Read note");
    puts("5. Delete note");
    puts("6. Exit");
    printf("> ");
}

static int read_int(void) {
    char buf[16];
    if (!fgets(buf, sizeof(buf), stdin)) exit(0);
    return atoi(buf);
}

static int get_idx(void) {
    printf("Note index [0-%d]: ", MAX_NOTES - 1);
    int idx = read_int();
    if (idx < 0 || idx >= MAX_NOTES) {
        puts("Invalid index.");
        return -1;
    }
    return idx;
}

static void do_alloc(size_t chunk_size) {
    int idx = -1;
    for (int i = 0; i < MAX_NOTES; i++) {
        if (!notes[i].in_use) { idx = i; break; }
    }
    if (idx < 0) { puts("No free slots."); return; }

    notes[idx].data   = malloc(chunk_size);
    notes[idx].size   = chunk_size;
    notes[idx].in_use = 1;
    memset(notes[idx].data, 0, chunk_size);
    printf("Allocated note %d (size=0x%zx)\n", idx, chunk_size);
}

static void do_write(void) {
    int idx = get_idx();
    if (idx < 0) return;

    /* BUG: no comprueba in_use → UAF write si el slot fue liberado */
    if (!notes[idx].data) { puts("Null pointer."); return; }

    printf("Data (max %zu bytes): ", notes[idx].size);
    if (fgets(notes[idx].data, notes[idx].size, stdin) == NULL) exit(0);
    /* strip newline */
    size_t l = strlen(notes[idx].data);
    if (l > 0 && notes[idx].data[l-1] == '\n') notes[idx].data[l-1] = '\0';
}

static void do_read(void) {
    int idx = get_idx();
    if (idx < 0) return;

    /* BUG: no comprueba in_use → UAF read si el slot fue liberado */
    if (!notes[idx].data) { puts("Empty."); return; }

    printf("Note %d: ", idx);
    /* Print raw bytes (may include heap metadata = leak) */
    for (size_t i = 0; i < notes[idx].size; i++) {
        unsigned char c = (unsigned char)notes[idx].data[i];
        if (c >= 0x20 && c < 0x7f)
            putchar(c);
        else
            printf("\\x%02x", c);
    }
    putchar('\n');
}

static void do_delete(void) {
    int idx = get_idx();
    if (idx < 0) return;

    if (!notes[idx].in_use) { puts("Already free."); return; }

    free(notes[idx].data);
    /* BUG: puntero NO nullificado → UAF en do_write / do_read */
    notes[idx].in_use = 0;
    printf("Deleted note %d.\n", idx);
}

int main(void) {
    setup();
    puts("Heap Notes Service v1.0");
    puts("Bug reports: /dev/null");

    while (1) {
        menu();
        int choice = read_int();
        switch (choice) {
            case 1: do_alloc(NOTE_SMALL); break;
            case 2: do_alloc(NOTE_LARGE); break;
            case 3: do_write(); break;
            case 4: do_read(); break;
            case 5: do_delete(); break;
            case 6: exit(0);
            default: puts("Unknown option.");
        }
    }
}
