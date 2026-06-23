#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_NOTES 10

typedef struct {
    size_t size;
    char *data;
} Note;

Note notes[MAX_NOTES];

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void menu() {
    puts("\n=== Note Manager ===");
    puts("1. Create note");
    puts("2. Edit note");
    puts("3. Delete note");
    puts("4. Show note");
    puts("5. Exit");
    printf("> ");
}

int get_idx() {
    int idx;
    printf("Index [0-9]: ");
    scanf("%d", &idx);
    getchar();
    return idx;
}

void create_note() {
    int idx = get_idx();
    if (idx < 0 || idx >= MAX_NOTES) { puts("Invalid index"); return; }
    if (notes[idx].data != NULL) { puts("Slot in use"); return; }
    size_t sz;
    printf("Size: ");
    scanf("%zu", &sz);
    getchar();
    if (sz == 0 || sz > 0x400) { puts("Invalid size"); return; }
    notes[idx].data = (char*)malloc(sz);
    if (!notes[idx].data) { puts("Malloc failed"); return; }
    notes[idx].size = sz;
    printf("Content: ");
    fgets(notes[idx].data, sz, stdin);
    puts("Created!");
}

void edit_note() {
    int idx = get_idx();
    if (idx < 0 || idx >= MAX_NOTES) { puts("Invalid index"); return; }
    /* BUG: no NULL check — UAF write possible on freed chunk */
    if (notes[idx].size == 0) { puts("Note not found"); return; }
    printf("New content (reading %zu bytes): ", notes[idx].size + 8);
    /* BUG: heap overflow of 8 bytes — overwrites next chunk metadata */
    read(STDIN_FILENO, notes[idx].data, notes[idx].size + 8);
    puts("Updated!");
}

void delete_note() {
    int idx = get_idx();
    if (idx < 0 || idx >= MAX_NOTES) { puts("Invalid index"); return; }
    if (notes[idx].data == NULL) { puts("Note not found"); return; }
    free(notes[idx].data);
    /* BUG: pointer not nulled — UAF read/write possible */
    notes[idx].size = 0;
    puts("Deleted!");
}

void show_note() {
    int idx = get_idx();
    if (idx < 0 || idx >= MAX_NOTES) { puts("Invalid index"); return; }
    if (notes[idx].data == NULL) { puts("Note not found"); return; }
    printf("Content: ");
    /* BUG: UAF read — reads from freed chunk, leaks tcache fd pointer */
    fwrite(notes[idx].data, 1, 0x40, stdout);
    puts("");
}

int main() {
    setup();
    puts("Welcome to Note Manager v1.0");
    /* Libc leak: print puts() address to help players find libc base */
    printf("[debug] libc@puts: %p\n", (void*)puts);

    while (1) {
        menu();
        int choice;
        if (scanf("%d", &choice) != 1) break;
        getchar();
        switch (choice) {
            case 1: create_note(); break;
            case 2: edit_note(); break;
            case 3: delete_note(); break;
            case 4: show_note(); break;
            case 5: exit(0);
            default: puts("Invalid choice");
        }
    }
    return 0;
}
