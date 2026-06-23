#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void setup() {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

/* Hidden win function — used to build ROP gadgets */
void win() {
    system("cat /home/ctf/flag.txt");
}

void authenticate() {
    char buf[64];
    char large[256];

    puts("=== Auth Server v2 ===");
    printf("Username: ");
    /* BUG 1: format string — leaks stack values (canary, saved rbp, ret addr) */
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\n")] = '\0';
    printf(buf);   /* <-- format string vulnerability */
    printf("\n");

    printf("Password: ");
    /* BUG 2: reads 512 bytes into 256-byte buffer — stack buffer overflow */
    read(STDIN_FILENO, large, 512);

    puts("Access denied.");
}

int main() {
    setup();
    /* Print puts() address so players can calculate libc even without PIE */
    printf("[info] server at: %p\n", (void*)win);
    authenticate();
    return 0;
}
