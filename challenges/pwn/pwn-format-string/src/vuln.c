#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void setup() {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void win() {
    system("cat /home/ctf/flag.txt");
}

void log_message() {
    char buf[256];
    printf("Enter log message: ");
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\n")] = '\0';

    printf("=== LOG === ");
    printf(buf);   /* BUG: format string vulnerability */
    printf(" ===\n");

    /* After logging, we call malloc — useful for __malloc_hook trigger */
    void *p = malloc(8);
    free(p);
}

int main() {
    setup();
    puts("=== Logger v1.0 ===");
    /* Helpful leak: print win() address so players can compute PIE base */
    printf("[debug] win=%p\n", (void*)win);

    int rounds = 3;
    while (rounds-- > 0) {
        log_message();
    }

    puts("Logging complete.");
    return 0;
}
