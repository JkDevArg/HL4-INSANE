#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void setup() {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

void win() {
    system("cat /home/ctf/flag.txt");
}

/* Filtered printf: blocks %n but allows %p */
void safe_printf(const char *fmt) {
    /* Filter: reject any format string containing %n */
    if (strstr(fmt, "%n") || strstr(fmt, "%N")) {
        puts("[security] format string write rejected!");
        return;
    }
    printf(fmt);
    printf("\n");
}

void interact() {
    char buf[64];
    char overflow_buf[64];
    int rounds = 5;

    printf("[info] win=%p\n", (void*)win);
    puts("You have 5 format string reads, then one overflow.");

    while (rounds-- > 0) {
        printf("[%d] fmt> ", rounds + 1);
        fgets(buf, sizeof(buf), stdin);
        buf[strcspn(buf, "\n")] = '\0';
        safe_printf(buf);
    }

    printf("Now, overflow: ");
    /* BUG: reads 144 bytes into 64-byte buffer — 80-byte overflow */
    /* Stack: [overflow_buf: 64][canary: 8][rbp: 8][rip: 8] = 88 bytes to rip */
    read(STDIN_FILENO, overflow_buf, 144);
    puts("Thanks!");
}

int main() {
    setup();
    interact();
    return 0;
}
