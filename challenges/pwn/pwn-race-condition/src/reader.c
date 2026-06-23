/*
 * File reader with TOCTOU vulnerability.
 * Runs as root (setuid). Players connect as ctf user.
 *
 * Vulnerability: access() uses real UID (ctf), fopen() uses effective UID (root).
 * Window enlarged with sleep(2) between them.
 * Race: create /tmp/myfile, pass it to reader, then symlink /tmp/myfile -> /root/flag.txt
 * before fopen() is called.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

int main() {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    puts("=== Secure File Reader v1.0 ===");
    puts("Note: Only files readable by YOU can be accessed.");
    printf("Enter file path: ");

    char path[512];
    if (fgets(path, sizeof(path), stdin) == NULL) return 1;
    path[strcspn(path, "\n")] = '\0';

    /* TOCTOU step 1: check with real UID */
    if (access(path, R_OK) != 0) {
        fprintf(stderr, "Access denied: %s\n", strerror(errno));
        return 1;
    }

    printf("Checking permissions... (this takes a moment)\n");
    fflush(stdout);

    /* BUG: race window — sleep between check and open */
    sleep(2);

    /* TOCTOU step 2: open with effective UID (root) */
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Failed to open: %s\n", strerror(errno));
        return 1;
    }

    char buf[4096];
    size_t n;
    puts("=== File Contents ===");
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        fwrite(buf, 1, n, stdout);
    }
    puts("=== End ===");
    fclose(f);
    return 0;
}
