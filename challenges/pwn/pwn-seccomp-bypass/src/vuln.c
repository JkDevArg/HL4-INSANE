#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <seccomp.h>

void setup_seccomp() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx) { perror("seccomp_init"); exit(1); }

    /* Allow: read, write, open, openat, exit, exit_group, fstat, close */
    /* Also allow: brk, mmap, mprotect (for static binary heap/stack) */
    int allowed[] = {
        SCMP_SYS(read),    SCMP_SYS(write),   SCMP_SYS(open),
        SCMP_SYS(openat),  SCMP_SYS(close),   SCMP_SYS(fstat),
        SCMP_SYS(exit),    SCMP_SYS(exit_group),
        SCMP_SYS(brk),     SCMP_SYS(mmap),    SCMP_SYS(mprotect),
        SCMP_SYS(lseek),   SCMP_SYS(pread64),
    };

    /* Block: execve, execveat, fork, clone, socket, connect, bind */
    /* These are blocked by not being in the allowlist (SCMP_ACT_KILL) */

    for (size_t i = 0; i < sizeof(allowed)/sizeof(allowed[0]); i++) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, allowed[i], 0) < 0) {
            perror("seccomp_rule_add"); exit(1);
        }
    }

    if (seccomp_load(ctx) < 0) { perror("seccomp_load"); exit(1); }
    seccomp_release(ctx);
}

void vuln() {
    char buf[128];
    printf("Enter command: ");
    /* BUG: reads 512 bytes into 128-byte buffer — stack overflow */
    read(STDIN_FILENO, buf, 512);
    printf("Got: %s\n", buf);
}

int main() {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    puts("=== Secure Service v1.0 ===");
    puts("Note: This service uses seccomp to block dangerous syscalls.");
    printf("[info] text base: %p\n", (void*)main);

    setup_seccomp();
    vuln();
    return 0;
}
