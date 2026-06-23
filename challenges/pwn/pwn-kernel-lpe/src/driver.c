/*
 * Simulated kernel driver with a buffer overflow in its ioctl handler.
 * Runs as root (uid=0). Flag is in /root/flag.txt.
 *
 * Protocol (binary):
 *   Client sends:  struct ioctl_req { uint32_t cmd; uint32_t len; char data[]; }
 *   Server reads data into a 256-byte kernel_buf, then calls callback()
 *
 * cmd values:
 *   0x01 = IOCTL_WRITE  -> memcpy(kernel_buf, data, len)  [NO BOUNDS CHECK]
 *   0x02 = IOCTL_READ   -> write(STDOUT, kernel_buf, 256)
 *   0x03 = IOCTL_STATUS -> print driver status
 *   0x04 = IOCTL_EXEC   -> call callback function pointer
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/personality.h>

/* Disable ASLR for this process */
void disable_aslr() {
    if (personality(ADDR_NO_RANDOMIZE) == -1) {
        /* ignore failure in some container environments */
    }
}

#pragma pack(1)
typedef struct {
    uint32_t cmd;
    uint32_t len;
} ioctl_hdr_t;

/* Kernel driver state — lives in BSS (fixed address, no PIE, no ASLR) */
static struct {
    char kernel_buf[256];           /* offset +0   */
    void (*callback)(void);         /* offset +256 */
    uint64_t magic;                 /* offset +264 */
} driver_state;

void default_callback(void) {
    puts("[driver] default callback executed");
}

void debug_info(void) {
    printf("[driver] kernel_buf addr:  %p\n", (void*)driver_state.kernel_buf);
    printf("[driver] callback addr:    %p\n", (void*)&driver_state.callback);
    printf("[driver] default_callback: %p\n", (void*)default_callback);
}

/* Called when player gains control — reads flag as root */
void give_flag(void) {
    puts("[DRIVER] *** Privilege escalation detected! Dumping flag: ***");
    FILE *f = fopen("/root/flag.txt", "r");
    if (!f) { puts("[DRIVER] flag file not found"); return; }
    char buf[256];
    while (fgets(buf, sizeof(buf), f)) printf("%s", buf);
    fclose(f);
}

void handle_client(void) {
    disable_aslr();

    driver_state.callback = default_callback;
    driver_state.magic    = 0xdeadbeefcafebabe;

    puts("[driver] KernelDrv v1.0 loaded");
    debug_info();

    ioctl_hdr_t hdr;
    char tmp[512];

    while (1) {
        /* Read header */
        ssize_t n = read(STDIN_FILENO, &hdr, sizeof(hdr));
        if (n <= 0) break;

        switch (hdr.cmd) {
            case 0x01: /* IOCTL_WRITE — buffer overflow here */
                if (hdr.len > sizeof(tmp)) hdr.len = sizeof(tmp);
                n = read(STDIN_FILENO, tmp, hdr.len);
                /* BUG: copies hdr.len bytes into 256-byte kernel_buf — overflow */
                memcpy(driver_state.kernel_buf, tmp, hdr.len);
                printf("[driver] wrote %u bytes to kernel_buf\n", hdr.len);
                break;

            case 0x02: /* IOCTL_READ */
                write(STDOUT_FILENO, driver_state.kernel_buf, 256);
                break;

            case 0x03: /* IOCTL_STATUS */
                debug_info();
                break;

            case 0x04: /* IOCTL_EXEC — call the callback */
                puts("[driver] executing callback...");
                driver_state.callback();
                break;

            default:
                puts("[driver] unknown command");
        }
    }
}

int main(void) {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    handle_client();
    return 0;
}
