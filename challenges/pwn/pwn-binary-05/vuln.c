/*
 * ColdVault Firmware — pwn-binary-05 (PWN INSANE, binario clásico en C)
 * ============================================================================
 *
 * Firmware de una "bóveda de almacenamiento en frío" (cold storage) para
 * dispositivos IoT custodios de claves/seed. El dispositivo expone una consola
 * de mantenimiento por puerto serie (aquí, por stdin/stdout, puenteado a TCP
 * 9999 por el wrapper Python). Un operador puede consultar el estado, registrar
 * una etiqueta de inventario y "diagnosticar" el firmware.
 *
 * VULNERABILIDADES (white-box: el source se entrega en solution/):
 *
 *   1) FORMAT STRING  (cmd `diag <texto>`):
 *        printf(user_input)   <-- el texto del operador se usa como formato.
 *      Permite filtrar memoria del stack: con `%p` se leen el CANARIO de stack
 *      y un puntero de código (de donde se deriva la BASE PIE).
 *
 *   2) STACK BUFFER OVERFLOW  (cmd `label <texto>`):
 *        char name[64]; ... read()/copia sin límite real -> se desborda el
 *      buffer, machacando el canario, el saved RBP y la dirección de retorno.
 *
 * MITIGACIONES PRESENTES (hay que bypassearlas; ver solution/README.md):
 *   - Stack canary (-fstack-protector-all): se filtra con la format string (1)
 *     y se vuelve a colocar intacto en el payload del overflow (2).
 *   - PIE / ASLR (-fPIE -pie): la base de código se filtra con (1); la
 *     dirección de unlock_vault() se calcula como base + offset.
 *   - NX (stack no ejecutable): no se ejecuta shellcode; se hace ret2win
 *     (return-to-function) hacia unlock_vault().
 *
 * CADENA DE EXPLOTACIÓN:  format-string leak (canary + PIE) -> stack overflow
 *                         que reescribe RIP -> ret2win a unlock_vault().
 *
 * La FLAG se lee de la variable de entorno FLAG y SÓLO se imprime al alcanzar
 * unlock_vault(). El binario es idéntico para todos los equipos; la flag es
 * por-equipo (env), así que compartir el binario NO filtra la flag.
 *
 * Referencias a fallos reales de firmware que costaron millones:
 *   - Stack overflows en firmware de wallets HW y dispositivos IoT (CVE-2018-
 *     varios en routers/cámaras; el "Mirai" se apoyó en credenciales+overflows).
 *   - Format strings en firmware embebido (clase CWE-134), recurrentes en
 *     dispositivos de red y SCADA.
 *
 * Compilación (ver Dockerfile):
 *   gcc -O0 -fno-omit-frame-pointer -fstack-protector-all -fPIE -pie \
 *       -Wl,-z,relro,-z,now -Wl,-z,noexecstack -o coldvault vuln.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FW_VERSION "ColdVault FW 3.1.7-iot"

/* Tamaño "documentado" del buffer de etiqueta de inventario. */
#define LABEL_SIZE 64

static void banner(void)
{
    puts("=========================================");
    puts(" ColdVault(tm) Cold Storage Vault");
    puts(" " FW_VERSION);
    puts(" Maintenance console (serial bridge)");
    puts("=========================================");
    puts("Commands:");
    puts("  status         - show vault status");
    puts("  diag <text>    - run self-diagnostic (echoes text)");
    puts("  label <text>   - set inventory label");
    puts("  help           - show this help");
    puts("  exit           - close session");
    fflush(stdout);
}

/*
 * unlock_vault() — FUNCIÓN GANADORA (ret2win).
 * No es alcanzable por el flujo normal de la consola: sólo se llega aquí
 * secuestrando la dirección de retorno. Imprime la flag leída de env FLAG.
 */
static void unlock_vault(void)
{
    const char *flag = getenv("FLAG");
    puts("");
    puts("[!!!] COLD VAULT UNLOCKED — emergency master key released");
    if (flag && *flag) {
        printf("[FLAG] %s\n", flag);
    } else {
        puts("[FLAG] flag{NO_FLAG_IN_ENV}");
    }
    fflush(stdout);
    /* Salida limpia para no disparar el __stack_chk_fail del frame previo. */
    _exit(0);
}

static void show_status(void)
{
    puts("[status] temperature : -18.0 C  (nominal)");
    puts("[status] tamper       : sealed");
    puts("[status] vault state  : LOCKED");
    puts("[status] keyslots     : 0/8 unlocked");
    fflush(stdout);
}

/*
 * VULN #1 — FORMAT STRING.
 * El texto del operador se pasa DIRECTAMENTE como cadena de formato a printf.
 * Con `%p`/`%lx` se filtra el stack (canario y punteros de código).
 */
static void run_diag(const char *user_text)
{
    printf("[diag] self-test report for input: ");
    printf(user_text);          /* <-- CWE-134: format string controlada */
    printf("\n[diag] subsystems: OK\n");
    fflush(stdout);
}

/*
 * VULN #2 — STACK BUFFER OVERFLOW.
 * `name` mide 64 bytes pero copiamos `len` bytes desde la entrada del operador
 * (len lo fija la longitud LEÍDA del puerto serie, hasta 512), sin recortar al
 * tamaño del buffer destino: se desborda y se machaca canario / saved RBP / RIP.
 *
 * Nota de diseño: la copia es por LONGITUD (memcpy con `len`), NO por cadena
 * (nada de strlen), así que el payload PUEDE contener bytes NUL — necesario
 * para reescribir el canario (acaba en 0x00) y direcciones PIE/stack.
 */
static void set_label(const char *src, size_t len)
{
    char name[LABEL_SIZE];
    /* "Copia segura"... pero el límite es el tamaño de la ENTRADA recibida, no
     * el del buffer destino. Clásico off-by-design de firmware embebido. */
    memcpy(name, src, len);     /* <-- desbordamiento si len > LABEL_SIZE */
    printf("[label] inventory label set to: %.*s\n", (int)len, name);
    fflush(stdout);
}

/*
 * Lee una línea de stdin (entrada del operador / socket puenteado).
 * Devuelve el número de bytes leídos (sin el '\n'), o -1 en EOF.
 * Lee hasta 512 bytes: deliberadamente mayor que LABEL_SIZE para permitir el
 * overflow determinista en set_label().
 */
static long read_line(char *buf, size_t cap)
{
    size_t i = 0;
    while (i < cap - 1) {
        char c;
        ssize_t r = read(STDIN_FILENO, &c, 1);
        if (r <= 0) {
            if (i == 0) return -1;
            break;
        }
        if (c == '\n') break;
        buf[i++] = c;
    }
    buf[i] = '\0';
    /* Quita un posible CR final (clientes que mandan CRLF). */
    if (i > 0 && buf[i - 1] == '\r') buf[--i] = '\0';
    return (long)i;
}

int main(void)
{
    char line[512];

    /* Entrada/salida sin buffer para que el puente TCP sea fluido. */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    banner();

    for (;;) {
        long n = read_line(line, sizeof(line));
        if (n < 0) break;                 /* EOF */
        if (n == 0) continue;

        if (strcmp(line, "exit") == 0 || strcmp(line, "quit") == 0) {
            puts("[*] session closed");
            fflush(stdout);
            break;
        } else if (strcmp(line, "help") == 0) {
            banner();
        } else if (strcmp(line, "status") == 0) {
            show_status();
        } else if (strncmp(line, "diag ", 5) == 0) {
            run_diag(line + 5);           /* VULN #1 */
        } else if (strcmp(line, "diag") == 0) {
            run_diag("");
        } else if (strncmp(line, "label ", 6) == 0) {
            /* Pasamos la longitud REAL leída (n) menos el prefijo "label ".
             * Esto permite payloads con bytes NUL (canario, direcciones). */
            set_label(line + 6, (size_t)n - 6);   /* VULN #2 */
        } else if (strcmp(line, "label") == 0) {
            set_label("", 0);
        } else {
            printf("[err] unknown command: %s\n", line);
            fflush(stdout);
        }
    }
    return 0;
}
