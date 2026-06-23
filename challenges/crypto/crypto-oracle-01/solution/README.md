# Solución — crypto-oracle-01 · Padding Confessions

**Categoría:** crypto · **Dificultad:** insane · **Vuln central:** Padding Oracle sobre AES-CBC + PKCS#7.

## Resumen

SecureVault cifra la flag con AES-128-CBC (IV aleatorio, prepended) y entrega
el token `iv||ct` en hex. El comando `decrypt <hex>` responde `OK` si el padding
PKCS#7 es válido tras descifrar, y `BAD_PADDING` si no. Esa diferencia es un
**oráculo de padding**: permite recuperar el plaintext **sin conocer la clave**.

## Fundamento

En CBC: `P_i = D_K(C_i) XOR C_{i-1}`. Si controlamos `C_{i-1}` (bloque previo) y
observamos si el padding del último bloque es válido, podemos recuperar
`D_K(C_i)` byte a byte:

- Forzamos que el último byte descifrado sea `0x01` (padding válido de 1):
  probando los 256 valores del byte correspondiente de `C_{i-1}'`. Cuando da
  `OK`, sabemos `D_K(C_i)[15] = C_{i-1}'[15] XOR 0x01`.
- Con `D_K(C_i)[15]` conocido, fijamos el padding a `0x02 0x02` y atacamos el
  byte 14, etc., hasta los 16 bytes del bloque intermedio.
- El plaintext real es `D_K(C_i) XOR C_{i-1}` (el `C_{i-1}` **original**).

Se repite por cada bloque de ciphertext usando su bloque anterior real (el IV
es el "bloque anterior" del primer bloque de ct).

## Ejecución

```sh
python solution/exploit.py <host> 9999
# [+] bloque 1: b'HL4{EJEMPLO}\x03\x03\x03'
# [*] FLAG: HL4{EJEMPLO}
```

El script (`solution/exploit.py`) maneja el falso positivo clásico en `pad=1`
(donde el byte podría completar un padding mayor) mutando el byte anterior y
re-consultando.

## Por qué es INSANE

- Requiere entender la estructura de CBC y construir el ataque byte-a-byte
  (no es un "descifra con la clave que te di").
- Miles de consultas al oráculo, manejo de bloques e IV, y el caso borde de
  `pad=1`.

## Mitigaciones (didáctico)

- Usar cifrado autenticado (AES-GCM) o Encrypt-then-MAC; verificar el MAC
  **antes** de descifrar.
- No revelar la causa del fallo (padding vs MAC); respuesta y timing uniformes.

## Nota anti-cheat

El reto se **sirve por red** (`nc host 9999`): no hay binario descargable que
analizar offline o compartir como artefacto. La clave AES es **aleatoria por
instancia** y la flag es **dinámica y única por equipo** (HMAC del flag-service,
`ARCHITECTURE §4`, inyectada por env `FLAG`). Cada equipo debe ejecutar el
ataque contra **su** servicio para obtener **su** flag; enviar la de otro equipo
dispara `cheat_flag_share` (`/whose-flag`). El abuso del oráculo (cientos de
consultas) emite un evento SIEM `scan_detected`/`alert` al collector.
