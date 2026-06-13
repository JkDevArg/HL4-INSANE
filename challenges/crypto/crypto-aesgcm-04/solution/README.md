# Solución — crypto-aesgcm-04 · Nonce Reuse Roulette

**Categoría:** crypto · **Dificultad:** insane · **Vuln central:** reuso de nonce en AES-GCM → recuperación de la clave de autenticación `H` y **forja de tags**.

## Resumen

VaultGCM "firma" comandos con AES-GCM, pero **reusa siempre el mismo nonce**.
Ofrece un oráculo `encrypt <hex>` que devuelve `nonce||ct||tag`. El objetivo es
ejecutar el comando admin `{"action":"reveal_flag","role":"admin"}`: hay que
enviar `command <ct> <tag>` con un **tag GCM válido** para ese plaintext. El
servidor entrega la flag solo si el tag valida y el plaintext es el admin.

## Fundamento

En GCM, con `H = E_K(0^128)` y `S = E_K(J0)` (J0 depende solo del nonce):

```
T = GHASH_H(C) XOR S
GHASH_H(C) = sum_{i=1}^{n} b_i * H^(n-i+1)     (b_i = bloques de ct + bloque de longitud)
```

Si el **nonce se reusa**, `S` y el bloque de longitud (a igual largo) son
constantes. Con dos cifrados `(C_a,T_a)` y `(C_b,T_b)` del mismo largo bajo el
mismo nonce:

```
T_a XOR T_b = sum_i (a_i XOR b_i) * H^(n-i+1)
```

Eso es un **polinomio en H sobre GF(2^128)** igualado a `T_a XOR T_b`. Sus
raíces son candidatos a `H`. Recuperado `H`, se despeja `S = T_a XOR GHASH_H(C_a)`
y ya se puede **forjar el tag de cualquier ciphertext**:

```
T_forjado = GHASH_H(C_objetivo) XOR S
```

Como el keystream también se repite (mismo nonce), el ciphertext del comando
admin se obtiene con `C_obj = P_obj XOR keystream`, donde
`keystream = C_a XOR P_a` (de un `encrypt` de plaintext conocido).

## Pasos

1. Leer el `PLAINTEXT_OBJETIVO` del banner.
2. `encrypt AA..` y `encrypt BB..` (mismo largo en bloques que el objetivo) →
   dos `(ct, tag)` bajo el mismo nonce.
3. Construir el polinomio diferencia en `H` y hallar sus raíces en GF(2^128)
   (aislar raíces con `gcd(poly, x^(2^128)-x)` + Cantor-Zassenhaus).
4. Para cada candidato `H`: despejar `S`, calcular `C_obj` (keystream conocido)
   y `T_forjado = GHASH_H(C_obj) XOR S`.
5. `command <C_obj_hex> <T_forjado_hex>` → si `H` era correcto, el tag valida y
   el servidor responde `FLAG ...`.

Exploit completo (aritmética GF(2^128) + GHASH + root-finding + forja):
`solution/exploit.py <host> 9999`. Verificado de extremo a extremo contra el
servicio real (recupera `H`, forja el tag y obtiene la flag).

## Por qué es INSANE

- No es "descifra con la clave": exige modelar GCM como polinomio en GF(2^128),
  implementar la aritmética del campo (multiplicación, inverso, gcd de
  polinomios, factorización) y la **forja** de tags.
- El ataque entrega varios candidatos a `H`; hay que probar cada uno forjando
  un tag real contra el servicio.

## Mitigaciones (didáctico)

- **Nunca reusar el nonce** con la misma clave en GCM (usar nonce aleatorio de
  96 bits con contador, o cifrado nonce-misuse-resistant como AES-GCM-SIV).
- Rotar claves; límites estrictos de mensajes por clave.
- No exponer un oráculo de cifrado que devuelva tag bajo nonce fijo.

## Nota anti-cheat

El reto se **sirve por red** (`nc host 9999`): no hay binario descargable que
analizar offline o compartir. La **clave AES y el nonce son aleatorios por
instancia**, así que `H` y `S` difieren por equipo: el método no transfiere la
respuesta, cada equipo debe recuperar SU `H` y forjar contra SU servicio. La
flag es **dinámica y única por equipo** (HMAC del flag-service, `ARCHITECTURE
§4`), inyectada por env `FLAG`. Enviar la flag de otro equipo dispara
`cheat_flag_share` (`/whose-flag`). El segundo `encrypt` bajo el mismo nonce y
la forja del comando admin emiten eventos SIEM (`scan_detected` alert/critical)
al collector.
