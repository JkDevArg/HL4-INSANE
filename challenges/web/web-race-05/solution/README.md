# Solución — web-race-05 · Double Spend

**Categoría:** web · **Dificultad:** insane · **Puntos:** 600 · **Vuln central:** condición de carrera **TOCTOU** (Time-of-Check Time-of-Use) en un read-modify-write NO atómico del flujo de canje de cupones.

## Resumen

"Coin Vault" es un canjeador de cupones. Cada sesión (cookie `vault_sid` -> fila
propia en SQLite) arranca con **5 cupones**. Cada canje en `/redeem` gasta 1
cupón y acredita **20 coins**, así que el máximo **en serie** es
`5 * 20 = 100 coins`. La cámara del tesoro `/treasure` solo abre con
**más de 200 coins** -> inalcanzable jugando limpio.

El truco: el canje **no es atómico**. Disparando muchas peticiones concurrentes
se gasta el mismo cupón varias veces (**double spend**), el saldo de coins sube
por encima del máximo teórico y `/treasure` suelta la flag.

## La vulnerabilidad (TOCTOU)

`/redeem` ejecuta un **read-modify-write** contra SQLite en autocommit, **sin
transacción ni lock**, con una **ventana real** en medio:

```
(1) CHECK : SELECT coupons, coins FROM vault WHERE sid=?     <- time-of-check
(2) GAP   : new_coupons = coupons-1 ; new_coins = coins+20   <- calculado sobre el snapshot
            time.sleep(RACE_WINDOW)                          <- ventana de carrera (~120 ms)
(3) USE   : UPDATE vault SET coupons=new_coupons,            <- time-of-use
            coins=new_coins WHERE sid=?
```

El descuento del paso (3) se escribe a partir del **snapshot leído en (1)**, no
del estado actual de la fila, y el `UPDATE` **no tiene condición** (`WHERE
coupons>0`) ni decremento atómico. Resultado: N peticiones concurrentes que
entran a la vez en la ventana **todas** leen `coupons>=1`, **todas** pasan el
check y **todas** escriben `coins = (su snapshot) + 20`. El último `UPDATE` que
ejecuta gana, pero como todos partieron del mismo `coins` bajo y todos suman,
los `+20` se acumulan mientras los `coupons` apenas bajan (cada hilo escribe
`coupons-1` calculado sobre el mismo snapshot). En la práctica un solo cupón se
"gasta" muchas veces -> **double spend**.

## Cadena de explotación

1. Cargar `/balance` y guardar la cookie de sesión (recurso compartido).
2. Lanzar una **ráfaga de `/redeem` concurrentes** (hilos / HTTP en paralelo)
   reutilizando la **misma cookie** -> todas pegan a la misma fila.
3. Repetir un par de rondas; cada ronda suma muchos `+20` gastando pocos cupones.
4. Cuando `coins > 200`, pedir `GET /treasure` -> la flag llega en el campo `flag`.

Exploit automatizado: `python solution/exploit.py http://<host>:8080`
(30 hilos por ronda, hasta 4 rondas; sube `BURST`/`ROUNDS` si la red es lenta).

## Por qué es INSANE

- No es un bug de lógica visible en el código del cliente: requiere **entender
  el TOCTOU** y que el check y el descuento ocurren en operaciones SQLite
  separadas sin atomicidad.
- Requiere **concurrencia real** (hilos / pipelining): un cliente secuencial
  nunca solapa peticiones dentro de la ventana y jamás pasa de 100 coins.
- La ventana es genuina pero acotada (~120 ms): explotable con una ráfaga
  normal, pero hay que ganarle a la carrera, no es determinista al 100% en una
  sola petición (de ahí las rondas).

## Por qué un lock / transacción lo arregla

La carrera vive **exactamente** en el hueco entre leer y escribir. Cualquiera de
estas correcciones lo cierra:

- **Decremento atómico condicional** (sin leer-luego-escribir):
  ```sql
  UPDATE vault SET coupons = coupons - 1, coins = coins + 20
   WHERE sid = ? AND coupons > 0;
  ```
  El motor evalúa `coupons > 0` y decrementa en **una sola operación atómica**;
  `rowcount == 0` significa "sin cupones". Solo una de las concurrentes con el
  último cupón tendría efecto.
- **Transacción serializable / `BEGIN IMMEDIATE`** alrededor del check+update,
  de modo que el read y el write sean indivisibles frente a otras conexiones.
- **Lock por sesión** (mutex por `sid`) que serialice los canjes de una misma
  bóveda.

Con cualquiera de ellas, de las N peticiones concurrentes **solo una** gana el
cupón; el resto ve `coupons=0` y es rechazada. El máximo vuelve a ser 100 coins
y `/treasure` jamás abre.

## Mitigaciones (didáctico)

- No hacer read-modify-write de saldos en pasos separados: usar UPDATE atómico
  condicional o transacción con el nivel de aislamiento adecuado.
- Validar la invariante en el `WHERE`/constraint, no solo en código de aplicación
  (`CHECK(coupons >= 0)`).
- Idempotencia / token de canje de un solo uso por operación para que reintentos
  o ráfagas no se contabilicen dos veces.

## Nota anti-cheat

La flag es **dinámica y única por equipo** (HMAC del flag-service,
`ARCHITECTURE §4`), inyectada por env `FLAG` en la instancia del equipo. El
servicio **no publica puertos al host**: solo es alcanzable por la VPN del
propio equipo en `172.30.{N}.15:8080`. El estado del vault está aislado **por
sesión** (cookie `vault_sid`) y la flag solo se entrega contra **tu** propia
bóveda tras un double-spend real, así que compartir la técnica no da puntos:
cada equipo debe correr la carrera contra SU instancia. Enviar la flag de otro
equipo dispara `cheat_flag_share` (`/whose-flag`). El éxito del exploit emite el
evento SIEM `challenge_solved` (alert) al collector con el saldo de coins
imposible-en-serie como evidencia del double-spend.
