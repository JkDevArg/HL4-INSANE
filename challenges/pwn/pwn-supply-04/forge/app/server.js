/*
 * Forgewright CI — pwn-supply-04 ("Poisoned Pipeline").  PWN · INSANE.
 *
 * ESCENARIO (cadena de suministro / supply chain):
 *   Forgewright es un vendor de software que vende una libreria interna,
 *   @forge/logger, a sus clientes. Su CI "forge-runner" reconstruye builds de
 *   clientes: el cliente sube un manifiesto (package.json) y, opcionalmente, un
 *   lockfile (package-lock.json); el runner ejecuta `npm install` en lo que
 *   CREE que es un sandbox, instalando dependencias desde el registro npm
 *   INTERNO de Forgewright (autoritativo para el scope @forge).
 *
 * VULN CENTRAL (REAL):  el runner ejecuta `npm install` SIN `--ignore-scripts`.
 *   Por tanto, los LIFECYCLE SCRIPTS de las dependencias (preinstall /
 *   install / postinstall) se EJECUTAN durante el build, dentro del runner,
 *   con el entorno del runner — que contiene el secreto de CI (FLAG).
 *
 *   El registro interno permite PUBLICAR sin autenticacion (anonimo). Un
 *   atacante publica una version MAYOR de @forge/logger con un `postinstall`
 *   que lee process.env.FLAG y lo imprime. El runner resuelve esa version (por
 *   semver / lockfile), corre el postinstall -> RCE en el runner -> la flag
 *   acaba en el LOG del build que el runner devuelve al cliente.
 *
 * Esto es la clase de ataque de SolarWinds / event-stream / codecov /
 * ua-parser-js: confiar en el codigo de una dependencia (y en sus install
 * scripts) que corre con los privilegios/secretos del pipeline.
 *
 * DISTINTO de web-supply-01: alli el vector era dependency-confusion sobre PyPI
 * y la exfiltracion era via `import` (codigo a nivel de modulo). AQUI el vector
 * es el LIFECYCLE SCRIPT de npm (postinstall) y/o un LOCKFILE manipulado que
 * fuerza una version/tarball maliciosa; el codigo corre en tiempo de INSTALL,
 * no de import.
 *
 * La FLAG se inyecta por equipo via env FLAG. NO esta hardcodeada.
 */
"use strict";

const http = require("http");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFile } = require("child_process");

const reqlog = require("./reqlog");
const { emit } = require("./siem");

const PORT = parseInt(process.env.PORT || "8080", 10);
const FLAG = process.env.FLAG || "flag{EJEMPLO_LOCAL}";
const REGISTRY_URL = process.env.REGISTRY_URL || "http://registry:8080";

// El paquete interno que el CI reconstruye en cada build.
const INTERNAL_SCOPE = "@forge";
const INTERNAL_PACKAGE = "@forge/logger";

// Resultados de builds (en memoria). buildId -> { id, rc, log }.
const BUILDS = {};

function indexPage() {
  return `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>Forgewright CI</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:820px;margin:40px auto;color:#0d1117;background:#f3f4f6}
 code,pre{background:#e7e9ee;padding:2px 6px;border-radius:4px;white-space:pre-wrap}
 .card{background:#fff;border:1px solid #d0d7de;border-radius:8px;padding:18px;margin:14px 0}
 h1{font-size:23px} h3{margin-top:0}
</style></head><body>
<h1>Forgewright · CI / forge-runner</h1>
<div class="card">
 <h3>Pipeline de build</h3>
 <p>Subes tu <code>package.json</code> (y opcionalmente <code>package-lock.json</code>),
    el runner instala dependencias desde el <b>registro npm interno</b> de
    Forgewright y te devuelve el <b>log del build</b>.</p>
 <pre>npm install --registry ${REGISTRY_URL}</pre>
 <p>El scope <code>@forge</code> es autoritativo en el registro interno. Toda
    librería del vendor (p.ej. <code>${INTERNAL_PACKAGE}</code>) se resuelve ahí.
    <i>(TODO seguridad: el registro permite publicar sin firma; revisar.)</i></p>
</div>
<div class="card">
 <h3>API</h3>
 <ul>
   <li><code>POST /build</code> — body JSON:
       <code>{"package.json": {...}, "package-lock.json": {...}}</code>.
       Lanza un build y devuelve <code>{build_id, rc, log}</code>.</li>
   <li><code>GET /build/&lt;id&gt;</code> — recupera el log de un build.</li>
   <li><code>GET /registry</code> — URL del registro npm interno.</li>
 </ul>
 <p>El runner ejecuta el ciclo de vida estándar de npm para validar que las
    dependencias del vendor cargan. <b>No</b> usamos <code>--ignore-scripts</code>
    para no romper paquetes con build nativo.</p>
</div>
</body></html>`;
}

function send(res, code, obj, contentType) {
  if (contentType === "html") {
    res.writeHead(code, { "Content-Type": "text/html; charset=utf-8" });
    return res.end(obj);
  }
  const body = typeof obj === "string" ? obj : JSON.stringify(obj);
  res.writeHead(code, { "Content-Type": "application/json" });
  res.end(body);
}

// --------------------------------------------------------------------------
// El build runner.
//
// 1) Escribe el package.json (y package-lock.json si se envio) del cliente en
//    un workdir temporal.
// 2) Escribe un .npmrc que delega el scope @forge al registro INTERNO y lo usa
//    como registry por defecto del build.
// 3) Ejecuta `npm install` SIN --ignore-scripts  <-- la VULN: corren los
//    lifecycle scripts (postinstall, etc.) de las dependencias resueltas, con
//    el entorno del runner (que incluye FLAG, el secreto de CI).
// 4) Devuelve el log combinado (stdout+stderr) del install.
// --------------------------------------------------------------------------
function runBuild(buildId, manifest, lockfile, cb) {
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), `build_${buildId}_`));

  // Manifiesto del cliente (o uno minimo por defecto que depende del paquete
  // interno del vendor — el caso "feliz" del CI).
  const pkgJson =
    manifest && typeof manifest === "object"
      ? manifest
      : {
          name: "customer-build",
          version: "0.0.0",
          private: true,
          dependencies: { [INTERNAL_PACKAGE]: "^1.0.0" },
        };
  fs.writeFileSync(path.join(workdir, "package.json"), JSON.stringify(pkgJson, null, 2));

  if (lockfile && typeof lockfile === "object") {
    fs.writeFileSync(
      path.join(workdir, "package-lock.json"),
      JSON.stringify(lockfile, null, 2)
    );
  }

  // .npmrc del build: el scope @forge -> registro interno; registry por defecto
  // tambien interno (asi el vendor controla la cadena... y quien publique alli).
  const npmrc =
    `@forge:registry=${REGISTRY_URL}/\n` +
    `registry=${REGISTRY_URL}/\n` +
    `//${REGISTRY_URL.replace(/^https?:\/\//, "")}/:_authToken=anon\n` +
    `audit=false\nfund=false\nupdate-notifier=false\n`;
  fs.writeFileSync(path.join(workdir, ".npmrc"), npmrc);

  const env = Object.assign({}, process.env, {
    FLAG: FLAG, // secreto de CI disponible para el runner (y sus subprocesos).
    CI: "true",
    npm_config_yes: "true",
  });

  // VULN: NO se pasa --ignore-scripts. Los lifecycle scripts corren.
  // --foreground-scripts: el CI captura el stdout/stderr de los scripts en el
  // log del build (para visibilidad de builds nativos). Es justo lo que hace
  // que la salida del postinstall malicioso aparezca en el log devuelto.
  // (timeout amplio: el install puede tardar; output limitado por -8KB al final)
  const args = [
    "install",
    "--no-audit",
    "--no-fund",
    "--foreground-scripts",
    "--loglevel",
    "info",
  ];

  const header = `$ npm ${args.join(" ")}  (registry=${REGISTRY_URL})`;
  execFile(
    "npm",
    args,
    { cwd: workdir, env, timeout: 120000, maxBuffer: 8 * 1024 * 1024 },
    (err, stdout, stderr) => {
      const rc = err && typeof err.code === "number" ? err.code : err ? 1 : 0;
      const log = [header, stdout || "", stderr || ""]
        .filter(Boolean)
        .join("\n")
        .slice(-8000);
      cb({ id: buildId, rc, log });
    }
  );
}

const server = http.createServer((req, res) => {
  // reqlog middleware: buffea body crudo + emite linea CTFREQ, luego enruta.
  reqlog.middleware(req, res, () => route(req, res));
});

function route(req, res) {
  const urlPath = req.url.split("?")[0];

  if (req.method === "GET" && urlPath === "/health") {
    return send(res, 200, { status: "ok" });
  }
  if (req.method === "GET" && urlPath === "/") {
    return send(res, 200, indexPage(), "html");
  }
  if (req.method === "GET" && urlPath === "/registry") {
    return send(res, 200, { registry: REGISTRY_URL, scope: INTERNAL_SCOPE });
  }

  // GET /build/<id>
  const m = urlPath.match(/^\/build\/([a-zA-Z0-9_-]+)$/);
  if (req.method === "GET" && m) {
    const b = BUILDS[m[1]];
    if (!b) return send(res, 404, { error: "not found" });
    return send(res, 200, b);
  }

  if (req.method === "POST" && urlPath === "/build") {
    let payload = {};
    try {
      const raw = (req.rawBody || Buffer.alloc(0)).toString("utf8").trim();
      payload = raw ? JSON.parse(raw) : {};
    } catch (e) {
      return send(res, 400, { error: "body JSON invalido: " + e.message });
    }
    const manifest = payload["package.json"] || payload.manifest || null;
    const lockfile = payload["package-lock.json"] || payload.lockfile || null;
    const buildId = require("crypto").randomBytes(6).toString("hex");

    const srcIp =
      (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "")
        .toString()
        .split(",")[0]
        .trim() || null;

    runBuild(buildId, manifest, lockfile, (result) => {
      BUILDS[buildId] = result;
      // SIEM: un build que resuelve una version no-baseline del paquete interno
      // o cuyo log evidencia ejecucion de scripts es sospechoso.
      try {
        const susp =
          /@forge\/logger/.test(result.log) &&
          (/\bpostinstall\b|\bpreinstall\b|run.*install script/i.test(result.log) ||
            /@forge\/logger@(?!1\.0\.0)/.test(result.log));
        if (susp) {
          emit("scan_detected", "alert", srcIp, {
            build_id: buildId,
            reason: "build-ran-lifecycle-script-or-nonbaseline-version",
          });
        }
      } catch (_) {}
      send(res, 200, result);
    });
    return;
  }

  return send(res, 404, { error: "no encontrado" });
}

server.listen(PORT, "0.0.0.0", () => {
  console.log(`[forge-runner] Forgewright CI en :${PORT}  registry=${REGISTRY_URL}`);
});
