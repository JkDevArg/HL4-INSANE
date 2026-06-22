/*
 * Forgewright — Registry npm INTERNO (pwn-supply-04).
 *
 * Implementacion MINIMA del protocolo de registro de npm, suficiente para que
 * `npm install` resuelva, descargue e instale paquetes del scope @forge, y para
 * que `npm publish` SUBA paquetes SIN autenticacion (la mala practica del reto).
 *
 * Endpoints soportados (subset del registry API de npm):
 *   GET  /:pkg            -> documento de paquete (metadata + dist-tags + versions)
 *   GET  /:pkg/-/:file    -> tarball .tgz
 *   PUT  /:pkg            -> publish (npm publish). ANONIMO: no valida token.
 *   GET  /-/ping          -> health
 *
 * El scope @forge esta "delegado" a este registry interno (ver .npmrc del runner),
 * asi que QUIEN PUEDA PUBLICAR aqui controla lo que el CI instala. No hay firma,
 * no hay 2FA, no hay revision: clasico compromiso de cadena de suministro interna.
 *
 * Estado en memoria + disco (/data/packages). Sin dependencias externas.
 */
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = parseInt(process.env.PORT || "8080", 10);
const DATA = process.env.PKGDIR || "/data/packages";
const PUBLIC_BASE = process.env.REGISTRY_PUBLIC_BASE || `http://registry:${PORT}`;

fs.mkdirSync(DATA, { recursive: true });

// packages[name] = { name, "dist-tags": {...}, versions: { ver: manifest }, _attachments... }
const packages = {};

function docPath(name) {
  return path.join(DATA, encodeURIComponent(name) + ".json");
}
// npm nombra los attachments con el scope incluido ("@forge/logger-1.0.0.tgz").
// Aplanamos el "/" para guardar/servir en un unico dir sin subcarpetas.
function flatName(file) {
  return String(file).replace(/^@/, "").replace(/\//g, "-");
}
function tgzPath(file) {
  return path.join(DATA, "tarballs", flatName(file));
}

function loadFromDisk() {
  for (const f of fs.readdirSync(DATA)) {
    if (f.endsWith(".json")) {
      try {
        const doc = JSON.parse(fs.readFileSync(path.join(DATA, f), "utf8"));
        packages[doc.name] = doc;
      } catch (_) {}
    }
  }
}
function persist(name) {
  fs.writeFileSync(docPath(name), JSON.stringify(packages[name]));
}

// Reescribe las URLs de tarball del documento para que apunten a ESTE registry
// (npm las usa para descargar). Asi el host/puerto siempre es resolvible.
function withResolvedTarballs(doc) {
  const out = JSON.parse(JSON.stringify(doc));
  for (const ver of Object.keys(out.versions || {})) {
    const dist = out.versions[ver].dist || {};
    const file = (dist.tarball || "").split("/-/").pop();
    if (file) {
      dist.tarball = `${PUBLIC_BASE}/${encodeURIComponent(out.name)}/-/${file}`;
      out.versions[ver].dist = dist;
    }
  }
  return out;
}

function send(res, code, obj, headers = {}) {
  const body = typeof obj === "string" ? obj : JSON.stringify(obj);
  res.writeHead(code, Object.assign({ "Content-Type": "application/json" }, headers));
  res.end(body);
}

// --- publish (npm publish PUT) -------------------------------------------
// npm envia un documento JSON con `versions`, `dist-tags` y `_attachments`
// (los tarballs en base64). Lo aceptamos TAL CUAL, sin autenticacion.
function handlePublish(name, payload, res) {
  let doc;
  try {
    doc = JSON.parse(payload);
  } catch (e) {
    return send(res, 400, { error: "json invalido" });
  }
  const existing = packages[name] || { name, "dist-tags": {}, versions: {} };

  // Guarda los tarballs adjuntos en disco.
  fs.mkdirSync(path.join(DATA, "tarballs"), { recursive: true });
  const attachments = doc._attachments || {};
  for (const fname of Object.keys(attachments)) {
    const data = Buffer.from(attachments[fname].data, "base64");
    fs.writeFileSync(tgzPath(fname), data);
  }

  // Mezcla versiones nuevas + recalcula shasum/integrity por si npm no lo mando.
  for (const ver of Object.keys(doc.versions || {})) {
    const manifest = doc.versions[ver];
    const dist = manifest.dist || {};
    // El attachment de npm viene keyed como "@scope/name-<ver>.tgz"; lo
    // aplanamos para servirlo sin subcarpetas (la ruta /-/ no admite "/").
    const attName = Object.keys(attachments)[0];
    const file = attName ? flatName(attName) : flatName(`${name}-${ver}.tgz`);
    const tgz = attName ? fs.readFileSync(tgzPath(attName)) : null;
    if (tgz) {
      dist.shasum = crypto.createHash("sha1").update(tgz).digest("hex");
      dist.integrity =
        "sha512-" + crypto.createHash("sha512").update(tgz).digest("base64");
    }
    dist.tarball = `${PUBLIC_BASE}/${encodeURIComponent(name)}/-/${file}`;
    manifest.dist = dist;
    existing.versions[ver] = manifest;
  }
  existing["dist-tags"] = Object.assign(
    existing["dist-tags"] || {},
    doc["dist-tags"] || {}
  );
  existing.name = name;
  packages[name] = existing;
  persist(name);

  console.log(
    `CTFREG publish name=${name} versions=${Object.keys(doc.versions || {}).join(",")}`
  );
  return send(res, 201, { ok: true, id: name });
}

const server = http.createServer((req, res) => {
  const url = decodeURIComponent(req.url.split("?")[0]);

  if (url === "/-/ping" || url === "/") {
    return send(res, 200, { ok: true, registry: "forgewright-internal" });
  }

  // GET tarball:  /<pkg>/-/<file.tgz>   (pkg puede ser @forge%2flogger o @forge/logger)
  const tgzMatch = url.match(/^\/(.+)\/-\/([^/]+\.tgz)$/);
  if (req.method === "GET" && tgzMatch) {
    const file = tgzMatch[2];
    const p = tgzPath(file);
    if (!fs.existsSync(p)) return send(res, 404, { error: "no tarball" });
    res.writeHead(200, { "Content-Type": "application/octet-stream" });
    return res.end(fs.readFileSync(p));
  }

  // PUT publish: /<pkg>
  if (req.method === "PUT") {
    const name = url.replace(/^\//, "");
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => handlePublish(name, Buffer.concat(chunks).toString("utf8"), res));
    return;
  }

  // GET package document: /<pkg>
  if (req.method === "GET") {
    const name = url.replace(/^\//, "");
    const doc = packages[name];
    if (!doc) return send(res, 404, { error: "no existe" });
    return send(res, 200, withResolvedTarballs(doc));
  }

  return send(res, 405, { error: "metodo no soportado" });
});

loadFromDisk();
server.listen(PORT, "0.0.0.0", () => {
  console.log(`[registry] forgewright npm interno en :${PORT} (publish ANONIMO)`);
  console.log(`[registry] paquetes cargados: ${Object.keys(packages).join(", ") || "(ninguno)"}`);
});
