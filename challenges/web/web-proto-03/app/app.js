/**
 * Doom Templates — web-proto-03 (Web INSANE).
 *
 * Vulnerabilidad central: PROTOTYPE POLLUTION (Node/Express) encadenada a
 * AUTH BYPASS + RCE en SSR (gadget de EJS). App "Doom Templates": un editor de
 * plantillas para correos/landing donde cada usuario guarda "preferencias" que
 * se MERGEAN (merge recursivo INSEGURO) sobre su objeto de perfil/config.
 *
 * Cadena INSANE para resolver:
 *   1) /api/templates/save hace un merge recursivo casero (mergeDeep) del JSON
 *      del usuario sobre su objeto de preferencias. NO filtra `__proto__` ni
 *      `constructor.prototype`, así que un body anidado contamina
 *      Object.prototype para TODO el proceso.
 *        {"settings":{"__proto__":{"role":"admin"}}}
 *      -> a partir de aquí, ({}).role === "admin" en todo objeto "vacío".
 *
 *   2) AUTH BYPASS: /admin/render comprueba la autorización leyendo
 *      `session.role`/`session.isAdmin`. La sesión es un objeto plano que NO
 *      define esas claves -> hereda las contaminadas del prototipo. El gate
 *      "solo admin" se abre sin credenciales.
 *
 *   3) RCE EN SSR (gadget EJS): /admin/render renderiza una plantilla con
 *      ejs.render(tpl, data, options) y pasa `options = {}` (sin filtrar). EJS
 *      lee de `options` claves como `outputFunctionName`, `escapeFunction`,
 *      `localsName`, `client`... que, al estar el prototipo contaminado, llegan
 *      contaminadas y se inyectan en el cuerpo de la función compilada -> RCE.
 *      Gadget clásico:
 *        {"settings":{"__proto__":{"outputFunctionName":
 *          "x;process.mainModule.require('child_process').execSync('cat /flag.txt > /app/pub/leak');//"}}}
 *      o más directo, devolver la salida del comando en la respuesta.
 *
 * La FLAG se inyecta por equipo vía env FLAG y se escribe a /flag.txt en el
 * arranque (solo dentro del contenedor). NO hardcodeada.
 *
 * Aislamiento: el servicio vive SOLO en la red del equipo (172.30.N.16:8080),
 * sin publicar puertos al host. La contaminación del prototipo es por-proceso,
 * así que cada equipo contamina SU instancia y lee SU flag.
 */
'use strict';

const fs = require('fs');
const express = require('express');
const ejs = require('ejs');
const { reqlogMiddleware } = require('./reqlog');
const { emit } = require('./siem');

const FLAG = process.env.FLAG || 'flag{EJEMPLO_LOCAL}';
// Puerto interno SIEMPRE 8080 en el contenedor (no se publica al host). PORT solo
// se sobreescribe para pruebas locales fuera de Docker.
const PORT = parseInt(process.env.PORT, 10) || 8080;

// La flag vive como archivo dentro del contenedor: es el objetivo de la lectura
// vía la cadena prototype-pollution -> RCE. Se escribe desde env FLAG en boot
// (NUNCA horneada en la imagen). El servicio no la sirve por ningún endpoint.
const FLAG_PATH = '/flag.txt';
try {
  fs.writeFileSync(FLAG_PATH, FLAG + '\n', { mode: 0o644 });
} catch (e) {
  /* en local sin permisos de escritura a /, el RCE igual puede leer env */
}

const app = express();

// --- body crudo para el reqlog + parseo JSON ---------------------------------
// Guardamos el body crudo (req.rawBody) para que el reqlog del SIEM imprima el
// JSON EXACTO que envió el jugador, igual que el reqlog.py original.
app.use(
  express.json({
    limit: '256kb',
    verify: (req, _res, buf) => {
      req.rawBody = buf && buf.length ? buf.toString('utf-8') : '';
    },
  })
);
// Loguea CADA petición entrante COMPLETA al SIEM del stream (CTFREQ {json}).
app.use(reqlogMiddleware);

// --- "Almacén" de perfiles en memoria ----------------------------------------
// Cada visitante tiene un perfil con preferencias de plantilla. Objeto PLANO:
// por eso hereda lo que se contamine en Object.prototype (esa es la trampa).
function newProfile() {
  // Perfil base SIN role/isAdmin: si esas claves existen, vienen del prototipo.
  return {
    name: 'guest',
    settings: {
      theme: 'dark',
      brand: 'Doom Templates',
    },
  };
}
const PROFILE = newProfile();

// --- mergeDeep VULNERABLE (sin saneo de __proto__) ---------------------------
// Merge recursivo casero. NO filtra claves peligrosas (`__proto__`,
// `constructor`, `prototype`) -> permite contaminar Object.prototype.
function isObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}
function mergeDeep(target, source) {
  for (const key in source) {
    // <- el bug: itera TODAS las claves del source, incluida "__proto__".
    if (isObject(source[key])) {
      if (!isObject(target[key])) {
        target[key] = {};
      }
      mergeDeep(target[key], source[key]); // recursión -> escala a Object.prototype
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// --- Vistas -------------------------------------------------------------------
const INDEX = `<!doctype html><html lang="es"><head><meta charset="utf-8">
<title>Doom Templates</title></head>
<body style="font-family:sans-serif;max-width:780px;margin:2rem auto;background:#0d0d0d;color:#ddd">
<h1>Doom Templates &middot; Editor de plantillas</h1>
<p>Guarda tus <b>preferencias</b> de plantilla y previsualiza el render del
correo. Las preferencias se fusionan sobre tu perfil. El render avanzado
(<code>/admin/render</code>) está reservado a administradores.</p>
<h3>Guardar preferencias</h3>
<form onsubmit="save(event)">
  <textarea id="prefs" style="width:100%;height:120px;background:#111;color:#0f0">{"settings":{"theme":"doom"}}</textarea>
  <button>Guardar</button>
</form>
<h3>Mi perfil</h3>
<pre id="me" style="background:#111;color:#0f0;padding:1rem;white-space:pre-wrap"></pre>
<p style="color:#888">API:
<code>POST /api/templates/save {"settings":{...}}</code> ·
<code>GET /api/profile</code> ·
<code>POST /admin/render {"template":"...EJS..."}</code> (solo admin)</p>
<script>
async function save(e){e.preventDefault();
 const r=await fetch('/api/templates/save',{method:'POST',headers:{'Content-Type':'application/json'},
   body:document.getElementById('prefs').value});
 document.getElementById('me').textContent=JSON.stringify(await r.json(),null,2);}
fetch('/api/profile').then(r=>r.json()).then(j=>document.getElementById('me').textContent=JSON.stringify(j,null,2));
</script></body></html>`;

app.get('/', (_req, res) => {
  res.type('html').send(INDEX);
});

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// Eco del perfil (para que el jugador "vea" el efecto del merge).
app.get('/api/profile', (_req, res) => {
  res.json(PROFILE);
});

// --- Endpoint VULNERABLE: merge inseguro -------------------------------------
app.post('/api/templates/save', (req, res) => {
  const srcIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '')
    .toString()
    .split(',')[0]
    .trim();
  const body = req.body || {};

  // Telemetría: detectar intento de contaminación de prototipo en el body crudo.
  try {
    if (/__proto__|constructor|prototype/.test(req.rawBody || '')) {
      emit('proto_pollution_attempt', 'warn', srcIp, {
        vuln: 'prototype-pollution',
        endpoint: '/api/templates/save',
      });
    }
  } catch (e) {
    /* no romper el flujo por telemetría */
  }

  // VULN: merge recursivo del JSON del usuario sobre el perfil, sin saneo.
  // Un body como {"settings":{"__proto__":{"role":"admin"}}} contamina
  // Object.prototype para todo el proceso.
  mergeDeep(PROFILE, body);

  res.json({ ok: true, profile: PROFILE });
});

// --- Endpoint gateado por "rol admin" -> RCE en SSR --------------------------
app.post('/admin/render', (req, res) => {
  const srcIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '')
    .toString()
    .split(',')[0]
    .trim();

  // Gate de autorización. `session` es un objeto PLANO sin role/isAdmin: si esas
  // claves existen, fueron CONTAMINADAS en el prototipo (auth bypass).
  const session = {};
  const isAdmin = session.role === 'admin' || session.isAdmin === true;
  if (!isAdmin) {
    return res
      .status(403)
      .json({ error: 'solo admin: render avanzado deshabilitado para tu rol' });
  }

  emit('admin_render_invoked', 'alert', srcIp, {
    vuln: 'prototype-pollution-authbypass',
    endpoint: '/admin/render',
  });

  const template = (req.body && req.body.template) || 'Hola <%= name %>';
  const data = { name: 'admin' };

  // VULN (gadget RCE): renderizamos con opciones VACÍAS. EJS lee de `options`
  // claves de configuración (outputFunctionName, escapeFunction, localsName,
  // client...). Con Object.prototype contaminado, esas opciones llegan
  // contaminadas y se inyectan en la función compilada -> ejecución.
  const options = {}; // <- vacío a propósito; hereda del prototipo contaminado
  try {
    const html = ejs.render(template, data, options);
    return res.json({ rendered: html });
  } catch (err) {
    // El gadget de outputFunctionName a menudo lanza tras ejecutar el payload;
    // devolvemos el error para no ocultar el resultado de la ejecución.
    return res.status(500).json({ error: String(err && err.message ? err.message : err) });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  process.stdout.write(`[doom-templates] escuchando en 0.0.0.0:${PORT}\n`);
});
