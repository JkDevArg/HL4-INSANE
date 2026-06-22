/*
 * reqlog.js — logging COMPLETO de peticiones de jugadores hacia el reto.
 *
 * Mismo CONTRATO que reqlog.py de los retos Python: cada peticion HTTP se
 * imprime a STDOUT como UNA linea con el prefijo `CTFREQ ` seguido de JSON
 * compacto. Promtail recoge esas lineas (filtro `CTFREQ `) y el caster-overlay
 * las narra anonimizadas por equipo.
 *
 * Formato EXACTO de la linea (HTTP):
 *   CTFREQ {"ts":"<iso8601>","challenge_id":"<id>","src_ip":"<ip>",
 *           "proto":"http","method":"POST","path":"/build","query":"",
 *           "headers":{...},"body":"<texto, <=8192 chars>"}
 *
 * - challenge_id sale del env CHALLENGE_ID.
 * - src_ip es la IP REAL del cliente (X-Forwarded-For si viene, si no remoteAddr).
 * - body se trunca a 8192 chars.
 * - NUNCA se loguea la FLAG propia del reto (env FLAG): se redacta si aparece.
 */
"use strict";

const MAX_BODY = 8192;
const CHALLENGE_ID = process.env.CHALLENGE_ID || "unknown";
const FLAG = process.env.FLAG || "";
const FLAG_REDACTION = "[FLAG-REDACTADA]";

function nowIso() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function redactFlag(text) {
  if (!text || !FLAG) return text;
  return text.split(FLAG).join(FLAG_REDACTION);
}

function coerceText(v) {
  if (v === null || v === undefined) return "";
  if (Buffer.isBuffer(v)) {
    const s = v.toString("utf8");
    return s;
  }
  return String(v);
}

function truncate(text) {
  if (text == null) return "";
  if (text.length > MAX_BODY) {
    return text.slice(0, MAX_BODY) + `...[+${text.length - MAX_BODY} chars]`;
  }
  return text;
}

function emit(record) {
  try {
    process.stdout.write("CTFREQ " + JSON.stringify(record) + "\n");
  } catch (_) {
    /* el logging jamas debe tumbar el reto */
  }
}

function reqlogHttp({ src_ip, method, path, query = "", headers = {}, body = "" }) {
  const hdrs = {};
  for (const k of Object.keys(headers || {})) {
    hdrs[String(k)] = redactFlag(coerceText(headers[k]));
  }
  emit({
    ts: nowIso(),
    challenge_id: CHALLENGE_ID,
    src_ip: coerceText(src_ip) || "?",
    proto: "http",
    method: coerceText(method) || "?",
    path: coerceText(path) || "/",
    query: redactFlag(coerceText(query)),
    headers: hdrs,
    body: truncate(redactFlag(coerceText(body))),
  });
}

// Middleware Express: loguea CADA peticion entrante COMPLETA. Buffea el body
// crudo (raw) para reinyectarlo a los handlers aguas abajo.
function middleware(req, res, next) {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const raw = Buffer.concat(chunks);
    req.rawBody = raw;
    try {
      let src = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "?";
      if (typeof src === "string" && src.includes(",")) src = src.split(",")[0].trim();
      const qIdx = req.url.indexOf("?");
      const query = qIdx >= 0 ? req.url.slice(qIdx + 1) : "";
      reqlogHttp({
        src_ip: src,
        method: req.method,
        path: qIdx >= 0 ? req.url.slice(0, qIdx) : req.url,
        query,
        headers: req.headers,
        body: raw,
      });
    } catch (_) {
      /* nunca tumbar el reto */
    }
    next();
  });
}

module.exports = { reqlogHttp, middleware };
