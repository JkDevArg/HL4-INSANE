/**
 * reqlog — logging COMPLETO de peticiones de jugadores hacia un reto (Node/Express).
 *
 * Port fiel de reqlog.py (web-ssrf-02). OBJETIVO: que el comentarista del stream
 * vea CUALQUIER cosa que un jugador envíe a un reto. Cada petición se imprime a
 * STDOUT como UNA línea con el prefijo `CTFREQ ` seguido de JSON compacto.
 * Promtail recoge esas líneas (filtro `CTFREQ `) y el caster-overlay las narra
 * anonimizadas por equipo.
 *
 * Formato EXACTO de la línea (HTTP) — IDÉNTICO al de reqlog.py:
 *   CTFREQ {"ts":"<iso8601>","challenge_id":"<id>","src_ip":"<ip cliente>",
 *           "proto":"http","method":"POST","path":"/api/templates/save",
 *           "query":"...","headers":{...},"body":"<texto, <=8192 chars>"}
 *
 * REGLAS (mismas que reqlog.py):
 *   - challenge_id sale del env CHALLENGE_ID.
 *   - src_ip es la IP REAL del cliente (x-forwarded-for / remoteAddress).
 *   - body se trunca a MAX_BODY chars (8192).
 *   - NUNCA se loguea la FLAG propia del reto (env FLAG): se redacta si aparece.
 *
 * Sin dependencias externas: solo Node core. Se copia tal cual a cada reto Node.
 */
'use strict';

const MAX_BODY = 8192;

const CHALLENGE_ID = process.env.CHALLENGE_ID || 'unknown';
const _FLAG = process.env.FLAG || '';
const _FLAG_REDACTION = '[FLAG-REDACTADA]';

function _nowIso() {
  // ISO-8601 UTC con sufijo Z (segundos), como datetime.strftime("%Y-%m-%dT%H:%M:%SZ").
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function _redactFlag(text) {
  if (!text || !_FLAG) return text;
  if (text.indexOf(_FLAG) !== -1) {
    return text.split(_FLAG).join(_FLAG_REDACTION);
  }
  return text;
}

function _coerceText(value) {
  if (value === null || value === undefined) return '';
  if (Buffer.isBuffer(value)) {
    const s = value.toString('utf-8');
    // Heurística simple: si la decodificación dejó el char de reemplazo, hex.
    if (s.includes('�')) return 'hex:' + value.toString('hex');
    return s;
  }
  if (typeof value === 'string') return value;
  return String(value);
}

function _truncate(text) {
  if (text === null || text === undefined) return '';
  if (text.length > MAX_BODY) {
    return text.slice(0, MAX_BODY) + `...[+${text.length - MAX_BODY} chars]`;
  }
  return text;
}

function _emit(record) {
  // Imprime la línea `CTFREQ {json}` a STDOUT con flush. Nunca lanza.
  try {
    const line = 'CTFREQ ' + JSON.stringify(record);
    process.stdout.write(line + '\n');
  } catch (e) {
    /* el logging jamás debe tumbar el reto */
  }
}

/**
 * Loguea una petición HTTP COMPLETA recibida por el reto.
 *   srcIp   : IP real del cliente.
 *   method  : método HTTP.
 *   path    : ruta SIN query string.
 *   query   : query string cruda (sin '?').
 *   headers : objeto con TODOS los headers.
 *   body    : cuerpo crudo (string o Buffer). Se trunca a 8192 chars.
 */
function reqlogHttp(srcIp, method, path, query = '', headers = null, body = '') {
  const hdrs = {};
  if (headers) {
    for (const k of Object.keys(headers)) {
      hdrs[String(k)] = _redactFlag(_coerceText(headers[k]));
    }
  }
  const record = {
    ts: _nowIso(),
    challenge_id: CHALLENGE_ID,
    src_ip: _coerceText(srcIp) || '?',
    proto: 'http',
    method: _coerceText(method) || '?',
    path: _coerceText(path) || '/',
    query: _redactFlag(_coerceText(query)),
    headers: hdrs,
    body: _truncate(_redactFlag(_coerceText(body))),
  };
  _emit(record);
}

/**
 * Middleware Express: loguea CADA petición entrante COMPLETA (método, ruta,
 * query, headers, body) para el SIEM del stream. No interfiere con el manejo.
 *
 * Requiere que el body crudo esté disponible. Usamos express.json()/raw con
 * un `verify` que guarda req.rawBody, o caemos al body ya parseado.
 */
function reqlogMiddleware(req, res, next) {
  try {
    let srcIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    if (srcIp && srcIp.indexOf(',') !== -1) {
      srcIp = srcIp.split(',')[0].trim();
    }
    // Preferimos SIEMPRE el body crudo (req.rawBody) guardado por el verify de
    // express.json(): así logueamos el JSON EXACTO del jugador (incl. __proto__),
    // sin que el parser lo normalice. Solo caemos al body parseado si no hay crudo.
    let body = '';
    if (req.rawBody !== undefined && req.rawBody !== null) {
      body = _coerceText(req.rawBody);
    } else if (req.body !== undefined && req.body !== null && Object.keys(req.body).length) {
      body = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
    }
    const qIndex = (req.originalUrl || req.url || '').indexOf('?');
    const query = qIndex >= 0 ? (req.originalUrl || req.url).slice(qIndex + 1) : '';
    reqlogHttp(srcIp, req.method, req.path, query, req.headers, body);
  } catch (e) {
    /* nunca tumbar el reto por el logging */
  }
  next();
}

module.exports = { reqlogHttp, reqlogMiddleware };
