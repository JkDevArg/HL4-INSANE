/** Emision de eventos SIEM (esquema ARCHITECTURE.md §5). Fire-and-forget. Port de siem.py. */
'use strict';

const http = require('http');
const { URL } = require('url');

const COLLECTOR_URL = process.env.COLLECTOR_URL || 'http://collector:9000';
const TEAM_ID = process.env.TEAM_ID || 'team_local';
const CHALLENGE_ID = process.env.CHALLENGE_ID || 'web-proto-03';

function _post(event) {
  try {
    const data = Buffer.from(JSON.stringify(event), 'utf-8');
    const u = new URL(COLLECTOR_URL + '/event');
    const req = http.request(
      {
        hostname: u.hostname,
        port: u.port || 80,
        path: u.pathname,
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': data.length },
        timeout: 2000,
      },
      (res) => { res.on('data', () => {}); res.on('end', () => {}); }
    );
    req.on('error', () => {});
    req.on('timeout', () => req.destroy());
    req.write(data);
    req.end();
  } catch (e) {
    /* fire-and-forget: nunca tumbar el reto */
  }
}

function emit(eventType, severity, srcIp = null, detail = null) {
  const event = {
    ts: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    source: 'challenge',
    team_id: TEAM_ID,
    user: TEAM_ID,
    src_ip: srcIp,
    event_type: eventType,
    severity: severity,
    challenge_id: CHALLENGE_ID,
    detail: detail || {},
  };
  _post(event);
}

module.exports = { emit };
