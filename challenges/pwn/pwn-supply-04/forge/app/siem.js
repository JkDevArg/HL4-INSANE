/*
 * siem.js — emision de eventos SIEM (esquema ARCHITECTURE.md §5). Fire-and-forget.
 * Equivalente Node de siem.py. Sin dependencias externas.
 */
"use strict";
const http = require("http");
const { URL } = require("url");

const COLLECTOR_URL = process.env.COLLECTOR_URL || "http://collector:9000";
const TEAM_ID = process.env.TEAM_ID || "team_local";
const CHALLENGE_ID = process.env.CHALLENGE_ID || "pwn-supply-04";

function emit(eventType, severity, srcIp = null, detail = {}) {
  const event = {
    ts: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    source: "challenge",
    team_id: TEAM_ID,
    user: TEAM_ID,
    src_ip: srcIp,
    event_type: eventType,
    severity,
    challenge_id: CHALLENGE_ID,
    detail: detail || {},
  };
  try {
    const u = new URL(COLLECTOR_URL + "/event");
    const data = Buffer.from(JSON.stringify(event));
    const req = http.request(
      {
        hostname: u.hostname,
        port: u.port || 80,
        path: u.pathname,
        method: "POST",
        headers: { "Content-Type": "application/json", "Content-Length": data.length },
        timeout: 2000,
      },
      (res) => res.resume()
    );
    req.on("error", () => {});
    req.on("timeout", () => req.destroy());
    req.write(data);
    req.end();
  } catch (_) {
    /* fire-and-forget */
  }
}

module.exports = { emit };
