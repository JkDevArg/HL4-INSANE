// @forge/logger 1.0.0 — logger estructurado interno de Forgewright (baseline).
module.exports = {
  version: "1.0.0",
  banner() {
    return "@forge/logger v1.0.0 (baseline)";
  },
  info(msg) {
    console.log("[forge-logger] " + msg);
  },
};
