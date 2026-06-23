#!/usr/bin/env python3
"""
Build Server — internal only (not exposed to team_net).
The flag lives at /app/secrets/flag.txt.
Receives build triggers from the CI runner.
"""
import os
import json
import time
from pathlib import Path
from flask import Flask, request, jsonify

app = Flask(__name__)

FLAG_FILE = Path("/app/secrets/flag.txt")
BUILD_LOG = Path("/tmp/build.log")

build_state = {
    "status": "idle",
    "last_build": None,
    "build_count": 0,
    "last_output": ""
}


def run_build(source="unknown"):
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    build_state["status"] = "building"
    build_state["last_build"] = ts
    build_state["build_count"] += 1

    log_entry = f"[{ts}] Build #{build_state['build_count']} triggered by {source}\n"
    log_entry += "  [*] Checking out HEAD...\n"
    log_entry += "  [*] Installing dependencies...\n"
    log_entry += "  [*] Running tests...\n"
    log_entry += "  [+] Build SUCCESS\n"

    with open(BUILD_LOG, "a") as f:
        f.write(log_entry)

    build_state["last_output"] = log_entry
    build_state["status"] = "success"
    return log_entry


@app.route("/trigger-build", methods=["POST"])
def trigger_build():
    data = request.get_json(silent=True) or {}
    source = data.get("source", "unknown")
    output = run_build(source)
    return jsonify({
        "status": "triggered",
        "build_number": build_state["build_count"],
        "output": output
    })


@app.route("/status")
def status():
    return jsonify({
        "status": build_state["status"],
        "last_build": build_state["last_build"],
        "build_count": build_state["build_count"],
        "secrets_path": "/app/secrets/",
        "flag_exists": FLAG_FILE.exists()
    })


@app.route("/logs")
def logs():
    if BUILD_LOG.exists():
        return BUILD_LOG.read_text(), 200, {"Content-Type": "text/plain"}
    return "No builds yet.\n", 200, {"Content-Type": "text/plain"}


@app.route("/secrets/flag")
def get_flag():
    """This endpoint is only reachable from inside the container (RCE required)."""
    if FLAG_FILE.exists():
        return jsonify({"flag": FLAG_FILE.read_text().strip()})
    return jsonify({"error": "Flag not found"}), 404


if __name__ == "__main__":
    print("[*] Build server starting on :9000")
    app.run(host="0.0.0.0", port=9000, debug=False)
