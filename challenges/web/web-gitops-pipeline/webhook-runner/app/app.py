#!/usr/bin/env python3
"""
Webhook Runner — internal only.
Validates HMAC-SHA256 signatures and executes pipeline steps.
The flag is at /flag.txt.
"""
import os
import hmac
import hashlib
import subprocess
import time
from pathlib import Path
from flask import Flask, request, jsonify, Response

app = Flask(__name__)

FLAG_FILE = Path("/flag.txt")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "sup3rs3cr3t_hmac_k3y")
run_log = []


def verify_signature(data: bytes, sig_header: str) -> bool:
    if not sig_header.startswith("sha256="):
        return False
    provided = sig_header[7:]
    expected = hmac.new(WEBHOOK_SECRET.encode(), data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(provided, expected)


@app.route("/run", methods=["POST"])
def run_pipeline():
    """Receives signed webhook, executes pipeline steps."""
    raw = request.get_data()
    sig = request.headers.get("X-Hub-Signature-256", "")

    if not verify_signature(raw, sig):
        return jsonify({
            "error": "Invalid signature",
            "hint": "Use HMAC-SHA256 with the webhook secret"
        }), 401

    body = request.get_json(force=True, silent=True) or {}
    steps = body.get("steps", ["echo 'No steps defined'"])
    ref = body.get("ref", "refs/heads/main")

    outputs = []
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    for step in steps:
        try:
            result = subprocess.run(
                step, shell=True, capture_output=True, text=True,
                timeout=30, cwd="/tmp"
            )
            entry = {
                "step": step,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            entry = {"step": step, "error": "timeout"}
        except Exception as e:
            entry = {"step": step, "error": str(e)}
        outputs.append(entry)

    log_entry = {"timestamp": ts, "ref": ref, "steps": len(steps), "outputs": outputs}
    run_log.append(log_entry)

    return jsonify({
        "status": "executed",
        "timestamp": ts,
        "ref": ref,
        "outputs": outputs
    })


@app.route("/status")
def status():
    """Status endpoint — shows recent runs."""
    return jsonify({
        "service": "webhook-runner",
        "secret_configured": bool(WEBHOOK_SECRET),
        "total_runs": len(run_log),
        "recent": run_log[-5:] if run_log else []
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok", "flag_exists": FLAG_FILE.exists()})


if __name__ == "__main__":
    print("[*] Webhook runner starting on :9001")
    app.run(host="0.0.0.0", port=9001, debug=False)
