#!/usr/bin/env python3
"""
Fake PyPI-compatible package registry.
Vulnerability: POST /api/publish accepts unauthenticated uploads when
X-Forwarded-For is set to an "internal" address. The CI runner auto-installs
every new package, executing postinstall hooks (setup.py cmdclass).
"""
import os
import json
import hashlib
import time
from pathlib import Path
from flask import Flask, request, jsonify, send_file, abort, render_template_string

app = Flask(__name__)

PACKAGES_DIR = Path("/app/packages")
DATA_FILE = Path("/app/data/packages.json")
PACKAGES_DIR.mkdir(parents=True, exist_ok=True)
DATA_FILE.parent.mkdir(parents=True, exist_ok=True)

VALID_API_KEY = "prod-key-do-not-share-f7a3c9"

HTML_INDEX = """<!DOCTYPE html>
<html>
<head>
  <title>CorpPyPI — Internal Package Registry</title>
  <style>
    body { font-family: monospace; background: #1a1a2e; color: #e0e0e0; padding: 2rem; }
    h1 { color: #00d4ff; }
    .pkg { background: #16213e; padding: 1rem; margin: 0.5rem 0; border-left: 3px solid #00d4ff; }
    .pkg h3 { margin: 0; color: #00d4ff; }
    .pkg p { margin: 0.3rem 0; font-size: 0.9rem; }
    .badge { background: #0f3460; padding: 2px 8px; border-radius: 3px; font-size: 0.8rem; }
    a { color: #00d4ff; }
    .notice { background: #2d1b00; border: 1px solid #ff9500; padding: 1rem; margin-bottom: 1rem; border-radius: 4px; }
  </style>
</head>
<body>
  <h1>CorpPyPI — Internal Package Registry</h1>
  <div class="notice">
    <strong>Internal use only.</strong> To publish packages use the API:<br>
    <code>curl -X POST /api/publish -H "X-API-Key: &lt;key&gt;" -F "package=@pkg.tar.gz" -F "metadata=@meta.json"</code>
  </div>
  <h2>Available Packages ({{ packages|length }})</h2>
  {% for pkg in packages %}
  <div class="pkg">
    <h3>{{ pkg.name }} <span class="badge">v{{ pkg.version }}</span></h3>
    <p>{{ pkg.description | safe }}</p>
    <p>Author: {{ pkg.author }} | Published: {{ pkg.published_at }}</p>
    <p><a href="/simple/{{ pkg.name }}/">Index</a> | <a href="/packages/{{ pkg.filename }}">Download</a></p>
  </div>
  {% else %}
  <p>No packages published yet.</p>
  {% endfor %}
  <hr>
  <p><a href="/simple/">Simple Index (pip compatible)</a></p>
</body>
</html>"""

HTML_SIMPLE_INDEX = """<!DOCTYPE html>
<html><head><title>Simple Index</title></head>
<body>
<h1>Simple Index</h1>
{% for pkg in packages %}
<a href="/simple/{{ pkg.name }}/">{{ pkg.name }}</a><br>
{% endfor %}
</body></html>"""

HTML_PKG_DETAIL = """<!DOCTYPE html>
<html><head><title>Links for {{ name }}</title></head>
<body>
<h1>Links for {{ name }}</h1>
{% for f in files %}
<a href="/packages/{{ f }}" data-requires-python=">=3.8">{{ f }}</a><br>
{% endfor %}
</body></html>"""


def load_packages():
    if DATA_FILE.exists():
        try:
            return json.loads(DATA_FILE.read_text())
        except Exception:
            return []
    return []


def save_packages(pkgs):
    DATA_FILE.write_text(json.dumps(pkgs, indent=2))


def is_internal_request():
    """Weak internal check — X-Forwarded-For is fully attacker-controlled."""
    xff = request.headers.get("X-Forwarded-For", "")
    remote = request.remote_addr or ""
    internal_ranges = ["127.", "10.", "172.", "192.168.", "::1"]
    for ip in [xff.split(",")[0].strip(), remote]:
        for r in internal_ranges:
            if ip.startswith(r):
                return True
    return False


@app.route("/")
def index():
    pkgs = load_packages()
    return render_template_string(HTML_INDEX, packages=pkgs)


@app.route("/simple/")
def simple_index():
    pkgs = load_packages()
    return render_template_string(HTML_SIMPLE_INDEX, packages=pkgs)


@app.route("/simple/<package_name>/")
def simple_package(package_name):
    pkgs = load_packages()
    files = [p["filename"] for p in pkgs if p["name"].lower() == package_name.lower()]
    if not files:
        abort(404)
    return render_template_string(HTML_PKG_DETAIL, name=package_name, files=files)


@app.route("/packages/<filename>")
def download_package(filename):
    filepath = PACKAGES_DIR / filename
    if not filepath.exists():
        abort(404)
    return send_file(str(filepath), as_attachment=True)


@app.route("/api/packages")
def list_packages():
    pkgs = load_packages()
    return jsonify({"packages": pkgs, "count": len(pkgs)})


@app.route("/api/publish", methods=["POST"])
def publish_package():
    """
    VULNERABILITY: Authentication can be bypassed two ways:
    1. Provide X-API-Key: admin123 (hardcoded fallback key in comments)
    2. Send X-Forwarded-For with an internal IP (172.x.x.x, 10.x.x.x, etc.)
    The real prod key is never shown but the fallback "admin123" works.
    """
    api_key = request.headers.get("X-API-Key", "")

    # Auth check: valid prod key OR hardcoded fallback OR "internal" network
    # BUG: The fallback key 'admin123' was never removed from the codebase
    authed = (
        api_key == VALID_API_KEY
        or api_key == "admin123"
        or is_internal_request()
    )

    if not authed:
        return jsonify({
            "error": "Unauthorized",
            "hint": "Valid API key required. Internal network requests bypass auth."
        }), 401

    if "package" not in request.files:
        return jsonify({"error": "Missing 'package' file field"}), 400

    pkg_file = request.files["package"]
    filename = pkg_file.filename

    # Basic validation
    if not (filename.endswith(".tar.gz") or filename.endswith(".whl")):
        return jsonify({"error": "Only .tar.gz and .whl packages accepted"}), 400

    # Parse metadata from form or JSON
    meta_raw = request.form.get("metadata", "{}")
    try:
        meta = json.loads(meta_raw)
    except Exception:
        meta = {}

    name = meta.get("name", filename.split("-")[0])
    version = meta.get("version", "0.0.1")
    description = meta.get("description", "No description provided")
    author = meta.get("author", "anonymous")

    # Save the file
    save_path = PACKAGES_DIR / filename
    pkg_file.save(str(save_path))

    # Compute hash
    md5 = hashlib.md5(save_path.read_bytes()).hexdigest()

    # Register in index
    pkgs = load_packages()
    # Remove old version if exists
    pkgs = [p for p in pkgs if not (p["name"] == name and p["version"] == version)]
    pkgs.append({
        "name": name,
        "version": version,
        "description": description,
        "author": author,
        "filename": filename,
        "md5": md5,
        "published_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "install_count": 0
    })
    save_packages(pkgs)

    return jsonify({
        "status": "published",
        "package": name,
        "version": version,
        "filename": filename,
        "md5": md5
    }), 201


@app.route("/api/packages/<name>/install-count", methods=["POST"])
def increment_install(name):
    """Called by CI runner after successful install."""
    pkgs = load_packages()
    for p in pkgs:
        if p["name"] == name:
            p["install_count"] = p.get("install_count", 0) + 1
    save_packages(pkgs)
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    print("[*] CorpPyPI Registry starting on :8080")
    app.run(host="0.0.0.0", port=8080, debug=False)
