#!/usr/bin/env python3
"""
Fake Gitea-like git server.
Vulnerabilities:
1. /.git/ directory is fully exposed — serves raw git objects
2. The first commit contains WEBHOOK_SECRET in .env (blob still in objects/)
3. POST /internal/webhook runs pipeline commands (internal endpoint)
Exploitation: enumerate /.git/logs/HEAD -> get commit hashes ->
              fetch /.git/objects/xx/yy -> decompress zlib -> read .env content
"""
import os
import zlib
import hashlib
import subprocess
from pathlib import Path
from flask import Flask, request, jsonify, Response, abort, render_template_string

app = Flask(__name__)

REPO_PATH = Path("/repo")
WEBHOOK_RUNNER_URL = os.environ.get("WEBHOOK_RUNNER_URL", "http://webhook-runner:9001")

HTML_INDEX = """<!DOCTYPE html>
<html>
<head>
  <title>CorpGit — Internal Git Server</title>
  <style>
    body { font-family: -apple-system, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }
    h1 { color: #58a6ff; }
    .repo { background: #161b22; border: 1px solid #30363d; padding: 1.5rem; border-radius: 6px; margin: 1rem 0; }
    .repo h3 { margin: 0 0 0.5rem 0; }
    a { color: #58a6ff; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .meta { color: #8b949e; font-size: 0.9rem; }
    code { background: #1f2937; padding: 2px 6px; border-radius: 3px; }
  </style>
</head>
<body>
  <h1>CorpGit — Internal Git Server</h1>
  <p class="meta">Self-hosted Git service for the DevOps team</p>
  <div class="repo">
    <h3><a href="/corp/pipeline">corp/pipeline</a></h3>
    <p>Main CI/CD pipeline configuration</p>
    <p class="meta">Last commit: Remove secrets from repo, use vault instead</p>
  </div>
  <hr>
  <p class="meta">CorpGit v2.1.0 | <a href="/corp/pipeline/commits">Commit History</a></p>
</body>
</html>"""

HTML_REPO = """<!DOCTYPE html>
<html>
<head>
  <title>corp/pipeline — CorpGit</title>
  <style>
    body { font-family: -apple-system, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }
    h1 { color: #58a6ff; }
    .file { padding: 0.4rem 0.8rem; border-bottom: 1px solid #30363d; }
    .file a { color: #58a6ff; }
    table { width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #30363d; border-radius: 6px; }
    td, th { padding: 0.5rem 1rem; text-align: left; }
    th { border-bottom: 1px solid #30363d; color: #8b949e; }
    a { color: #58a6ff; text-decoration: none; }
    .commit-msg { color: #8b949e; font-size: 0.9rem; }
    code { background: #1f2937; padding: 2px 6px; border-radius: 3px; }
  </style>
</head>
<body>
  <h1>corp / pipeline</h1>
  <p><a href="/corp/pipeline/commits">Commits</a> |
     <a href="/corp/pipeline/raw/main/pipeline.yml">pipeline.yml</a> |
     <a href="/corp/pipeline/raw/main/README.md">README.md</a></p>
  <table>
    <tr><th>File</th><th>Last commit</th></tr>
    <tr><td><a href="/corp/pipeline/raw/main/README.md">README.md</a></td><td class="commit-msg">Remove secrets from repo, use vault instead</td></tr>
    <tr><td><a href="/corp/pipeline/raw/main/pipeline.yml">pipeline.yml</a></td><td class="commit-msg">Remove secrets from repo, use vault instead</td></tr>
    <tr><td><a href="/corp/pipeline/raw/main/deploy.sh">deploy.sh</a></td><td class="commit-msg">Remove secrets from repo, use vault instead</td></tr>
  </table>
  <hr>
  <p>Clone: <code>git clone http://this-server:8080/corp/pipeline.git</code></p>
</body>
</html>"""

HTML_COMMITS = """<!DOCTYPE html>
<html>
<head>
  <title>Commits — corp/pipeline</title>
  <style>
    body { font-family: -apple-system, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }
    h1 { color: #58a6ff; }
    .commit { background: #161b22; border: 1px solid #30363d; padding: 1rem; margin: 0.5rem 0; border-radius: 4px; }
    .hash { font-family: monospace; color: #58a6ff; font-size: 0.85rem; }
    .msg { font-weight: bold; }
    .meta { color: #8b949e; font-size: 0.85rem; }
    a { color: #58a6ff; }
  </style>
</head>
<body>
  <h1>Commit History — corp/pipeline</h1>
  {% for c in commits %}
  <div class="commit">
    <p class="hash"><a href="/corp/pipeline/commit/{{ c.hash }}">{{ c.hash[:8] }}</a> &nbsp; {{ c.hash }}</p>
    <p class="msg">{{ c.message }}</p>
    <p class="meta">{{ c.author }} · {{ c.date }}</p>
  </div>
  {% endfor %}
</body>
</html>"""


def git_log():
    """Return list of commits from the repo."""
    try:
        result = subprocess.run(
            ["git", "log", "--pretty=format:%H|%s|%an|%ai"],
            cwd=str(REPO_PATH),
            capture_output=True, text=True
        )
        commits = []
        for line in result.stdout.strip().split("\n"):
            if "|" in line:
                parts = line.split("|", 3)
                commits.append({
                    "hash": parts[0],
                    "message": parts[1],
                    "author": parts[2],
                    "date": parts[3][:19] if len(parts) > 3 else ""
                })
        return commits
    except Exception as e:
        print(f"git log error: {e}")
        return []


def git_show_file(ref, path):
    """Return raw file content at given ref."""
    try:
        result = subprocess.run(
            ["git", "show", f"{ref}:{path}"],
            cwd=str(REPO_PATH),
            capture_output=True, text=True
        )
        if result.returncode == 0:
            return result.stdout
        return None
    except Exception:
        return None


@app.route("/")
def index():
    return render_template_string(HTML_INDEX)


@app.route("/corp/pipeline")
@app.route("/corp/pipeline/")
def repo_page():
    return render_template_string(HTML_REPO)


@app.route("/corp/pipeline/commits")
def commits_page():
    commits = git_log()
    return render_template_string(HTML_COMMITS, commits=commits)


@app.route("/corp/pipeline/commit/<commit_hash>")
def commit_detail(commit_hash):
    try:
        result = subprocess.run(
            ["git", "show", "--stat", commit_hash],
            cwd=str(REPO_PATH),
            capture_output=True, text=True
        )
        if result.returncode != 0:
            abort(404)
        return Response(result.stdout, mimetype="text/plain")
    except Exception:
        abort(404)


@app.route("/corp/pipeline/raw/<ref>/<path:filepath>")
def raw_file(ref, filepath):
    content = git_show_file(ref, filepath)
    if content is None:
        abort(404)
    return Response(content, mimetype="text/plain")


# =====================================================================
# VULNERABILITY: /.git/ directory is fully served (git dumping attack)
# =====================================================================

@app.route("/.git/")
@app.route("/.git/<path:git_path>")
def serve_git(git_path=""):
    """Serves the .git directory — allows complete repository reconstruction."""
    target = REPO_PATH / ".git" / git_path

    # Serve directory listing
    if target.is_dir():
        entries = []
        for item in sorted(target.iterdir()):
            rel = str(item.relative_to(REPO_PATH / ".git"))
            entries.append(f'<a href="/.git/{rel}{"/" if item.is_dir() else ""}">{item.name}{"/" if item.is_dir() else ""}</a>')
        html = f"<html><body><h2>.git/{git_path}</h2><pre>" + "\n".join(entries) + "</pre></body></html>"
        return Response(html, mimetype="text/html")

    # Serve file
    if target.is_file():
        data = target.read_bytes()
        return Response(data, mimetype="application/octet-stream")

    abort(404)


# =====================================================================
# Webhook endpoints
# =====================================================================

@app.route("/webhook/register", methods=["POST"])
def register_webhook():
    """
    Register a webhook. Requires HMAC-SHA256 signature.
    Hint visible in error message: uses the WEBHOOK_SECRET.
    """
    import hmac
    data = request.get_data()
    sig = request.headers.get("X-Hub-Signature-256", "")

    # The secret is what's in the deleted .env — players must extract it from git history
    secret = os.environ.get("WEBHOOK_SECRET", "sup3rs3cr3t_hmac_k3y")
    expected = "sha256=" + hmac.new(secret.encode(), data, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(sig, expected):
        return jsonify({
            "error": "Invalid HMAC signature",
            "hint": "Check the pipeline documentation for signature format",
            "format": "X-Hub-Signature-256: sha256=<hmac-sha256-hex>"
        }), 401

    body = request.get_json(force=True, silent=True) or {}
    url = body.get("url", "")
    return jsonify({"status": "registered", "url": url, "events": ["push", "tag"]})


@app.route("/internal/webhook", methods=["POST"])
def internal_webhook():
    """Internal webhook endpoint — runs pipeline steps. Accessible from internal_net."""
    import hmac
    data = request.get_data()
    sig = request.headers.get("X-Hub-Signature-256", "")
    secret = os.environ.get("WEBHOOK_SECRET", "sup3rs3cr3t_hmac_k3y")
    expected = "sha256=" + hmac.new(secret.encode(), data, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(sig, expected):
        return jsonify({"error": "Unauthorized"}), 401

    body = request.get_json(force=True, silent=True) or {}
    ref = body.get("ref", "refs/heads/main")
    steps = body.get("steps", ["echo Pipeline triggered"])

    outputs = []
    for step in steps:
        try:
            result = subprocess.run(
                step, shell=True, capture_output=True, text=True, timeout=10,
                cwd="/tmp"
            )
            outputs.append({"step": step, "stdout": result.stdout, "stderr": result.stderr, "rc": result.returncode})
        except Exception as e:
            outputs.append({"step": step, "error": str(e)})

    return jsonify({"status": "executed", "ref": ref, "outputs": outputs})


# =====================================================================
# Git smart HTTP protocol (minimal — enough for git clone)
# =====================================================================

@app.route("/corp/pipeline.git/info/refs")
def git_info_refs():
    service = request.args.get("service", "")
    if service == "git-upload-pack":
        result = subprocess.run(
            ["git", "upload-pack", "--stateless-rpc", "--advertise-refs", "."],
            cwd=str(REPO_PATH),
            capture_output=True
        )
        pkt = f"# service={service}\n"
        pkt_line = f"{len(pkt) + 4:04x}{pkt}0000".encode()
        return Response(pkt_line + result.stdout,
                        mimetype="application/x-git-upload-pack-advertisement")
    abort(403)


@app.route("/corp/pipeline.git/git-upload-pack", methods=["POST"])
def git_upload_pack():
    result = subprocess.run(
        ["git", "upload-pack", "--stateless-rpc", "."],
        cwd=str(REPO_PATH),
        input=request.data,
        capture_output=True
    )
    return Response(result.stdout, mimetype="application/x-git-upload-pack-result")


if __name__ == "__main__":
    print("[*] CorpGit server starting on :8080")
    app.run(host="0.0.0.0", port=8080, debug=False)
