#!/usr/bin/env python3
"""
CI Runner — polls the internal registry every 30 seconds.
For each new package not yet installed, downloads and pip-installs it.
Runs as root; postinstall hooks in setup.py execute with full privileges.
"""
import os
import json
import time
import subprocess
import tempfile
import requests
from pathlib import Path

REGISTRY_URL = os.environ.get("REGISTRY_URL", "http://registry:8080")
BUILD_SERVER_URL = os.environ.get("BUILD_SERVER_URL", "http://build-server:9000")
INSTALLED_DB = Path("/tmp/installed.json")
POLL_INTERVAL = 30  # seconds


def load_installed():
    if INSTALLED_DB.exists():
        try:
            return json.loads(INSTALLED_DB.read_text())
        except Exception:
            return {}
    return {}


def save_installed(db):
    INSTALLED_DB.write_text(json.dumps(db, indent=2))


def get_packages():
    try:
        r = requests.get(f"{REGISTRY_URL}/api/packages", timeout=10)
        r.raise_for_status()
        return r.json().get("packages", [])
    except Exception as e:
        print(f"[!] Failed to fetch packages: {e}")
        return []


def install_package(pkg):
    name = pkg["name"]
    version = pkg["version"]
    filename = pkg["filename"]
    download_url = f"{REGISTRY_URL}/packages/{filename}"

    print(f"[+] Installing {name}=={version} from {download_url}")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Download
        try:
            r = requests.get(download_url, timeout=30)
            r.raise_for_status()
        except Exception as e:
            print(f"[!] Download failed for {name}: {e}")
            return False

        pkg_path = os.path.join(tmpdir, filename)
        with open(pkg_path, "wb") as f:
            f.write(r.content)

        # pip install — runs setup.py postinstall hooks
        cmd = [
            "pip", "install",
            "--no-index",           # use only local file
            "--no-deps",
            "-q",
            pkg_path
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=tmpdir
            )
            if result.returncode == 0:
                print(f"[+] Successfully installed {name}=={version}")
                # Notify registry
                try:
                    requests.post(
                        f"{REGISTRY_URL}/api/packages/{name}/install-count",
                        timeout=5
                    )
                except Exception:
                    pass
                return True
            else:
                print(f"[!] pip install failed for {name}:\n{result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            print(f"[!] pip install timed out for {name}")
            return False


def trigger_build():
    try:
        r = requests.post(f"{BUILD_SERVER_URL}/trigger-build",
                          json={"source": "ci-runner"},
                          timeout=10)
        print(f"[+] Build triggered: {r.status_code}")
    except Exception as e:
        print(f"[!] Could not trigger build: {e}")


def main():
    print(f"[*] CI Runner started. Registry: {REGISTRY_URL}")
    print(f"[*] Poll interval: {POLL_INTERVAL}s")

    # Wait for registry to be ready
    for attempt in range(20):
        try:
            requests.get(f"{REGISTRY_URL}/api/packages", timeout=5)
            print("[+] Registry is reachable.")
            break
        except Exception:
            print(f"[.] Waiting for registry... ({attempt+1}/20)")
            time.sleep(5)

    while True:
        installed = load_installed()
        packages = get_packages()

        new_installs = 0
        for pkg in packages:
            key = f"{pkg['name']}=={pkg['version']}"
            if key not in installed:
                success = install_package(pkg)
                installed[key] = {
                    "installed": success,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                }
                save_installed(installed)
                if success:
                    new_installs += 1

        if new_installs > 0:
            trigger_build()

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
