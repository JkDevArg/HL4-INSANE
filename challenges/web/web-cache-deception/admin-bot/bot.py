#!/usr/bin/env python3
"""
Admin bot — simulates the admin user visiting the portal.
Every 30 seconds:
  1. Logs in as admin through the nginx proxy
  2. Visits /profile/info.css (the vulnerable cached endpoint)
  3. This causes nginx to cache the admin's profile response
The attacker fetches /profile/info.css before the cache expires (60s TTL)
to get the cached admin response containing the flag.
"""
import os
import time
import requests
import logging

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("admin-bot")

PROXY_URL = os.environ.get("PROXY_URL", "http://nginx-proxy:8080")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "adminpass123")
INTERVAL = 30  # seconds between visits


def wait_for_proxy(max_attempts=30):
    for i in range(max_attempts):
        try:
            r = requests.get(f"{PROXY_URL}/login", timeout=5)
            log.info("Proxy is up.")
            return True
        except Exception:
            log.info(f"Waiting for proxy... ({i+1}/{max_attempts})")
            time.sleep(5)
    return False


def admin_visit():
    session = requests.Session()
    try:
        # Login as admin
        resp = session.post(
            f"{PROXY_URL}/login",
            data={"username": "admin", "password": ADMIN_PASSWORD},
            allow_redirects=True,
            timeout=15
        )
        if "Profile" not in resp.text and "profile" not in resp.url:
            log.warning(f"Login may have failed. Status: {resp.status_code}")
            return

        log.info("Admin logged in successfully.")

        # Visit the sensitive cached endpoint
        # This response will be cached by nginx keyed to /profile/info.css
        resp2 = session.get(
            f"{PROXY_URL}/profile/info.css",
            timeout=15
        )
        cache_status = resp2.headers.get("X-Cache-Status", "unknown")
        log.info(
            f"Visited /profile/info.css — status={resp2.status_code} "
            f"cache={cache_status} size={len(resp2.content)}B"
        )

        # Also visit the normal profile page
        session.get(f"{PROXY_URL}/profile", timeout=15)

    except Exception as e:
        log.error(f"Admin bot visit failed: {e}")


def main():
    log.info(f"Admin bot starting. Target: {PROXY_URL}")
    log.info(f"Visit interval: {INTERVAL}s")

    if not wait_for_proxy():
        log.error("Could not reach proxy. Exiting.")
        return

    # Initial delay so containers fully start
    time.sleep(10)

    while True:
        log.info("--- Admin bot performing visit ---")
        admin_visit()
        log.info(f"Next visit in {INTERVAL}s")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
