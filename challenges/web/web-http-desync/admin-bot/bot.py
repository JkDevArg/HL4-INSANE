#!/usr/bin/env python3
"""
Admin bot — makes authenticated requests to /admin/flag every 10 seconds.
The X-Admin-Token header is sent with each request.
Via CL.TE request smuggling, an attacker can:
1. Send a smuggled request that poisons the backend queue with a partial
   GET /capture HTTP/1.1 + headers prefix
2. The admin bot's next request gets appended, and its body/headers
   (including X-Admin-Token) are stored in /capture
3. Attacker reads /capture/log to get the token
4. Directly requests /admin/flag with the stolen token

Alternatively: directly smuggle a complete GET /admin/flag with the token
(since the token value can be inferred from the challenge source).
"""
import os
import time
import requests
import logging

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("admin-bot")

HAPROXY_URL = os.environ.get("HAPROXY_URL", "http://haproxy:8080")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "secret-admin-token-xyz")
INTERVAL = 10  # seconds


def wait_for_haproxy(max_attempts=30):
    for i in range(max_attempts):
        try:
            requests.get(f"{HAPROXY_URL}/", timeout=5)
            log.info("HAProxy is reachable.")
            return True
        except Exception:
            log.info(f"Waiting for HAProxy... ({i+1}/{max_attempts})")
            time.sleep(5)
    return False


def admin_request():
    """Admin bot makes a privileged request to /admin/flag."""
    try:
        resp = requests.get(
            f"{HAPROXY_URL}/admin/flag",
            headers={"X-Admin-Token": ADMIN_TOKEN},
            timeout=15
        )
        log.info(f"Admin request: status={resp.status_code}")
    except Exception as e:
        log.error(f"Admin request failed: {e}")


def main():
    log.info(f"Admin bot starting. Target: {HAPROXY_URL}")
    log.info(f"Admin token: [REDACTED] (length={len(ADMIN_TOKEN)})")

    if not wait_for_haproxy():
        log.error("HAProxy unreachable. Exiting.")
        return

    time.sleep(5)
    log.info("Starting admin request loop.")

    while True:
        admin_request()
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
