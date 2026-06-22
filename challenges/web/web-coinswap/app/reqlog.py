"""Logging de requests HTTP para el SIEM stream."""
import json, logging, os, threading, urllib.request
logger = logging.getLogger("reqlog")
COLLECTOR_URL = os.environ.get("COLLECTOR_URL", "http://collector:9000")
TEAM_ID = os.environ.get("TEAM_ID", "team_local")
CHALLENGE_ID = os.environ.get("CHALLENGE_ID", "unknown")

def _post(payload: dict) -> None:
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(f"{COLLECTOR_URL}/reqlog", data=data,
            headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=1.5)
    except Exception as exc:
        logger.debug("reqlog drop: %s", exc)

def reqlog_http(src_ip, method, path, query="", headers=None, body=""):
    payload = {"team_id": TEAM_ID, "challenge_id": CHALLENGE_ID,
        "src_ip": src_ip, "method": method, "path": path, "query": query,
        "headers": {k: v for k, v in (headers or {}).items()
                    if k.lower() not in ("cookie", "authorization")},
        "body_snippet": body[:512]}
    threading.Thread(target=_post, args=(payload,), daemon=True).start()
