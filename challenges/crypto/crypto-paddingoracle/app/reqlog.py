"""reqlog — logging de peticiones de jugadores hacia un reto."""
import json
import os
import sys
from datetime import datetime, timezone

MAX_BODY = 8192

CHALLENGE_ID = os.environ.get("CHALLENGE_ID", "unknown")
_FLAG = os.environ.get("FLAG", "")
_FLAG_REDACTION = "[FLAG-REDACTADA]"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _redact_flag(text: str) -> str:
    if not text or not _FLAG:
        return text
    if _FLAG in text:
        return text.replace(_FLAG, _FLAG_REDACTION)
    return text


def _coerce_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        try:
            return bytes(value).decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            return "hex:" + bytes(value).hex()
    return str(value)


def _truncate(text: str) -> str:
    if text is None:
        return ""
    if len(text) > MAX_BODY:
        return text[:MAX_BODY] + f"...[+{len(text) - MAX_BODY} chars]"
    return text


def _emit(record: dict) -> None:
    try:
        line = "CTFREQ " + json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        print(line, flush=True)
    except Exception:
        try:
            sys.stdout.flush()
        except Exception:
            pass


def reqlog_http(src_ip, method, path, query="", headers=None, body="") -> None:
    hdrs = {}
    if headers:
        for k, v in dict(headers).items():
            hdrs[str(k)] = _redact_flag(_coerce_text(v))

    record = {
        "ts": _now_iso(),
        "challenge_id": CHALLENGE_ID,
        "src_ip": _coerce_text(src_ip) or "?",
        "proto": "http",
        "method": _coerce_text(method) or "?",
        "path": _coerce_text(path) or "/",
        "query": _redact_flag(_coerce_text(query)),
        "headers": hdrs,
        "body": _truncate(_redact_flag(_coerce_text(body))),
    }
    _emit(record)


def reqlog_tcp(src_ip, data, label=None) -> None:
    headers = {}
    if label:
        headers["kind"] = str(label)

    record = {
        "ts": _now_iso(),
        "challenge_id": CHALLENGE_ID,
        "src_ip": _coerce_text(src_ip) or "?",
        "proto": "tcp",
        "method": None,
        "path": None,
        "query": None,
        "headers": headers,
        "body": _truncate(_redact_flag(_coerce_text(data))),
    }
    _emit(record)
