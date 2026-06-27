"""
caster-overlay — Overlay PÚBLICO para comentaristas/stream (OBS).

Muestra en vivo la actividad de los jugadores del CTF, traducida a texto
NARRABLE en español (para que el comentarista lea en voz alta qué hace cada
equipo) y ANONIMIZADA: ninguna IP real sale al aire (ver app/anonymize.py).

Fuente de datos: Loki (HTTP API /loki/api/v1/query_range).

Estructura REAL de los datos (las líneas traen el contenido EN LA LÍNEA, no
en labels):

  {job="suricata"}    -> JSON EVE. El grueso es event_type=flow (RUIDO, se
                         descarta). Solo interesa event_type=alert, con
                         src_ip / dest_ip / dest_port / alert.signature /
                         alert.category.
  {job="dns"}         -> texto dnsmasq:
                          "... query[A] api.openai.com from 10.10.1.2"
                          "... reply api.openai.com is 0.0.0.0"  (sinkhole IA)
                          "... reply github.com is 1.2.3.4"
  {source="platform"} -> JSON con event_type / team_id / detail.
  {source="vpn"}      -> JSON con event_type vpn_connect/disconnect/ban.
  {job="firewall"}    -> INTERNET_BLOCK por paquete (RUIDO, NO va al feed).

Diseñado para ser robusto: si Loki está caído, los endpoints devuelven
estructuras vacías en vez de fallar.
"""

import ipaddress
import json
import os
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .anonymize import anonymize, anonymize_ip, team_from_ip, team_from_team_id, _player_label

# Anonimización SUAVE para PAYLOADS (body/query de las peticiones): muestra el
# ataque tal cual lo escribió el jugador (p.ej. 169.254.169.254 en un SSRF, o
# IPs/URLs objetivo) pero sustituye SOLO las IPs del rango VPN (10.10.x.x) por
# su etiqueta (Equipo NN / plataforma / siem), para no exponer IPs de jugadores
# ni del propio SIEM. Todo lo demás del payload se deja CRUDO (completo).
_PAYLOAD_VPN_IP_RE = re.compile(r"(?<![\w.])(10\.10\.\d{1,3}\.\d{1,3})(?![\w.])")


def anonymize_payload(s) -> str:
    if not s:
        return ""
    return _PAYLOAD_VPN_IP_RE.sub(lambda m: anonymize_ip(m.group(1)), str(s))

# ----------------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------------
LOKI_URL = os.environ.get("LOKI_URL", "http://loki:3100").rstrip("/")
WINDOW_MIN = int(os.environ.get("WINDOW_MIN", "1440"))      # ventana histórica (scoreboard, violations)
STATS_WIN_MIN = int(os.environ.get("STATS_WIN_MIN", "60"))  # ventana contadores en vivo (stats header)
SESSION_TTL_MIN = int(os.environ.get("SESSION_TTL_MIN", "20"))
CTF_NAME = os.environ.get("CTF_NAME", "CTF HACKL4BS")
LOKI_TIMEOUT = float(os.environ.get("LOKI_TIMEOUT", "15"))

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

# Ventana de deduplicación para consultas DNS repetidas (mismo equipo+dominio).
DNS_DEDUP_SEC = 60
# Dedup fuerte del feed completo por (equipo, dominio/detalle) en esta ventana.
FEED_DEDUP_SEC = 60
# Dedup fuerte de "trabajando en reto": máx 1 por (equipo, reto) cada 30s.
# Los eventos flow de Suricata hacia un reto son MUY frecuentes.
CHALLENGE_DEDUP_SEC = 30

# --- Detección de ESCANEO de puertos (nmap) por flujos ---
# No hay alertas IDS (event_type=alert) que disparen el nmap, así que el escaneo
# se infiere de los flows: un equipo que toca MUCHOS puertos distintos en poco
# tiempo está escaneando (incl. puertos cerrados, que es justo lo que delata el
# scan). Umbrales y ventana:
SCAN_PORTS_PER_HOST = 10      # >= N puertos distintos en UN mismo host -> scan
SCAN_PORTS_TOTAL = 15         # o >= N puertos distintos en TODA la red de retos
SCAN_WINDOW_SEC = 60          # ventana de agregación para contar puertos
SCAN_DEDUP_SEC = 60           # no re-emitir el mismo (equipo, host) en esta ventana
# Una sesión VPN se considera "viva" si su último evento connect es más
# reciente que esta antigüedad (evita contar sesiones zombie).
SESSION_TTL_SEC = SESSION_TTL_MIN * 60

# Iconos por tipo de evento (kind).
ICONS = {
    "login": "🔑",
    "login_fail": "⛔",
    "submit": "📝",
    "flag_ok": "✅",
    "flag_fail": "❌",
    "cheat": "🔴",
    "vpn_connect": "🟢",
    "vpn_disconnect": "🟡",
    "ban": "⛔",
    "ids": "🚨",
    "scan": "🛰️",
    "ai_block": "🚫",
    "dns": "🌐",
    "challenge": "🎯",
    "request": "📡",
}

# Truncado del body en el TEXTO del feed (la vista por equipo expone el body
# completo vía /api/team/{nn}).
REQ_FEED_BODY_MAX = 160
# Dedup de peticiones CTFREQ idénticas (misma línea cruda) en esta ventana.
REQ_DEDUP_SEC = 8

# ----------------------------------------------------------------------------
# Mapa de retos: red de reto 172.30.N.0/24 (N = equipo); el ÚLTIMO octeto
# identifica el reto (servicio Docker fijo). challenge_for(ip) traduce una IP
# de la red de retos a su nombre legible para narrar "qué reto atacan".
# ----------------------------------------------------------------------------
CHALLENGE_MAP = {
    10: "Reto Web",
    20: "Reto API",
    30: "Reto Cripto",
    40: "Reto Reversing",
}

_CHALLENGE_NET = ipaddress.ip_network("172.30.0.0/16")


def challenge_for(ip: str):
    """
    Si `ip` pertenece a la red de retos (172.30.0.0/16), devuelve el nombre
    legible del reto según el último octeto (CHALLENGE_MAP). Si el octeto no
    está mapeado devuelve un genérico 'reto (.NN)'. Fuera de 172.30/16 -> None.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version != 4 or addr not in _CHALLENGE_NET:
        return None
    last = int(str(ip).split(".")[3])
    return CHALLENGE_MAP.get(last, f"reto (.{last})")

# ----------------------------------------------------------------------------
# Diccionarios de traducción a lenguaje narrable
# ----------------------------------------------------------------------------

# Traducción de firmas/categorías suricata -> frase legible en español.
# Cada entrada: (regex, frase). Se evalúan en orden; primera que matchea gana.
SIG_TRANSLATIONS = [
    (re.compile(r"\bnmap\b", re.I), "ejecutó un escaneo de puertos (nmap)"),
    (re.compile(r"masscan", re.I), "ejecutó un escaneo masivo de puertos (masscan)"),
    (re.compile(r"port ?scan|portscan|scan|sweep|recon", re.I), "ejecutó un escaneo de puertos"),
    (re.compile(r"sqlmap", re.I), "lanzó una inyección SQL automatizada (sqlmap)"),
    (re.compile(r"\bsql ?injection|union select|\bsqli\b", re.I), "intentó una inyección SQL"),
    (re.compile(r"nikto|gobuster|dirb|dirbuster|feroxbuster|ffuf|wfuzz", re.I), "hizo fuzzing de directorios web"),
    (re.compile(r"path ?traversal|directory traversal|\.\./|\bLFI\b|local file inclusion", re.I), "intentó un path traversal / inclusión de archivos"),
    (re.compile(r"\bRFI\b|remote file inclusion", re.I), "intentó una inclusión remota de archivos (RFI)"),
    (re.compile(r"\bXSS\b|cross.site.script", re.I), "intentó un ataque XSS"),
    (re.compile(r"command injection|\brce\b|remote code", re.I), "intentó ejecución remota de comandos (RCE)"),
    (re.compile(r"brute.?force|hydra|password guess", re.I), "lanzó un ataque de fuerza bruta"),
    (re.compile(r"hydra", re.I), "lanzó fuerza bruta con hydra"),
    (re.compile(r"metasploit|meterpreter", re.I), "usó Metasploit"),
    (re.compile(r"reverse shell|shellcode|\bshell\b", re.I), "intentó abrir una shell"),
    (re.compile(r"\bexploit\b|\bCVE-", re.I), "intentó explotar una vulnerabilidad"),
    (re.compile(r"\bDoS\b|denial of service|flood", re.I), "generó tráfico de denegación de servicio"),
    (re.compile(r"trojan|malware|backdoor", re.I), "tráfico clasificado como malware/backdoor"),
]

# Lo que cuenta como "escaneo" para el contador de stats.
SCAN_SIG_RE = re.compile(r"nmap|masscan|port ?scan|portscan|\bscan\b|sweep|recon", re.I)

# Dominios de telemetría / ruido que NO interesan al stream.
DNS_NOISE_RE = re.compile(
    r"(akamai|akamaiedge\.net|akadns|"
    r"\.windows\.com|windowsupdate|\.microsoft\.com|microsoftonline|"
    r"msftncsi|msftconnecttest|msedge|edge\.microsoft|edgedl|"
    r"\.gstatic\.com|\.googleapis\.com|googleusercontent|"
    r"\.bing\.com|bing\.net|"
    r"brave|brave\.com|brave-core|"
    r"mozilla|firefox|spotify|"
    r"ocsp|crl\.|\.crl|pki\.|symcb|symcd|digicert|verisign|globalsign|letsencrypt|"
    r"\.apple\.com|push\.apple|icloud|"
    r"telemetry|settings-win|update\.|cdn\.|cloudflare-dns|"
    r"in-addr\.arpa|ip6\.arpa|\.local$|"
    r"connectivitycheck|detectportal|nmcheck|"
    r"\.ntp\.|pool\.ntp|time\.windows|time\.apple|"
    r"doubleclick|google-analytics|googletagmanager|googleadservices|"
    r"fbcdn|facebook|instagram|whatsapp|fonts\.|"
    r"sentry|newrelic|segment\.io|amplitude|mixpanel)",
    re.I,
)

# Dominios "interesantes" que SIEMPRE deben mostrarse (prioritarios).
DNS_INTERESTING_RE = re.compile(
    r"(openai|chatgpt|anthropic|claude|gemini|bard|copilot|perplexity|deepseek|"
    r"mistral|cohere|huggingface|poe\.com|character\.ai|x\.ai|grok|copilot\.microsoft|"
    r"github|gitlab|pastebin|exploit-db|exploitdb|cve|nvd\.nist|"
    r"hackthebox|tryhackme|portswigger|owasp|"
    r"shodan|censys|virustotal|"
    r"ngrok|burpcollaborator|interact\.sh|requestbin|webhook\.site|"
    r"raw\.githubusercontent|gist\.github)",
    re.I,
)

app = FastAPI(title="caster-overlay", docs_url=None, redoc_url=None)


# ----------------------------------------------------------------------------
# Loki helpers
# ----------------------------------------------------------------------------
def _ns(dt: datetime) -> int:
    return int(dt.timestamp() * 1_000_000_000)


async def loki_query_range(query: str, limit: int = 500, window_min: int = None):
    """
    Consulta /loki/api/v1/query_range. Devuelve lista de
    (ts_ns:int, line:str, labels:dict) o [] si algo falla (Loki caído).
    window_min: ventana en minutos (default WINDOW_MIN).
    """
    win = window_min if window_min is not None else WINDOW_MIN
    now = datetime.now(timezone.utc)
    start = _ns(now) - win * 60 * 1_000_000_000
    end = _ns(now)
    params = {
        "query": query,
        "start": str(start),
        "end": str(end),
        "limit": str(limit),
        "direction": "backward",
    }
    out = []
    try:
        async with httpx.AsyncClient(timeout=LOKI_TIMEOUT) as client:
            r = await client.get(f"{LOKI_URL}/loki/api/v1/query_range", params=params)
            r.raise_for_status()
            data = r.json()
        for stream in data.get("data", {}).get("result", []):
            labels = stream.get("stream", {})
            for value in stream.get("values", []):
                ts_ns = int(value[0])
                line = value[1]
                out.append((ts_ns, line, labels))
    except Exception:
        return []
    return out


def _parse_json_line(line: str):
    """Extrae el JSON embebido en la línea (collector / suricata EVE)."""
    line = (line or "").strip()
    if not line:
        return {}
    if line[0] == "{":
        try:
            return json.loads(line)
        except Exception:
            pass
    # A veces hay prefijo logfmt antes del JSON: busca la primera llave.
    i = line.find("{")
    if i >= 0:
        try:
            return json.loads(line[i:])
        except Exception:
            pass
    return {}


def _rel_ts_iso(ts_ns: int) -> str:
    return datetime.fromtimestamp(ts_ns / 1_000_000_000, tz=timezone.utc).isoformat()


def _challenge_label(chal) -> str:
    """challenge_id -> texto legible. 'web_sqli_01' -> 'web sqli 01'."""
    if not chal:
        return "un reto"
    s = str(chal).strip()
    s = s.replace("_", " ").replace("-", " ")
    return s


def _item(ts_ns, team, kind, severity, text, dedup=None, priority=1, anon=True):
    """
    Construye un item del feed.

    anon=True (default): anonimiza SIEMPRE el texto (red de seguridad para la
       mayoría de eventos). anon=False: el caller YA dejó el texto seguro (se
       usa en peticiones CTFREQ, donde el body/query se muestra crudo salvo las
       IPs VPN, vía anonymize_payload).
    dedup    : clave estable para deduplicar variantes del mismo evento.
    priority : 2 = actividad CTF/amenazas, 1 = normal, 0 = navegación trivial.
    """
    team_a = anonymize(team)
    text_out = text if not anon else anonymize(text)
    return {
        "ts": _rel_ts_iso(ts_ns),
        "ts_ns": ts_ns,
        "team": team_a,
        "kind": kind,
        "severity": severity,
        "text": text_out,
        "icon": ICONS.get(kind, "•"),
        "_dedup": dedup if dedup is not None else (team_a, text_out),
        "_priority": priority,
    }


# ----------------------------------------------------------------------------
# Mapeadores por fuente  (devuelven un item dict, o None para descartar)
# ----------------------------------------------------------------------------
def map_platform(ts_ns, line, labels):
    """
    source=platform: login / submit / flag_ok / flag_fail / cheat_flag_share.
    Devuelve item o None si no se puede narrar.
    """
    ev = _parse_json_line(line)
    if not ev:
        return None
    etype = (ev.get("event_type") or labels.get("event_type") or "").lower()
    detail = ev.get("detail") or {}
    if not isinstance(detail, dict):
        detail = {}

    team = team_from_team_id(ev.get("team_id") or labels.get("team_id"))
    if not team:
        team = team_from_ip(ev.get("src_ip") or detail.get("src_ip") or "")
    team = team or "Equipo ?"

    chal = ev.get("challenge_id") or detail.get("challenge_id") or ""
    chal_txt = _challenge_label(chal)

    if etype == "login":
        result = (ev.get("result") or detail.get("result") or "").lower()
        if result == "ok" or result == "success" or detail.get("ok") is True:
            return _item(ts_ns, team, "login", "info", f"{team} inició sesión", priority=2)
        reason = detail.get("reason") or ev.get("reason") or "credenciales inválidas"
        return _item(ts_ns, team, "login_fail", "warn", f"{team}: login fallido ({reason})", priority=2)

    if etype == "submit":
        return _item(ts_ns, team, "submit", "info", f"{team} envió una flag en {chal_txt}", priority=2)

    if etype == "flag_ok":
        pts = detail.get("points") or ev.get("points")
        txt = f"{team} resolvió {chal_txt}"
        if pts:
            txt += f" (+{pts} pts)"
        return _item(ts_ns, team, "flag_ok", "success", txt, priority=2)

    if etype == "flag_fail":
        return _item(ts_ns, team, "flag_fail", "info", f"{team}: flag incorrecta en {chal_txt}", priority=2)

    if etype == "cheat_flag_share":
        return _item(
            ts_ns, team, "cheat", "critical",
            f"TRAMPA: {team} envió la flag de otro equipo ({chal_txt})",
            priority=2,
        )

    # Otros eventos de plataforma no aportan narrativa -> descartar.
    return None


def map_vpn(ts_ns, line, labels):
    """source=vpn: vpn_connect / vpn_disconnect / vpn_ban."""
    ev = _parse_json_line(line)
    if not ev:
        return None
    etype = (ev.get("event_type") or labels.get("event_type") or "").lower()
    detail = ev.get("detail") or {}
    if not isinstance(detail, dict):
        detail = {}

    src_ip = ev.get("src_ip") or detail.get("src_ip") or ""
    team = team_from_team_id(ev.get("team_id") or labels.get("team_id"))
    if not team:
        team = team_from_ip(src_ip)
    team = team or "Equipo ?"

    # Usar el nombre del jugador del evento (on-connect.sh envía detail.player="alice")
    player_name = detail.get("player") or ev.get("player") or ""
    if player_name:
        who = f"{team} · {player_name}"
    else:
        who = _who(team, src_ip)

    if etype == "vpn_connect":
        return _item(ts_ns, team, "vpn_connect", "info", f"{who} se conectó a la VPN", priority=2)
    if etype == "vpn_disconnect":
        return _item(ts_ns, team, "vpn_disconnect", "info", f"{who} se desconectó de la VPN", priority=2)
    if etype == "vpn_ban":
        return _item(
            ts_ns, team, "ban", "critical",
            f"{team} fue BANEADO (3 desconexiones)",
            priority=2,
        )
    return None


def _translate_signature(signature: str, category: str) -> str:
    """Traduce firma/categoría suricata a frase narrable."""
    blob = f"{signature} {category}"
    for rx, phrase in SIG_TRANSLATIONS:
        if rx.search(blob):
            return phrase
    # No reconocida: muestra la firma cruda (o categoría) tal cual.
    raw = signature.strip() or category.strip() or "actividad sospechosa"
    return f"disparó alerta IDS: {raw}"


def map_suricata(ts_ns, line, labels):
    """
    job=suricata: SOLO event_type=alert. flow y otros se descartan.
    """
    ev = _parse_json_line(line)
    if not ev:
        return None
    if (ev.get("event_type") or "").lower() != "alert":
        return None

    alert = ev.get("alert") or {}
    if not isinstance(alert, dict):
        alert = {}
    signature = str(alert.get("signature") or "")
    category = str(alert.get("category") or "")

    src_ip = ev.get("src_ip") or ""
    dest_ip = ev.get("dest_ip") or ""
    dest_port = ev.get("dest_port")

    team = team_from_ip(src_ip) or "Equipo ?"
    destino = anonymize(dest_ip) if dest_ip else ""

    phrase = _translate_signature(signature, category)
    text = f"{team} {phrase}"
    if destino:
        text += f" contra {destino}"
        if dest_port:
            text += f":{dest_port}"

    return _item(ts_ns, team, "ids", "alert", text, priority=2)


def _player_from_ip(ip):
    """10.10.N.(11-14) -> nombre del jugador (o 'Jugador N' si no hay config). Si no aplica -> ''."""
    try:
        o = str(ip).split(".")
        if len(o) == 4 and o[0] == "10" and o[1] == "10":
            team_n = int(o[2])
            last = int(o[3])
            if 11 <= last <= 14:
                return _player_label(team_n, last - 10)
    except (ValueError, IndexError):
        pass
    return ""


def _who(team, ip):
    """'Equipo NN · Jugador M' si la IP es de un miembro; si no, 'Equipo NN'."""
    p = _player_from_ip(ip)
    if team and p:
        return f"{team} · Jugador {p}"
    return team or "Equipo ?"


def map_challenge_flows(rows):
    """
    Detección de "qué reto atacan" desde Suricata (dest_ip ∈ 172.30.0.0/16).
    Usa DOS tipos de evento:
      - event_type=http  -> petición CONCRETA e inmediata: "<MÉTODO> <url> en <reto>".
      - event_type=flow   -> "atacando <reto>" SOLO si el servicio RESPONDIÓ
        (bytes_toclient>0 o app_proto). Así un escaneo a una IP vacía (p.ej. .15
        sin servicio) NO se marca como "atacando web-race-05".
    Incluye el jugador (certs por miembro, IP .11-.14 -> Jugador 1-4).
    Devuelve (items, current) con el reto más reciente por equipo.
    """
    items = []
    current = {}
    seen = {}
    win = CHALLENGE_DEDUP_SEC * 1_000_000_000
    http_win = 12 * 1_000_000_000     # peticiones http: dedup más corto (más detalle)

    chrono = sorted(rows, key=lambda r: r[0])
    for ts_ns, line, _labels in chrono:
        ev = _parse_json_line(line)
        if not ev:
            continue
        etype = (ev.get("event_type") or "").lower()
        if etype not in ("http", "flow"):
            continue
        dest_ip = ev.get("dest_ip") or ""
        chal = challenge_for(dest_ip)
        if not chal:
            continue
        src_ip = ev.get("src_ip") or ""
        team = team_from_ip(src_ip)
        if not team:
            try:
                from .anonymize import _team_label as _tl
                n = int(str(dest_ip).split(".")[2])
                if 1 <= n <= 5:
                    team = _tl(n)
            except (ValueError, IndexError):
                team = None
        team = team or "Equipo ?"
        who = _who(team, src_ip)

        if etype == "http":
            http = ev.get("http") if isinstance(ev.get("http"), dict) else {}
            method = str(http.get("http_method") or "GET")
            url = str(http.get("url") or "/")
            # Mostrar la URL COMPLETA (ruta + query) hasta ~140 chars, para que
            # se vea "lo que envía" en GET (p.ej. ?url=http://169.254.169.254/...).
            # El cuerpo del POST no llega vía Suricata, así que no se inventa.
            if len(url) > 140:
                url = url[:137] + "..."
            if current.get(team) is None or ts_ns >= current[team][0]:
                current[team] = (ts_ns, chal)
            dkey = (team, chal, method, url)
            prev = seen.get(dkey)
            if prev is not None and (ts_ns - prev) < http_win:
                continue
            seen[dkey] = ts_ns
            items.append(_item(
                ts_ns, team, "challenge", "info",
                f"{who} → {method} {url} en {chal}",
                dedup=("challenge_http", team, chal, method, url), priority=2,
            ))
        else:  # flow
            flow = ev.get("flow") if isinstance(ev.get("flow"), dict) else {}
            responded = False
            try:
                responded = int(flow.get("bytes_toclient") or 0) > 0
            except (ValueError, TypeError):
                responded = False
            # Sin respuesta del servicio y sin app_proto => probable escaneo a IP
            # vacía: NO marcar "atacando" (evita falsos como web-race-05 en .15).
            if not responded and not ev.get("app_proto"):
                continue
            if current.get(team) is None or ts_ns >= current[team][0]:
                current[team] = (ts_ns, chal)
            dkey = (team, chal)
            prev = seen.get(dkey)
            if prev is not None and (ts_ns - prev) < win:
                continue
            seen[dkey] = ts_ns
            items.append(_item(
                ts_ns, team, "challenge", "info",
                f"{who} → atacando {chal}",
                dedup=("challenge", team, chal), priority=2,
            ))

    return items, current


def detect_scans(rows):
    """
    Detección de ESCANEO de puertos (nmap/masscan) a partir de los flows de
    Suricata hacia la red de retos (172.30.0.0/16).

    Como NO hay alertas IDS que disparen, el escaneo se infiere por el número de
    PUERTOS DISTINTOS que un equipo toca en una ventana corta. Se usan TODOS los
    flows (incl. los que no respondieron, p.ej. puertos cerrados): justamente esa
    "ráfaga" a muchos puertos es la firma del scan.

    Reglas (dentro de SCAN_WINDOW_SEC, agrupando por equipo origen):
      - >= SCAN_PORTS_PER_HOST puertos distintos en UN mismo host de reto, o
      - >= SCAN_PORTS_TOTAL puertos distintos en toda la red de retos del equipo.

    Devuelve dos listas de dicts:
      violations: {ts_ns, ts, team, player, type="scan", domain_or_detail, text, n_ports, host}
      feed_items: items del feed (kind="scan", severity="alert")
    Dedup por (equipo, dest_ip) en SCAN_DEDUP_SEC para no spamear.
    """
    violations = []
    feed_items = []

    chrono = sorted(rows, key=lambda r: r[0])
    win_ns = SCAN_WINDOW_SEC * 1_000_000_000
    dedup_ns = SCAN_DEDUP_SEC * 1_000_000_000

    # Estado por (equipo, dest_ip): puertos vistos con su ts, para ventana móvil.
    per_host = defaultdict(dict)        # (team, dest_ip) -> {port: ts_ns}
    # Estado por equipo (red completa): puertos por (dest_ip, port).
    per_team = defaultdict(dict)        # team -> {(dest_ip, port): ts_ns}
    last_emit = {}                      # (team, dest_ip|"*") -> ts_ns de la última violación
    last_src = {}                       # (team, dest_ip) -> src_ip más reciente (para jugador)

    for ts_ns, line, _labels in chrono:
        ev = _parse_json_line(line)
        if not ev:
            continue
        if (ev.get("event_type") or "").lower() != "flow":
            continue
        dest_ip = ev.get("dest_ip") or ""
        if not challenge_for(dest_ip):
            continue
        dest_port = ev.get("dest_port")
        if dest_port is None:
            continue
        try:
            dest_port = int(dest_port)
        except (ValueError, TypeError):
            continue

        src_ip = ev.get("src_ip") or ""
        team = team_from_ip(src_ip)
        if not team:
            try:
                from .anonymize import _team_label as _tl
                n = int(str(dest_ip).split(".")[2])
                if 1 <= n <= 5:
                    team = _tl(n)
            except (ValueError, IndexError):
                team = None
        team = team or "Equipo ?"

        hkey = (team, dest_ip)
        last_src[hkey] = src_ip

        # --- Registrar puerto y purgar lo más viejo que la ventana ---
        hports = per_host[hkey]
        hports[dest_port] = ts_ns
        for p in [p for p, t in hports.items() if (ts_ns - t) > win_ns]:
            del hports[p]

        tports = per_team[team]
        tports[(dest_ip, dest_port)] = ts_ns
        for k in [k for k, t in tports.items() if (ts_ns - t) > win_ns]:
            del tports[k]

        n_host = len(hports)
        n_team = len(tports)

        scan_hit = None   # (scope_key, n_ports, host_label, host_ip)
        if n_host >= SCAN_PORTS_PER_HOST:
            scan_hit = (hkey, n_host, challenge_for(dest_ip), dest_ip)
        elif n_team >= SCAN_PORTS_TOTAL:
            scan_hit = ((team, "*"), n_team, "la red de retos", "")

        if scan_hit is None:
            continue

        scope_key, n_ports, host_label, host_ip = scan_hit
        prev = last_emit.get(scope_key)
        if prev is not None and (ts_ns - prev) < dedup_ns:
            continue
        last_emit[scope_key] = ts_ns

        src_for_who = last_src.get((team, host_ip), src_ip) if host_ip else src_ip
        who = _who(team, src_for_who)

        txt_feed = f"🚨 {who} → ESCANEO de puertos ({n_ports} puertos en {host_label})"
        feed_items.append(_item(
            ts_ns, team, "scan", "alert", txt_feed,
            dedup=("scan", team, host_ip or "*"), priority=2,
        ))

        m = re.search(r"(\d{1,2})", team or "")
        num = m.group(1).zfill(2) if m else "??"
        player = _player_from_ip(src_for_who)
        who_v = f"EQUIPO {num}" + (f" · JUGADOR {player}" if player else "")
        text = anonymize(
            f"🚨 ESCANEO DE PUERTOS — {who_v} ({n_ports} puertos en {host_label})"
        )
        violations.append({
            "ts_ns": ts_ns, "ts": _rel_ts_iso(ts_ns), "team": team, "player": player,
            "type": "scan", "domain_or_detail": anonymize(host_label),
            "text": text, "n_ports": n_ports, "host": anonymize(host_label),
        })

    return violations, feed_items


# DNS necesita estado (asociar reply -> última query, y deduplicar). Se procesa
# en lote en map_dns_batch en vez de línea a línea.
_DNS_QUERY_RE = re.compile(r"query\[\w+\]\s+(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)", re.I)
_DNS_QUERY_NOIP_RE = re.compile(r"query\[\w+\]\s+(\S+)", re.I)
# dnsmasq loguea el sinkhole (address=/dom/0.0.0.0) como "config <dom> is 0.0.0.0",
# y las respuestas normales como "reply <dom> is <ip>". Matcheamos AMBAS.
_DNS_REPLY_RE = re.compile(r"(?:reply|config)\s+(\S+)\s+is\s+(\S+)", re.I)
# Algunos dnsmasq registran el cliente como "10.10.1.2/58718" en la línea.
_DNS_CLIENT_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)/\d+")


def map_dns_batch(rows):
    """
    Procesa el stream DNS completo (dnsmasq) y produce items narrables.

    - reply <dom> is 0.0.0.0  -> 🚫 intento de IA/bloqueado (severity alert)
    - query[..] <dom> from ip -> 🌐 consultó <dom> (info), con dedup y filtro
      de ruido de telemetría.

    rows llega en orden 'backward' (reciente->antiguo). Para asociar un reply
    sinkhole con el equipo que lo pidió, recordamos la última query por dominio.
    Como el orden es reciente->antiguo, recorremos en orden cronológico
    (lo invertimos) para que la query preceda a su reply.
    """
    items = []
    # cronológico ascendente
    chrono = sorted(rows, key=lambda r: r[0])

    last_query_team = {}      # dominio -> (team, ts_ns)
    dns_seen = {}             # (team, dominio) -> ts_ns de la última vez mostrada

    for ts_ns, line, _labels in chrono:
        line = line or ""

        # ---- REPLY (sinkhole / resolución) ----
        m = _DNS_REPLY_RE.search(line)
        if m:
            domain = m.group(1).rstrip(".")
            answer = m.group(2)
            if answer == "0.0.0.0":
                # Bloqueado (típicamente IA u otro dominio prohibido).
                team, _, player = last_query_team.get(domain, (None, None, ""))
                # Fallback: extraer equipo del dominio si tiene 172.30.N.x embebido.
                if not team and domain:
                    m_dom = re.search(r"172\.30\.([1-5])\.\d+", domain)
                    if m_dom:
                        team = team_from_ip(f"10.10.{m_dom.group(1)}.1")
                if team and player:
                    who = f"{team} · Jugador {player}"
                elif team:
                    who = team
                else:
                    who = "alguien"
                text = f"{who} intentó acceder a {domain} (BLOQUEADO)"
                ai_item = _item(
                    ts_ns, team or "", "ai_block", "alert", text,
                    dedup=("ai_block", team or "?", domain), priority=2,
                )
                ai_item["domain"] = domain
                ai_item["player"] = player
                items.append(ai_item)
            # replies normales (is 1.2.3.4) no se narran: la query ya lo cubre.
            continue

        # ---- QUERY ----
        m = _DNS_QUERY_RE.search(line)
        ip = None
        domain = None
        if m:
            domain = m.group(1).rstrip(".")
            ip = m.group(2)
        else:
            m2 = _DNS_QUERY_NOIP_RE.search(line)
            if m2:
                domain = m2.group(1).rstrip(".")
                mc = _DNS_CLIENT_RE.search(line)
                if mc:
                    ip = mc.group(1)
        if not domain:
            continue

        team = team_from_ip(ip) if ip else None
        # Si la IP no resuelve equipo, intentar extraerlo del dominio.
        # Caso típico: callback OOB/SSRF con la IP del reto embebida,
        # p.ej. "*.172.30.1.10.interact.sh" → el tercer octeto (1) es el equipo.
        if not team and domain:
            m_dom = re.search(r"172\.30\.([1-5])\.\d+", domain)
            if m_dom:
                team = team_from_ip(f"10.10.{m_dom.group(1)}.1")
        # Jugador (miembro) por la IP: 10.10.N.(11-14) -> "1".."4" (certs por miembro).
        player = ""
        if ip:
            mo = re.match(r"^10\.10\.\d+\.(\d+)$", ip)
            if mo and 11 <= int(mo.group(1)) <= 14:
                player = str(int(mo.group(1)) - 10)
        # Recordar la query para poder atribuir un futuro reply sinkhole.
        if team:
            last_query_team[domain] = (team, ts_ns, player)

        # Filtro de ruido de telemetría (salvo que sea dominio interesante).
        interesting = bool(DNS_INTERESTING_RE.search(domain))
        if not interesting and DNS_NOISE_RE.search(domain):
            continue
        # Sin dominio "interesante" y sin equipo identificado: poco valor.
        if not team and not interesting:
            continue

        team_lbl = team or "Equipo ?"

        # Dedup: mismo (equipo, dominio) no más de una vez cada DNS_DEDUP_SEC.
        dkey = (team_lbl, domain)
        prev = dns_seen.get(dkey)
        if prev is not None and (ts_ns - prev) < DNS_DEDUP_SEC * 1_000_000_000:
            continue
        dns_seen[dkey] = ts_ns

        # Dominio "interesante" (IA/hacking/exfil) = prioritario; el resto es
        # navegación trivial -> priority 0 (solo si sobra espacio en el feed).
        prio = 2 if interesting else 0
        text = f"{team_lbl} consultó {domain}"
        items.append(_item(
            ts_ns, team_lbl, "dns", "info", text,
            dedup=("dns", team_lbl, domain), priority=prio,
        ))

    return items


# ----------------------------------------------------------------------------
# CTFREQ — peticiones COMPLETAS que los jugadores envían a los retos.
#
# Cada reto imprime a STDOUT una línea `CTFREQ {json}` por petición (ver
# challenges/_lib/reqlog.py). Promtail las recoge con job=challenge-logs.
# Aquí las parseamos, mapeamos src_ip -> Equipo/Jugador y challenge_id -> nombre
# legible, y producimos items de feed kind="request" (📡) + detalle completo
# (headers + body íntegro) para la vista por equipo.
# ----------------------------------------------------------------------------

# challenge_id (env CHALLENGE_ID del contenedor) -> nombre legible para narrar.
CHALLENGE_ID_MAP = {
    "web-supply-01": "web-supply-01 · Poisoned Pipeline",
    "web-ssrf-02": "web-ssrf-02 · Metadata Mirage",
    "api-bola-01": "api-bola-01 · Tenant Trespass",
    "api-graphql-03": "api-graphql-03 · Introspection Abyss",
    "crypto-oracle-01": "crypto-oracle-01 · Padding Whisperer",
    "crypto-aesgcm-04": "crypto-aesgcm-04 · Nonce Reuse Roulette",
}


def _challenge_name_from_id(cid) -> str:
    """challenge_id ('web-ssrf-02') -> nombre legible. Fallback: el id en limpio."""
    if not cid:
        return "un reto"
    cid = str(cid).strip()
    return CHALLENGE_ID_MAP.get(cid, _challenge_label(cid))


def _parse_ctfreq_line(line: str):
    """Extrae el JSON que va tras el prefijo `CTFREQ ` en la línea.

    Devuelve dict, o {} si la línea no es un CTFREQ válido.
    """
    if not line:
        return {}
    idx = line.find("CTFREQ ")
    if idx < 0:
        return {}
    payload = line[idx + len("CTFREQ "):].strip()
    try:
        obj = json.loads(payload)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _summarize_request(ev: dict) -> str:
    """Resumen corto y narrable de una petición (sin equipo/jugador).

    HTTP: 'POST /api/fetch?query · body: <body≈160c>'
    TCP : 'TCP · <datos≈160c>'
    """
    proto = (ev.get("proto") or "").lower()
    body = anonymize_payload(ev.get("body") or "")   # payload crudo salvo IPs VPN
    body_short = body.replace("\n", " ").replace("\r", " ")
    if len(body_short) > REQ_FEED_BODY_MAX:
        body_short = body_short[:REQ_FEED_BODY_MAX] + "…"

    if proto == "tcp":
        return f"TCP · {body_short}" if body_short else "TCP · (conexión)"

    # HTTP
    method = str(ev.get("method") or "?")
    path = str(ev.get("path") or "/")
    query = anonymize_payload(ev.get("query") or "")
    line = f"{method} {path}"
    if query:
        line += f"?{query}"
    if body_short:
        line += f" · body: {body_short}"
    return line


def map_requests(rows):
    """
    Convierte las líneas CTFREQ en items de feed kind="request" (📡).

    Devuelve (items, details) donde:
      items   : lista de items de feed (texto narrable, anonimizado).
      details : lista de dicts con el DETALLE COMPLETO por petición (headers +
                body íntegro) para exponer en /api/team/{nn}; ya anonimizados en
                la parte de equipo/jugador (las IPs internas se anonimizan, el
                body se deja tal cual lo envió el jugador).

    Dedup: descarta la MISMA línea repetida (mismo team+challenge+resumen) dentro
    de REQ_DEDUP_SEC; NO colapsa peticiones distintas.
    """
    items = []
    details = []
    seen = {}
    win = REQ_DEDUP_SEC * 1_000_000_000

    chrono = sorted(rows, key=lambda r: r[0])
    for ts_ns, line, _labels in chrono:
        ev = _parse_ctfreq_line(line)
        if not ev:
            continue

        src_ip = ev.get("src_ip") or ""
        team = team_from_ip(src_ip) or "Equipo ?"
        who = _who(team, src_ip)
        chal = _challenge_name_from_id(ev.get("challenge_id"))

        summary = _summarize_request(ev)
        text = f"{who} → {summary} en {chal}"

        # Dedup de líneas idénticas seguidas (evita duplicar la MISMA petición).
        dkey = (team, chal, summary)
        prev = seen.get(dkey)
        if prev is not None and (ts_ns - prev) < win:
            continue
        seen[dkey] = ts_ns

        items.append(_item(
            ts_ns, team, "request", "info", text,
            dedup=("request", team, chal, summary), priority=2, anon=False,
        ))

        # Detalle COMPLETO para la vista por equipo (headers + body íntegro).
        # anonymize() sustituye cualquier IP interna que aparezca en los valores.
        headers = ev.get("headers") if isinstance(ev.get("headers"), dict) else {}
        headers_anon = {str(k): anonymize(str(v)) for k, v in headers.items()}
        details.append({
            "ts": _rel_ts_iso(ts_ns),
            "ts_ns": ts_ns,
            "team": anonymize(team),
            "who": anonymize(who),
            "challenge": chal,
            "proto": (ev.get("proto") or "").lower(),
            "method": ev.get("method"),
            "path": ev.get("path"),
            "query": anonymize_payload(ev.get("query") or ""),
            "headers": headers_anon,
            "body": anonymize_payload(ev.get("body") or ""),
        })

    return items, details


# ----------------------------------------------------------------------------
# Agregadores
# ----------------------------------------------------------------------------
async def collect_feed(limit: int = 80, team: str = None):
    """
    Consulta los streams relevantes, mapea a texto narrable, descarta ruido
    (firewall/no mapeable), fusiona, deduplica y ordena reciente->antiguo.

    Incluye la detección de "qué reto atacan" (Suricata event_type=flow con
    dest_ip ∈ 172.30.0.0/16). team: si se pasa ('Equipo NN'), filtra al equipo.
    """
    fetch = max(limit * 3, 300)

    plat_rows = await loki_query_range('{source="platform"}', limit=fetch)
    vpn_rows = await loki_query_range('{source="vpn"}', limit=fetch)
    sur_rows = await loki_query_range(
        '{job="suricata"} |= "\\"event_type\\":\\"alert\\""', limit=fetch
    )
    # Flows hacia un reto: traen "172.30." en la línea (filtra ruido en Loki).
    flow_rows = await loki_query_range(
        '{job="suricata"} |= "172.30."', limit=fetch
    )
    dns_rows = await loki_query_range('{job="dns"}', limit=fetch)
    # Peticiones COMPLETAS a los retos (CTFREQ). Filtramos por el prefijo en Loki.
    req_rows = await loki_query_range(
        '{job="challenge-logs"} |= "CTFREQ {"', limit=fetch
    )

    items = []
    for ts_ns, line, labels in plat_rows:
        try:
            it = map_platform(ts_ns, line, labels)
            if it:
                items.append(it)
        except Exception:
            continue
    for ts_ns, line, labels in vpn_rows:
        try:
            it = map_vpn(ts_ns, line, labels)
            if it:
                items.append(it)
        except Exception:
            continue
    for ts_ns, line, labels in sur_rows:
        try:
            it = map_suricata(ts_ns, line, labels)
            if it:
                items.append(it)
        except Exception:
            continue
    try:
        items.extend(map_dns_batch(dns_rows))
    except Exception:
        pass
    try:
        chal_items, _cur = map_challenge_flows(flow_rows)
        items.extend(chal_items)
    except Exception:
        pass
    # Escaneo de puertos (nmap) inferido por flujos a muchos puertos distintos.
    try:
        _scan_v, scan_feed = detect_scans(flow_rows)
        items.extend(scan_feed)
    except Exception:
        pass
    # Peticiones COMPLETAS a los retos (CTFREQ) -> kind="request" (📡).
    try:
        req_items, _req_details = map_requests(req_rows)
        items.extend(req_items)
    except Exception:
        pass

    # Filtro opcional por equipo (vista por equipo).
    if team:
        items = [it for it in items if it.get("team") == team]

    # Orden cronológico ascendente para que la dedup por ventana de tiempo
    # conserve la PRIMERA aparición de cada (dedup-key) en cada ventana de
    # FEED_DEDUP_SEC. Así "www.bing.com" repetido 50 veces colapsa a 1.
    items.sort(key=lambda x: x["ts_ns"])

    dedup_seen = {}          # _dedup -> ts_ns de la última aceptada
    deduped = []
    win = FEED_DEDUP_SEC * 1_000_000_000
    for it in items:
        key = it["_dedup"]
        prev = dedup_seen.get(key)
        if prev is not None and (it["ts_ns"] - prev) < win:
            continue
        dedup_seen[key] = it["ts_ns"]
        deduped.append(it)

    # Reciente -> antiguo. Mantiene prioridad: la navegación trivial
    # (priority 0) queda relegada al final, después de toda la actividad CTF.
    deduped.sort(key=lambda x: (x["_priority"], x["ts_ns"]), reverse=True)

    for it in deduped:
        it.pop("ts_ns", None)
        it.pop("_dedup", None)
        it.pop("_priority", None)
    return deduped[:limit]


async def collect_scoreboard():
    """Deriva puntos/solves por equipo a partir de los flag_ok del collector."""
    rows = await loki_query_range('{source="platform"} |= "flag_ok"', limit=5000)
    agg = defaultdict(lambda: {"points": 0, "solves": 0})
    for ts_ns, line, labels in rows:
        ev = _parse_json_line(line)
        if (ev.get("event_type") or "").lower() != "flag_ok":
            continue
        team = team_from_team_id(ev.get("team_id") or labels.get("team_id"))
        if not team:
            team = team_from_ip(ev.get("src_ip") or "")
        if not team:
            continue
        detail = ev.get("detail") or {}
        if not isinstance(detail, dict):
            detail = {}
        pts = detail.get("points") or ev.get("points") or 0
        try:
            pts = int(pts)
        except (TypeError, ValueError):
            pts = 0
        agg[team]["points"] += pts
        agg[team]["solves"] += 1

    board = [
        {"team": anonymize(team), "points": v["points"], "solves": v["solves"]}
        for team, v in agg.items()
    ]
    board.sort(key=lambda x: (x["points"], x["solves"]), reverse=True)
    return board


# ----------------------------------------------------------------------------
# Estado por equipo (conexiones VPN, puntos, status) y violaciones
# ----------------------------------------------------------------------------
TEAM_IDS = [f"team_{i:02d}" for i in range(1, 6)]


def _team_id_to_label(team_id: str) -> str:
    """'team_03' -> 'DARKHIVE' (para los 5 equipos del CTF)."""
    return team_from_team_id(team_id) or anonymize(team_id)


async def collect_teams():
    """
    Estado por equipo (Equipo 01..Equipo 10, SIEMPRE los 10).

    connected: sesiones VPN activas distintas por equipo. Clave de sesión =
      (team_id, real_ip:real_port). Una sesión está activa si su ÚLTIMO evento
      es vpn_connect (no seguido de disconnect/ban). Soporta varios jugadores.
    points/solves: de flag_ok (suma detail.points / conteo).
    status: 'banned' si hubo vpn_ban reciente sin re-connect posterior;
            'online' si connected>0; si no 'offline'.
    last_action: texto del último evento narrable del equipo (anonimizado).
    """
    fetch = 5000
    vpn_rows = await loki_query_range('{source="vpn"}', limit=fetch)
    plat_rows = await loki_query_range('{source="platform"}', limit=fetch)
    flow_rows = await loki_query_range(
        '{job="suricata"} |= "172.30."', limit=fetch
    )

    # Reto actual por equipo (más reciente) a partir de los flows hacia retos.
    current_challenge = {}    # team_label -> reto (str)
    try:
        _ci, cur = map_challenge_flows(flow_rows)
        for team_lbl, (_ts, chal) in cur.items():
            current_challenge[team_lbl] = chal
    except Exception:
        pass

    # --- Sesiones VPN: por equipo, estado de cada sesión en orden cronológico.
    # session_state[team_label][session_key] = ('connect'|'disconnect'|'ban', ts_ns)
    session_state = defaultdict(dict)
    # Nombre del jugador por sesión: team -> {skey -> player_name}
    session_player: dict = defaultdict(dict)
    # Último vpn_ban / vpn_connect por equipo para derivar 'banned'.
    last_ban = {}        # team_label -> ts_ns
    last_connect = {}    # team_label -> ts_ns
    # last_action por equipo (cualquier fuente).
    last_action = {}     # team_label -> (ts_ns, text)

    vpn_chrono = sorted(vpn_rows, key=lambda r: r[0])
    for ts_ns, line, labels in vpn_chrono:
        ev = _parse_json_line(line)
        if not ev:
            continue
        etype = (ev.get("event_type") or labels.get("event_type") or "").lower()
        team_id = ev.get("team_id") or labels.get("team_id")
        team = team_from_team_id(team_id)
        if not team:
            team = team_from_ip(ev.get("src_ip") or "")
        if not team:
            continue

        detail = ev.get("detail") or {}
        if not isinstance(detail, dict):
            detail = {}
        real_ip = str(detail.get("real_ip") or ev.get("src_ip") or "?")
        real_port = str(detail.get("real_port") or "?")
        skey = f"{real_ip}:{real_port}"

        # Nombre del jugador desde el evento (on-connect.sh envía detail.player="alice")
        player_name = detail.get("player") or ev.get("player") or ""

        if etype == "vpn_connect":
            session_state[team][skey] = ("connect", ts_ns)
            if player_name:
                session_player[team][skey] = player_name
            last_connect[team] = ts_ns
            who_txt = f"{team} · {player_name}" if player_name else team
            last_action[team] = (ts_ns, f"{who_txt} se conectó a la VPN")
        elif etype == "vpn_disconnect":
            session_state[team][skey] = ("disconnect", ts_ns)
            who_txt = f"{team} · {player_name}" if player_name else team
            last_action[team] = (ts_ns, f"{who_txt} se desconectó de la VPN")
        elif etype == "vpn_ban":
            session_state[team][skey] = ("ban", ts_ns)
            last_ban[team] = ts_ns
            last_action[team] = (ts_ns, f"{team} fue BANEADO")

    # connected = sesiones cuyo último estado es 'connect' y no demasiado viejas.
    now_ns = _ns(datetime.now(timezone.utc))
    ttl_ns = SESSION_TTL_SEC * 1_000_000_000
    connected = defaultdict(int)
    connected_players: dict = defaultdict(list)  # team -> [player_name, ...]
    for team, sessions in session_state.items():
        for skey, (state, ts_ns) in sessions.items():
            if state == "connect" and (now_ns - ts_ns) <= ttl_ns:
                connected[team] += 1
                p = session_player.get(team, {}).get(skey, "")
                connected_players[team].append(p if p else "—")

    # --- Puntos / solves / last_action de plataforma (flag_ok y demás).
    points = defaultdict(int)
    solves = defaultdict(int)
    plat_chrono = sorted(plat_rows, key=lambda r: r[0])
    for ts_ns, line, labels in plat_chrono:
        try:
            it = map_platform(ts_ns, line, labels)
        except Exception:
            it = None
        if not it:
            continue
        team = it["team"]
        # Actualiza última acción (la lista es cronológica, gana la más nueva).
        prev = last_action.get(team)
        if prev is None or ts_ns >= prev[0]:
            last_action[team] = (ts_ns, it["text"])
        if it["kind"] == "flag_ok":
            ev = _parse_json_line(line)
            detail = ev.get("detail") or {}
            if not isinstance(detail, dict):
                detail = {}
            try:
                pts = int(detail.get("points") or ev.get("points") or 0)
            except (TypeError, ValueError):
                pts = 0
            points[team] += pts
            solves[team] += 1

    # --- Ensamblar los 10 equipos (aunque no tengan actividad).
    teams = []
    max_pts = 0
    for tid in TEAM_IDS:
        team = _team_id_to_label(tid)
        c = connected.get(team, 0)
        pts = points.get(team, 0)
        slv = solves.get(team, 0)
        max_pts = max(max_pts, pts)

        # status
        banned = (
            team in last_ban
            and last_ban[team] >= last_connect.get(team, -1)
            and c == 0
        )
        if banned:
            status = "banned"
        elif c > 0:
            status = "online"
        else:
            status = "offline"

        la = last_action.get(team)
        last_text = anonymize(la[1]) if la else "sin actividad"
        last_ts = _rel_ts_iso(la[0]) if la else None

        teams.append({
            "team": team,
            "team_id": tid,
            "connected": c,
            "players": connected_players.get(team, []),
            "points": pts,
            "solves": slv,
            "status": status,
            "last_activity_ts": last_ts,
            "last_action": last_text,
            "current_challenge": current_challenge.get(team),
        })

    # Marca el líder (más puntos, si hay > 0).
    for t in teams:
        t["leader"] = bool(max_pts > 0 and t["points"] == max_pts)

    return teams


async def collect_violations(limit: int = 40):
    """
    SOLO eventos graves/narrables como 'violación', más reciente primero:
      - IA: DNS sinkhole (reply ... is 0.0.0.0)
      - Escaneos / exploits: alertas suricata
      - Trampa: cheat_flag_share
      - Ban: vpn_ban
    Formato: {ts, team, type, domain_or_detail, text}
    """
    fetch = 3000
    dns_rows = await loki_query_range('{job="dns"}', limit=fetch)
    sur_rows = await loki_query_range(
        '{job="suricata"} |= "\\"event_type\\":\\"alert\\""', limit=fetch
    )
    flow_rows = await loki_query_range('{job="suricata"} |= "172.30."', limit=fetch)
    plat_rows = await loki_query_range('{source="platform"} |= "cheat"', limit=fetch)
    vpn_rows = await loki_query_range('{source="vpn"} |= "ban"', limit=fetch)

    out = []
    seen = set()  # dedup por (type, team, detalle) en ventana

    def _team_num(team_label: str) -> str:
        m = re.search(r"(\d{1,2})", team_label or "")
        return m.group(1).zfill(2) if m else "??"

    # --- IA: sinkhole DNS (reusa map_dns_batch para atribuir equipo).
    try:
        dns_items = map_dns_batch(dns_rows)
    except Exception:
        dns_items = []
    for it in dns_items:
        if it["kind"] != "ai_block":
            continue
        domain = it.get("domain")
        if not domain:
            m = re.search(r"acceder a (\S+) \(BLOQUEADO\)", it["text"])
            domain = m.group(1) if m else "dominio IA"
        team = it["team"] or "Equipo ??"
        player = it.get("player") or ""
        who = f"EQUIPO {_team_num(team)}" + (f" · JUGADOR {player}" if player else "")
        # text es fallback; el frontend renderiza ai_block con estilo rojo + [BLOCK].
        text = anonymize(f"🚫 {domain} DETECTADO — {who} intentó acceder [BLOCK]")
        out.append({
            "ts": it["ts"], "ts_ns": it["ts_ns"], "team": team, "player": player,
            "type": "ai_block", "domain_or_detail": domain, "text": text,
        })

    # --- Escaneos / exploits suricata.
    for ts_ns, line, labels in sur_rows:
        ev = _parse_json_line(line)
        if (ev.get("event_type") or "").lower() != "alert":
            continue
        alert = ev.get("alert") or {}
        if not isinstance(alert, dict):
            alert = {}
        signature = str(alert.get("signature") or "")
        category = str(alert.get("category") or "")
        team = team_from_ip(ev.get("src_ip") or "") or "Equipo ??"
        num = _team_num(team)
        blob = f"{signature} {category}"
        if SCAN_SIG_RE.search(blob):
            text = anonymize(f"🚨 ESCANEO NMAP — EQUIPO {num}")
            vtype = "scan"
            detail = "escaneo de puertos"
        else:
            phrase = _translate_signature(signature, category)
            text = anonymize(f"🚨 {phrase.upper()} — EQUIPO {num}")
            vtype = "exploit"
            detail = signature or category or "alerta IDS"
        out.append({
            "ts": _rel_ts_iso(ts_ns), "ts_ns": ts_ns, "team": team,
            "type": vtype, "domain_or_detail": anonymize(detail), "text": text,
        })

    # --- Escaneo de puertos (nmap) inferido por flujos a muchos puertos.
    try:
        scan_v, _scan_feed = detect_scans(flow_rows)
    except Exception:
        scan_v = []
    out.extend(scan_v)

    # --- Trampa (cheat_flag_share).
    for ts_ns, line, labels in plat_rows:
        ev = _parse_json_line(line)
        if (ev.get("event_type") or labels.get("event_type") or "").lower() != "cheat_flag_share":
            continue
        team = team_from_team_id(ev.get("team_id") or labels.get("team_id")) \
            or team_from_ip(ev.get("src_ip") or "") or "Equipo ??"
        num = _team_num(team)
        text = anonymize(f"🔴 TRAMPA — EQUIPO {num} usó flag ajena")
        out.append({
            "ts": _rel_ts_iso(ts_ns), "ts_ns": ts_ns, "team": team,
            "type": "cheat", "domain_or_detail": "flag compartida", "text": text,
        })

    # --- Bans VPN.
    for ts_ns, line, labels in vpn_rows:
        ev = _parse_json_line(line)
        if (ev.get("event_type") or labels.get("event_type") or "").lower() != "vpn_ban":
            continue
        team = team_from_team_id(ev.get("team_id") or labels.get("team_id")) \
            or team_from_ip(ev.get("src_ip") or "") or "Equipo ??"
        num = _team_num(team)
        text = anonymize(f"⛔ BAN — EQUIPO {num} expulsado de la VPN")
        out.append({
            "ts": _rel_ts_iso(ts_ns), "ts_ns": ts_ns, "team": team,
            "type": "ban", "domain_or_detail": "ban VPN", "text": text,
        })

    # AGREGACIÓN CON CONTADOR: una sola fila por (tipo, equipo, jugador, dominio)
    # en toda la ventana, con `count` (×N) y el timestamp MÁS RECIENTE. Evita que
    # el mismo intento (p.ej. chatgpt.com de Equipo 01 · Jugador 1) llene el panel.
    groups = {}
    for v in out:
        key = (v["type"], v["team"], v.get("player", ""), v["domain_or_detail"])
        g = groups.get(key)
        if g is None:
            g = dict(v)
            g["count"] = 1
            groups[key] = g
        else:
            g["count"] += 1
            if v["ts_ns"] > g["ts_ns"]:
                g["ts_ns"] = v["ts_ns"]
                g["ts"] = v["ts"]
    aggregated = list(groups.values())
    aggregated.sort(key=lambda x: x["ts_ns"], reverse=True)
    for v in aggregated:
        v.pop("ts_ns", None)
    return aggregated[:limit]


async def collect_stats():
    """
    Contadores globales para el header del overlay.
    solves usa WINDOW_MIN (histórico completo). El resto usa STATS_WIN_MIN
    (ventana corta) para que las queries a Loki sean rápidas y no hagan timeout.
    """
    fetch = 5000
    w = STATS_WIN_MIN

    plat_rows = await loki_query_range('{source="platform"}', limit=fetch, window_min=WINDOW_MIN)
    vpn_rows = await loki_query_range('{source="vpn"}', limit=fetch, window_min=w)
    sur_rows = await loki_query_range(
        '{job="suricata"} |= "\\"event_type\\":\\"alert\\""', limit=fetch, window_min=w
    )
    flow_rows = await loki_query_range('{job="suricata"} |= "172.30."', limit=fetch, window_min=w)
    dns_rows = await loki_query_range('{job="dns"}', limit=fetch, window_min=w)

    total_events = 0
    alerts = 0
    ai_blocked = 0
    scans = 0
    solves = 0

    # Plataforma
    for ts_ns, line, labels in plat_rows:
        it = None
        try:
            it = map_platform(ts_ns, line, labels)
        except Exception:
            it = None
        if not it:
            continue
        total_events += 1
        if it["severity"] in ("alert", "critical"):
            alerts += 1
        if it["kind"] == "flag_ok":
            solves += 1

    # VPN
    for ts_ns, line, labels in vpn_rows:
        it = None
        try:
            it = map_vpn(ts_ns, line, labels)
        except Exception:
            it = None
        if not it:
            continue
        total_events += 1
        if it["severity"] in ("alert", "critical"):
            alerts += 1

    # Suricata alerts
    for ts_ns, line, labels in sur_rows:
        ev = _parse_json_line(line)
        if (ev.get("event_type") or "").lower() != "alert":
            continue
        total_events += 1
        alerts += 1
        alert = ev.get("alert") or {}
        if not isinstance(alert, dict):
            alert = {}
        sig = f"{alert.get('signature') or ''} {alert.get('category') or ''}"
        if SCAN_SIG_RE.search(sig):
            scans += 1

    # Escaneos detectados por FLUJOS (nmap sin alerta IDS): cuentan como scan
    # y como evento de severidad alert. Cada violación = un escaneo detectado.
    try:
        scan_v, scan_feed = detect_scans(flow_rows)
    except Exception:
        scan_v, scan_feed = [], []
    scans += len(scan_v)
    total_events += len(scan_feed)
    alerts += len(scan_feed)

    # DNS: sinkhole (IA bloqueada) + consultas narrables como eventos útiles
    dns_items = []
    try:
        dns_items = map_dns_batch(dns_rows)
    except Exception:
        dns_items = []
    for it in dns_items:
        total_events += 1
        if it["kind"] == "ai_block":
            ai_blocked += 1
            alerts += 1

    # Equipos / jugadores online a partir del estado por equipo.
    teams_online = 0
    players_online = 0
    try:
        teams = await collect_teams()
        for t in teams:
            if t["connected"] > 0:
                teams_online += 1
                players_online += t["connected"]
    except Exception:
        pass

    return {
        "total_events": total_events,
        "alerts": alerts,
        "ai_blocked": ai_blocked,
        "scans": scans,
        "solves": solves,
        "teams_online": teams_online,
        "players_online": players_online,
        "window_min": WINDOW_MIN,
        "ctf_name": CTF_NAME,
    }


def _team_label_from_nn(nn) -> str:
    """'3' / '03' / 3 -> nombre del equipo. Para resolver el path param /api/team/{nn}."""
    try:
        n = int(str(nn).strip())
    except (TypeError, ValueError):
        return ""
    if 1 <= n <= 5:
        return team_from_team_id(f"team_{n:02d}") or f"Equipo {n:02d}"
    return ""


async def collect_team_detail(nn, recent: int = 20):
    """
    Detalle de UN equipo (vista por equipo).

    Devuelve {team, connected, points, solves, status, current_challenge,
    challenges_touched:[...], recent:[últimos `recent` eventos del equipo]}.
    Reusa collect_teams (stats/estado) y collect_feed(team=...) (eventos).
    """
    team_lbl = _team_label_from_nn(nn)
    if not team_lbl:
        return None

    # Estado/stats del equipo desde collect_teams (mantiene una sola fuente).
    base = {
        "team": team_lbl, "connected": 0, "points": 0, "solves": 0,
        "status": "offline", "current_challenge": None,
    }
    try:
        for t in await collect_teams():
            if t["team"] == team_lbl:
                base.update({
                    "connected": t["connected"], "points": t["points"],
                    "solves": t["solves"], "status": t["status"],
                    "current_challenge": t.get("current_challenge"),
                })
                break
    except Exception:
        pass

    # Eventos recientes del equipo (ya anonimizados y priorizados).
    try:
        events = await collect_feed(limit=max(recent, 40), team=team_lbl)
    except Exception:
        events = []

    # Retos que ha tocado (de los eventos kind=challenge del equipo).
    touched = []
    seen = set()
    for it in events:
        if it.get("kind") == "challenge":
            # texto: "Equipo NN → atacando <reto>"
            m = re.search(r"atacando (.+)$", it.get("text") or "")
            chal = m.group(1) if m else None
            if chal and chal not in seen:
                seen.add(chal)
                touched.append(chal)

    base["challenges_touched"] = touched
    base["recent"] = events[:recent]

    # Peticiones COMPLETAS del equipo (headers + body íntegro) para la vista por
    # equipo. Filtra al equipo y devuelve reciente -> antiguo.
    requests_full = []
    try:
        req_rows = await loki_query_range(
            '{job="challenge-logs"} |= "CTFREQ {"', limit=max(recent * 4, 200)
        )
        _ri, details = map_requests(req_rows)
        details = [d for d in details if d.get("team") == team_lbl]
        details.sort(key=lambda d: d.get("ts_ns", 0), reverse=True)
        for d in details:
            d.pop("ts_ns", None)
        requests_full = details[:recent]
    except Exception:
        requests_full = []
    base["requests"] = requests_full
    return base


async def collect_timeseries(minutes: int = 15):
    """
    Series temporales por minuto sobre la ventana solicitada:
      labels      : ['HH:MM', ...] (un punto por minuto, ascendente)
      events      : total de eventos útiles por minuto
      alerts      : eventos severity alert/critical por minuto
      ai_blocked  : sinkholes IA (ai_block) por minuto
    Además by_team: {'Equipo NN': total_eventos} (para barras por equipo).
    Robusto ante Loki caído: devuelve series de ceros.
    """
    minutes = max(1, min(minutes, WINDOW_MIN))
    fetch = 5000

    plat_rows = await loki_query_range('{source="platform"}', limit=fetch)
    vpn_rows = await loki_query_range('{source="vpn"}', limit=fetch)
    sur_rows = await loki_query_range(
        '{job="suricata"} |= "\\"event_type\\":\\"alert\\""', limit=fetch
    )
    flow_rows = await loki_query_range(
        '{job="suricata"} |= "172.30."', limit=fetch
    )
    dns_rows = await loki_query_range('{job="dns"}', limit=fetch)

    # Reunir items normalizados (ts_ns, severity, kind, team).
    norm = []   # (ts_ns, severity, kind, team)
    for ts_ns, line, labels in plat_rows:
        try:
            it = map_platform(ts_ns, line, labels)
        except Exception:
            it = None
        if it:
            norm.append((ts_ns, it["severity"], it["kind"], it["team"]))
    for ts_ns, line, labels in vpn_rows:
        try:
            it = map_vpn(ts_ns, line, labels)
        except Exception:
            it = None
        if it:
            norm.append((ts_ns, it["severity"], it["kind"], it["team"]))
    for ts_ns, line, labels in sur_rows:
        try:
            it = map_suricata(ts_ns, line, labels)
        except Exception:
            it = None
        if it:
            norm.append((ts_ns, it["severity"], it["kind"], it["team"]))
    try:
        for it in map_dns_batch(dns_rows):
            norm.append((it["ts_ns"], it["severity"], it["kind"], it["team"]))
    except Exception:
        pass
    try:
        chal_items, _cur = map_challenge_flows(flow_rows)
        for it in chal_items:
            norm.append((it["ts_ns"], it["severity"], it["kind"], it["team"]))
    except Exception:
        pass
    try:
        _scan_v, scan_feed = detect_scans(flow_rows)
        for it in scan_feed:
            norm.append((it["ts_ns"], it["severity"], it["kind"], it["team"]))
    except Exception:
        pass

    # Buckets por minuto: el último bucket termina en el minuto actual.
    now = datetime.now(timezone.utc)
    now_min = now.replace(second=0, microsecond=0)
    labels = []
    bucket_start = []   # ts (datetime) inicio de cada bucket, ascendente
    for i in range(minutes - 1, -1, -1):
        b = now_min.timestamp() - i * 60
        bd = datetime.fromtimestamp(b, tz=timezone.utc)
        bucket_start.append(b)
        # Hora local del navegador no aplica aquí; mostramos UTC HH:MM.
        labels.append(bd.strftime("%H:%M"))

    events = [0] * minutes
    alerts = [0] * minutes
    ai_blocked = [0] * minutes
    by_team = defaultdict(int)

    win_start = bucket_start[0]
    for ts_ns, sev, kind, team in norm:
        ts = ts_ns / 1_000_000_000
        if ts < win_start:
            continue
        idx = int((ts - win_start) // 60)
        if idx < 0 or idx >= minutes:
            continue
        events[idx] += 1
        if sev in ("alert", "critical"):
            alerts[idx] += 1
        if kind == "ai_block":
            ai_blocked[idx] += 1
        if team and "?" not in team:
            by_team[team] += 1

    by_team_sorted = dict(sorted(by_team.items(), key=lambda kv: kv[0]))

    return {
        "labels": labels,
        "events": events,
        "alerts": alerts,
        "ai_blocked": ai_blocked,
        "by_team": by_team_sorted,
        "minutes": minutes,
    }


# ----------------------------------------------------------------------------
# Endpoints
# ----------------------------------------------------------------------------
@app.get("/")
async def index():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file), media_type="text/html")
    return JSONResponse({"error": "index.html no encontrado"}, status_code=500)


@app.get("/streams")
async def streams():
    f = STATIC_DIR / "streams.html"
    if f.exists():
        return FileResponse(str(f), media_type="text/html")
    return JSONResponse({"error": "streams.html no encontrado"}, status_code=500)


@app.get("/api/feed")
async def api_feed(limit: int = 80, team: str = None):
    limit = max(1, min(limit, 300))
    team_lbl = None
    if team:
        # Acepta 'NN', 'Equipo NN' o 'team_NN'.
        team_lbl = team_from_team_id(team) or _team_label_from_nn(team)
        if not team_lbl and str(team).strip().lower().startswith("equipo"):
            team_lbl = team
    items = await collect_feed(limit=limit, team=team_lbl)
    return JSONResponse(items)


@app.get("/api/team/{nn}")
async def api_team(nn: str, recent: int = 20):
    recent = max(1, min(recent, 80))
    detail = await collect_team_detail(nn, recent=recent)
    if detail is None:
        return JSONResponse({"error": "equipo inválido"}, status_code=404)
    return JSONResponse(detail)


@app.get("/api/timeseries")
async def api_timeseries(minutes: int = 15):
    return JSONResponse(await collect_timeseries(minutes=minutes))


@app.get("/api/scoreboard")
async def api_scoreboard():
    return JSONResponse(await collect_scoreboard())


@app.get("/api/teams")
async def api_teams():
    return JSONResponse(await collect_teams())


@app.get("/api/violations")
async def api_violations(limit: int = 40):
    limit = max(1, min(limit, 200))
    return JSONResponse(await collect_violations(limit=limit))


@app.get("/api/stats")
async def api_stats():
    return JSONResponse(await collect_stats())


@app.get("/api/health")
async def api_health():
    loki_up = False
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            r = await client.get(f"{LOKI_URL}/ready")
            loki_up = r.status_code < 500
    except Exception:
        loki_up = False
    return JSONResponse(
        {
            "status": "ok",
            "service": "caster-overlay",
            "ctf_name": CTF_NAME,
            "loki_url": LOKI_URL,
            "loki_reachable": loki_up,
            "window_min": WINDOW_MIN,
            "ts": int(time.time()),
        }
    )


# Sirve estáticos sin pisar /api.
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
