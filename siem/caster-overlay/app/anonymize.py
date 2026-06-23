"""
Anonimización de IPs para el overlay PÚBLICO de comentaristas/stream.

REGLA CRÍTICA: este overlay es público (OBS / stream). NUNCA puede salir
una IP real al aire. Toda salida del servicio debe pasar por anonymize().

Mapeo (basado en docs/ARCHITECTURE.md sección 2 - Plan de Red):

  10.10.N.M       (N = 1..5)    -> nombre del equipo (VPN, subnet de equipo)
  10.10.100.x                   -> "plataforma"  (plataforma + servicios internos)
  10.10.200.x                   -> "siem"        (stack SIEM)
  10.10.0.x                     -> "interno"     (pool VPN sin asignar)
  172.30.N.x      (N = 1..5)    -> "reto(NombreEquipo)" (red Docker de retos del team_N)
  otra IP interna 10.x / 172.x / 192.168.x       -> "interno"
  cualquier IP pública                            -> "externo"

Cualquier IP que aparezca embebida en texto libre se sustituye in-place,
de modo que frases como "blocked 10.10.3.4 -> 10.10.100.10" salgan como
"blocked Equipo 03 -> plataforma".
"""

import ipaddress
import re

# Detecta IPv4 dentro de texto libre (con límites razonables, sin capturar
# por ejemplo versiones tipo 1.2.3.4 dentro de palabras — exigimos frontera).
_IP_RE = re.compile(
    r"(?<![\w.])"
    r"((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})"
    r"(?![\w.])"
)

TEAM_NAMES = {
    1: "Bytreach",
    2: "MoodySploiters",
    3: "DARKHIVE",
    4: "Threat Hunters",
    5: "Capa 8",
}

# Jugadores por equipo: team_N -> [jugador_1, jugador_2, jugador_3, jugador_4]
# Completar con los nombres reales de vpn/teams.json antes del deploy.
PLAYER_NAMES: dict[int, list[str]] = {
    1: ["sh4dowxz", "gorje", "AlarmW", "kincito"],          # Bytreach
    2: ["quimichin", "Aulloaal", "Marinex", "NA787"],        # MoodySploiters
    3: ["ast4x", "NoTtrebor", "Italo", "Onhubxx"],           # DARKHIVE
    4: ["vulc4nx", "APT404", "m4thv", "K4w0rU2"],            # Threat Hunters
    5: ["SonyB0t", "rafooo_6", "Fetuccini", "Michi"],        # Capa 8
}


def _player_label(team_n: int, player_idx: int) -> str:
    """Devuelve el nombre del jugador (1-based) o 'Jugador N' como fallback."""
    names = PLAYER_NAMES.get(team_n, [])
    if names and 1 <= player_idx <= len(names):
        return names[player_idx - 1]
    return f"Jugador {player_idx}"


def _team_label(n: int) -> str:
    """team N -> nombre del equipo (o 'Equipo NN' como fallback)."""
    return TEAM_NAMES.get(n, f"Equipo {n:02d}")


def anonymize_ip(ip: str) -> str:
    """
    Traduce una sola IP a su etiqueta anónima.
    Si el string no es una IP válida, lo devuelve tal cual.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip

    # IPv6 u otros: nunca exponer
    if addr.version != 4:
        return "externo" if addr.is_global else "interno"

    octets = ip.split(".")
    o = [int(x) for x in octets]

    # Red VPN / equipos / plataforma / siem: 10.10.x.x
    if o[0] == 10 and o[1] == 10:
        if 1 <= o[2] <= 5:
            return _team_label(o[2])          # 10.10.N.M -> nombre equipo
        if o[2] == 100:
            return "plataforma"               # 10.10.100.x
        if o[2] == 200:
            return "siem"                      # 10.10.200.x
        if o[2] == 0:
            return "interno"                   # 10.10.0.x (pool sin asignar)
        return "interno"                       # resto 10.10.x.x

    # Red Docker de retos por equipo: 172.30.N.x
    if o[0] == 172 and o[1] == 30:
        if 1 <= o[2] <= 5:
            return f"reto({_team_label(o[2])})"
        return "reto"

    # Cualquier otra IP privada -> interno
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return "interno"

    # IP pública -> externo (jamás mostrar una IP pública)
    return "externo"


def team_from_ip(ip: str):
    """
    Devuelve 'Equipo NN' si la IP pertenece a una subnet de equipo
    (10.10.N.0/24 con N=1..10), si no None. Útil para asociar logs de
    dnsmasq/suricata a un equipo.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version != 4:
        return None
    o = ip.split(".")
    a, b, c = int(o[0]), int(o[1]), int(o[2])
    if a == 10 and b == 10 and 1 <= c <= 5:
        return _team_label(c)
    return None


def team_from_team_id(team_id):
    """team_03 / team_01_alice / team_01_p2 -> nombre del equipo. Cualquier otra cosa -> None."""
    if not team_id:
        return None
    # Acepta: team_NN, team_NN_pX (legacy), team_NN_playername (nuevo).
    m = re.match(r"team_?(\d{1,2})(?:_.+)?$", str(team_id).strip(), re.IGNORECASE)
    if not m:
        return None
    return _team_label(int(m.group(1)))


def anonymize(text: str) -> str:
    """
    Sustituye TODAS las IPs presentes en `text` por sus etiquetas anónimas.
    Es la función que DEBE envolver toda salida pública del servicio.
    """
    if text is None:
        return ""
    text = str(text)
    return _IP_RE.sub(lambda m: anonymize_ip(m.group(1)), text)


if __name__ == "__main__":
    # ---- Tests rápidos de privacidad ----
    cases_ip = [
        ("10.10.3.4", "DARKHIVE"),
        ("10.10.1.100", "Bytreach"),
        ("10.10.5.1",  "Capa 8"),
        ("10.10.6.1",  "interno"),      # equipo 6 no existe → interno
        ("10.10.100.10", "plataforma"),
        ("10.10.100.2", "plataforma"),
        ("10.10.200.20", "siem"),
        ("10.10.200.30", "siem"),
        ("10.10.0.5", "interno"),
        ("10.10.55.5", "interno"),
        ("172.30.3.5", "reto(DARKHIVE)"),
        ("172.30.5.9", "reto(Capa 8)"),
        ("172.30.6.9", "reto"),          # equipo 6 no existe → reto genérico
        ("172.30.99.9", "reto"),
        ("192.168.1.5", "interno"),
        ("10.0.0.1", "interno"),
        ("8.8.8.8", "externo"),
        ("104.18.32.47", "externo"),
        ("1.1.1.1", "externo"),
        ("no-es-ip", "no-es-ip"),
    ]
    failed = 0
    for raw, expected in cases_ip:
        got = anonymize_ip(raw)
        ok = got == expected
        failed += 0 if ok else 1
        print(f"[{'OK' if ok else 'FAIL'}] anonymize_ip({raw!r}) = {got!r} (esperado {expected!r})")

    cases_text = [
        (
            "blocked 10.10.3.4 -> 10.10.100.10 dns 8.8.8.8",
            "blocked DARKHIVE -> plataforma dns externo",
        ),
        (
            "DARKHIVE intentó resolver chat.openai.com desde 10.10.3.4",
            "DARKHIVE intentó resolver chat.openai.com desde DARKHIVE",
        ),
        (
            "nmap scan 10.10.3.22 hacia 172.30.3.10",
            "nmap scan DARKHIVE hacia reto(DARKHIVE)",
        ),
        (
            "version 1.2 build 3 no toca octetos sueltos",
            "version 1.2 build 3 no toca octetos sueltos",
        ),
        (
            "rango 10.10.200.0/24 es siem",
            "rango siem/24 es siem",
        ),
    ]
    for raw, expected in cases_text:
        got = anonymize(raw)
        ok = got == expected
        failed += 0 if ok else 1
        print(f"[{'OK' if ok else 'FAIL'}] anonymize({raw!r})")
        if not ok:
            print(f"        got={got!r}")
            print(f"   expected={expected!r}")

    # Garantía dura: ninguna salida debe contener un patrón IPv4 público.
    leak_probe = anonymize("conexiones 8.8.8.8 y 200.48.225.130 y 10.10.4.4")
    assert "8.8.8.8" not in leak_probe and "200.48.225.130" not in leak_probe, "FUGA DE IP PUBLICA"
    print(f"[OK] sin fuga de IP pública: {leak_probe!r}")

    print()
    if failed:
        print(f"=== {failed} test(s) FALLARON ===")
        raise SystemExit(1)
    print("=== todos los tests OK ===")
