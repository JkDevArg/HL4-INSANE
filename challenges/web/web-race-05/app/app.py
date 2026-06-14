"""Coin Vault — web-race-05 (Web INSANE) · "Double Spend".

Vulnerabilidad central: CONDICION DE CARRERA / TOCTOU (Time-of-Check
Time-of-Use) en un flujo de canje de cupones por "coins".

Modelo:
  - Cada sesion arranca con un saldo limitado de CUPONES (COUPONS_START=5).
  - Cada cupon canjeado en /redeem entrega COINS_PER_REDEEM=20 coins.
  - En SERIE, lo maximo que puedes conseguir es COUPONS_START * COINS_PER_REDEEM
    = 100 coins. La flag se desbloquea en /treasure SOLO si superas
    TREASURE_THRESHOLD=200 coins -> imposible jugando limpio (en serie).

La VULN (deliberada):
  El estado del vault (coupons, coins) vive en memoria por sesion y /redeem hace
  un READ-MODIFY-WRITE NO atomico SIN lock, con una VENTANA real en medio:

      1) CHECK : c = state["coupons"]  ;  m = state["coins"]   <- time-of-check
                 if c <= 0: rechazar
      2) GAP   : new_c = c - 1 ; new_m = m + 20  (sobre el snapshot)
                 time.sleep(RACE_WINDOW)                        <- ventana de carrera
      3) USE   : state["coupons"] = new_c                       <- time-of-use
                 state["coins"]   = new_m

  El decremento de cupones y el credito de coins se ESCRIBEN a partir del
  snapshot leido en (1), no del estado ACTUAL. Como Flask sirve con threaded=True
  y no hay lock, N peticiones que entran a la vez en la ventana TODAS leen el
  mismo (coupons, coins), TODAS pasan el check (coupons>=1) y TODAS escriben
  `coins = snapshot+20`. Los decrementos de cupones se PIERDEN (lost update):
  coupons baja muchisimo menos de lo que deberia mientras coins se acumula muy
  por encima del maximo en serie. Resultado: DOUBLE SPEND -> coins > umbral
  -> flag.

Por que un lock/transaccion lo arreglaria: si el check y el descuento fuesen
ATOMICOS (un lock por sesion que envuelva read+write, o un decremento atomico
condicional `coupons-=1 if coupons>0`), solo UNA de las concurrentes ganaria el
cupon; el resto veria coupons=0 y seria rechazada. La carrera vive EXACTAMENTE
en el hueco entre leer (check) y escribir (use), sin lock que lo cierre.

Estado aislado por SESION (cookie vault_sid -> entrada propia en el dict en
memoria), compartido entre los hilos del servidor -> la carrera es genuina.

La FLAG se inyecta por equipo via env FLAG. NO hardcodeada.
"""
import os
import threading
import time
import uuid

from flask import Flask, Response, jsonify, request

from siem import emit
from reqlog import reqlog_http

app = Flask(__name__)

FLAG = os.environ.get("FLAG", "flag{EJEMPLO_LOCAL}")

# --- Reglas economicas del vault ------------------------------------------
COUPONS_START = 5          # cupones iniciales por sesion
COINS_PER_REDEEM = 20      # coins que entrega canjear un cupon
# Maximo teorico jugando en serie: 5 * 20 = 100 coins.
TREASURE_THRESHOLD = 200   # > maximo teorico -> solo alcanzable con double-spend

# Ventana de la carrera (segundos). Suficientemente grande para que sea
# EXPLOTABLE con concurrencia normal, suficientemente pequena para no afectar al
# juego serie (un cliente secuencial nunca solapa peticiones).
RACE_WINDOW = float(os.environ.get("RACE_WINDOW", "0.15"))

# Estado en memoria por sesion: { sid: {"coupons": int, "coins": int} }.
# NO hay lock alrededor del read-modify-write de /redeem: ahi vive la vuln.
_VAULTS: dict[str, dict] = {}
# Lock SOLO para crear la entrada de la sesion (NO protege /redeem).
_init_lock = threading.Lock()


def _ensure_session(sid: str) -> dict:
    """Crea/devuelve el estado de la sesion. La creacion SI esta bajo lock (no
    es la vuln); el canje posterior NO."""
    st = _VAULTS.get(sid)
    if st is None:
        with _init_lock:
            st = _VAULTS.get(sid)
            if st is None:
                st = {"coupons": COUPONS_START, "coins": 0}
                _VAULTS[sid] = st
    return st


# --------------------------------------------------------------------------
# Logging CTFREQ para el SIEM del stream (igual que web-ssrf-02)
# --------------------------------------------------------------------------
@app.before_request
def _log_request():
    """Loguea CADA peticion entrante COMPLETA (metodo, ruta, query, headers,
    body) para el SIEM del stream. No interfiere con el manejo normal."""
    try:
        src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        if src_ip and "," in src_ip:
            src_ip = src_ip.split(",")[0].strip()
        body = request.get_data(cache=True, as_text=True)
        reqlog_http(
            src_ip=src_ip,
            method=request.method,
            path=request.path,
            query=request.query_string.decode("utf-8", "replace"),
            headers=dict(request.headers),
            body=body,
        )
    except Exception:
        pass


def _sid() -> str:
    """Devuelve el session-id desde la cookie; si no hay, genera uno nuevo."""
    return request.cookies.get("vault_sid") or uuid.uuid4().hex


def _with_cookie(resp: Response, sid: str) -> Response:
    resp.set_cookie("vault_sid", sid, httponly=True, samesite="Lax")
    return resp


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------
INDEX = """<!doctype html><html lang="es"><head><meta charset="utf-8">
<title>Coin Vault</title></head><body style="font-family:sans-serif;max-width:760px;margin:2rem auto">
<h1>Coin Vault &middot; Coupon Exchange</h1>
<p>Tu boveda arranca con <b>%(coupons)d cupones</b>. Cada canje en
<code>/redeem</code> gasta 1 cupon y te acredita <b>%(coins)d coins</b>.
El maximo teorico que puedes acumular es <b>%(maxcoins)d coins</b>.</p>
<p>La camara del tesoro (<code>/treasure</code>) solo abre si tu saldo supera
<b>%(threshold)d coins</b>... lo cual, jugando limpio, es imposible.</p>
<form onsubmit="redeem(event)"><button>Canjear 1 cupon</button></form>
<form onsubmit="bal(event)"><button>Ver saldo</button></form>
<form onsubmit="treas(event)"><button>Abrir el tesoro</button></form>
<pre id="out" style="background:#111;color:#0f0;padding:1rem;white-space:pre-wrap"></pre>
<p style="color:#888">API:
 <code>POST /redeem</code> &middot;
 <code>GET /balance</code> &middot;
 <code>GET /treasure</code></p>
<script>
async function call(m,p){const r=await fetch(p,{method:m});
 document.getElementById('out').textContent=JSON.stringify(await r.json(),null,2);}
function redeem(e){e.preventDefault();call('POST','/redeem');}
function bal(e){e.preventDefault();call('GET','/balance');}
function treas(e){e.preventDefault();call('GET','/treasure');}
</script></body></html>"""


@app.get("/")
def index():
    sid = _sid()
    _ensure_session(sid)
    html = INDEX % {
        "coupons": COUPONS_START,
        "coins": COINS_PER_REDEEM,
        "maxcoins": COUPONS_START * COINS_PER_REDEEM,
        "threshold": TREASURE_THRESHOLD,
    }
    return _with_cookie(Response(html, mimetype="text/html"), sid)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/balance")
def balance():
    sid = _sid()
    st = _ensure_session(sid)
    resp = jsonify({
        "coupons": st["coupons"],
        "coins": st["coins"],
        "max_serial_coins": COUPONS_START * COINS_PER_REDEEM,
        "treasure_threshold": TREASURE_THRESHOLD,
    })
    return _with_cookie(resp, sid)


@app.post("/redeem")
def redeem():
    """Canjea 1 cupon por COINS_PER_REDEEM coins.

    VULN TOCTOU: el check de saldo y el descuento NO son atomicos y no hay lock.
    Entre leer el estado (time-of-check) y escribirlo (time-of-use) hay una
    ventana real (RACE_WINDOW). Las escrituras parten del SNAPSHOT leido en el
    check, asi que peticiones concurrentes pisan los decrementos de cupones
    (lost update) mientras acumulan coins -> double spend.
    """
    sid = _sid()
    st = _ensure_session(sid)

    # (1) TIME-OF-CHECK: leemos el saldo de CUPONES y decidimos si se permite.
    #     Este snapshot es lo que abusan los hilos concurrentes: todos leen
    #     coupons>=1 ANTES de que nadie haya descontado.
    coupons_seen = st["coupons"]

    if coupons_seen <= 0:
        resp = jsonify({"error": "sin cupones",
                        "coupons": coupons_seen, "coins": st["coins"]})
        return _with_cookie(resp, sid), 402

    # (2) GAP / VENTANA: "validacion del cupon y acuñado de la recompensa".
    #     Trabajo NO atomico en medio del check y el descuento. Aqui es donde
    #     se solapan los hilos: todos ya pasaron el check de cupones.
    time.sleep(RACE_WINDOW)            # ventana real de la carrera

    # (3) TIME-OF-USE: acreditamos coins y descontamos el cupon. Read-modify-write
    #     en memoria SIN lock -> no atomico. La autorizacion se baso en el
    #     snapshot del paso (1); el descuento ya no esta ligado a el. N hilos
    #     que pasaron el check con un solo cupon acreditan N*20 coins (double
    #     spend) muy por encima del maximo en serie.
    st["coins"] += COINS_PER_REDEEM
    st["coupons"] -= 1

    resp = jsonify({"redeemed": True,
                    "coupons": st["coupons"], "coins": st["coins"]})
    return _with_cookie(resp, sid)


@app.get("/treasure")
def treasure():
    """Abre la camara del tesoro SOLO si el saldo de coins supera el umbral
    imposible-en-serie. Detectar ese saldo == double-spend exitoso -> flag."""
    sid = _sid()
    st = _ensure_session(sid)
    src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    coins = st["coins"]

    max_serial = COUPONS_START * COINS_PER_REDEEM
    if coins > TREASURE_THRESHOLD:
        emit("challenge_solved", "alert", src_ip=src_ip,
             detail={"vuln": "toctou-double-spend", "coins": coins,
                     "max_serial": max_serial})
        resp = jsonify({
            "treasure": "unlocked",
            "coins": coins,
            "note": "saldo imposible en serie: double-spend detectado",
            "flag": FLAG,
        })
        return _with_cookie(resp, sid)

    # Saldo dentro de lo posible jugando limpio -> nada que ver aqui.
    resp = jsonify({
        "treasure": "locked",
        "coins": coins,
        "treasure_threshold": TREASURE_THRESHOLD,
        "hint": f"necesitas mas de {TREASURE_THRESHOLD} coins; el maximo en serie es {max_serial}",
    })
    return _with_cookie(resp, sid), 403


if __name__ == "__main__":
    # threaded=True es CLAVE: permite peticiones concurrentes -> habilita la carrera.
    app.run(host="0.0.0.0", port=8080, threaded=True)
