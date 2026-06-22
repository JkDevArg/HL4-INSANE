"""CoinSwap Exchange — web-coinswap (Web INSANE) · "Race Condition en Retiros".

Vulnerabilidad central: CONDICION DE CARRERA / TOCTOU en el flujo de swap
de criptomonedas. El check de saldo y el descuento ocurren en momentos
distintos con una ventana real en medio — sin lock ni atomicidad.

Flujo /swap:
  (1) CHECK : lee coin_a = wallet["COIN_A"]  <- time-of-check
              si coin_a < amount: rechazar
  (2) GAP   : sleep(RACE_WINDOW)             <- ventana real de carrera
  (3) USE   : wallet["COIN_A"] = coin_a_snapshot - amount  <- time-of-use
              wallet["COIN_B"] = coin_b_snapshot + amount
              (escritura basada en snapshot del paso 1, no en estado actual)

N peticiones concurrentes con amount=100 durante la ventana:
  - Todas leen COIN_A=100 (pasan el check)
  - Todas escriben COIN_B = 0 + 100 = 100 (pero COIN_A deberia ser 0)
  - En la practica: COIN_B acumula N*100 porque las escrituras usan el snapshot
    (el ultimo escritor "gana" en COIN_A, pero COIN_B se "suma" varias veces)

Para hacer la carrera interesante y acumulable, el write de COIN_B usa += sobre
el estado actual (no snapshot), pero el write de COIN_A usa el snapshot.
Esto significa: COIN_A baja correctamente pero COIN_B se acumula por cada
hilo concurrente que pasa el check. Resultado: COIN_B puede crecer mucho
mas alla del 1:1 con COIN_A.
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

# --- Parametros del exchange ---
COIN_A_START = 100      # saldo inicial COIN_A
COIN_B_START = 0        # saldo inicial COIN_B
VAULT_THRESHOLD = 10000 # saldo minimo para desbloquear la boveda
SWAP_RATE = 1           # 1 COIN_A = 1 COIN_B

# Ventana de carrera: suficientemente larga para explotar con concurrencia,
# suficientemente corta para no afectar uso serie.
RACE_WINDOW = float(os.environ.get("RACE_WINDOW", "0.08"))

# Estado en memoria por sesion: {sid: {"COIN_A": int, "COIN_B": int}}
_WALLETS: dict[str, dict] = {}
_init_lock = threading.Lock()


def _ensure_wallet(sid: str) -> dict:
    w = _WALLETS.get(sid)
    if w is None:
        with _init_lock:
            w = _WALLETS.get(sid)
            if w is None:
                w = {"COIN_A": COIN_A_START, "COIN_B": COIN_B_START}
                _WALLETS[sid] = w
    return w


def _sid() -> str:
    return request.cookies.get("swap_sid") or uuid.uuid4().hex


def _with_cookie(resp: Response, sid: str) -> Response:
    resp.set_cookie("swap_sid", sid, httponly=True, samesite="Lax")
    return resp


# ---------------------------------------------------------------------------
# HTML de la interfaz
# ---------------------------------------------------------------------------
_INDEX_HTML = """<!doctype html>
<html lang="es">
<head><meta charset="utf-8"><title>CoinSwap Exchange</title>
<style>
*{box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:#0a0e1a;color:#e0e6f0;margin:0}
.header{background:linear-gradient(135deg,#1a237e,#4a148c);padding:1.5rem 2rem;display:flex;align-items:center;gap:1rem}
.header h1{margin:0;font-size:1.8rem;color:#fff}
.logo{width:40px;height:40px;background:#7c4dff;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:1.5rem}
.container{max-width:960px;margin:2rem auto;padding:0 1rem;display:grid;grid-template-columns:1fr 1fr;gap:1.5rem}
.card{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:1.5rem}
.card h2{margin:0 0 1rem;color:#818cf8;font-size:1.1rem;text-transform:uppercase;letter-spacing:.05em}
.balance-grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1rem}
.coin-box{background:#0d1117;border:1px solid #374151;border-radius:8px;padding:1rem;text-align:center}
.coin-name{font-size:.8rem;color:#6b7280;text-transform:uppercase;letter-spacing:.1em}
.coin-val{font-size:2rem;font-weight:bold;color:#34d399;margin:.3rem 0}
.coin-val.coin-b{color:#818cf8}
.full-width{grid-column:1/-1}
input[type=number]{background:#0d1117;border:1px solid #374151;color:#e0e6f0;padding:.7rem;border-radius:6px;width:100%;font-size:1rem;margin:.3rem 0}
select{background:#0d1117;border:1px solid #374151;color:#e0e6f0;padding:.7rem;border-radius:6px;width:100%;font-size:1rem;margin:.3rem 0}
button{background:#4f46e5;color:white;border:none;padding:.8rem 1.5rem;border-radius:6px;cursor:pointer;font-size:1rem;width:100%;margin-top:.5rem}
button:hover{background:#6366f1}
button.vault-btn{background:#7c3aed}
button.vault-btn:hover{background:#8b5cf6}
pre{background:#0d1117;border:1px solid #374151;border-radius:6px;padding:1rem;overflow-x:auto;font-size:.85rem;color:#a0aec0;white-space:pre-wrap;min-height:4rem}
label{font-size:.9rem;color:#9ca3af}
.hint{font-size:.8rem;color:#4b5563;margin-top:.5rem}
.api-box{background:#0d1117;border:1px solid #374151;border-radius:6px;padding:1rem;font-family:monospace;font-size:.85rem;color:#7dd3fc}
</style>
</head>
<body>
<div class="header">
  <div class="logo">&#9889;</div>
  <h1>CoinSwap Exchange</h1>
  <span style="margin-left:auto;color:#818cf8;font-size:.9rem">Decentralized &middot; Fast &middot; Secure</span>
</div>
<div class="container">
  <div class="card">
    <h2>Tu Cartera</h2>
    <div class="balance-grid">
      <div class="coin-box">
        <div class="coin-name">COIN_A</div>
        <div class="coin-val" id="coin-a">-</div>
      </div>
      <div class="coin-box">
        <div class="coin-name">COIN_B</div>
        <div class="coin-val coin-b" id="coin-b">-</div>
      </div>
    </div>
    <button onclick="getBalance()">Actualizar Saldo</button>
  </div>

  <div class="card">
    <h2>Swap</h2>
    <label>Par de intercambio</label>
    <select id="pair">
      <option value="A_to_B">COIN_A &rarr; COIN_B (rate 1:1)</option>
      <option value="B_to_A">COIN_B &rarr; COIN_A (rate 1:1)</option>
    </select>
    <label>Cantidad</label>
    <input type="number" id="amount" value="10" min="1"/>
    <button onclick="doSwap()">Ejecutar Swap</button>
    <div class="hint">&#9888; El swap verifica saldo antes de procesar. La transaccion tarda ~80ms.</div>
  </div>

  <div class="card full-width">
    <h2>Boveda de Recompensas</h2>
    <p style="color:#6b7280">La boveda se abre cuando tu saldo alcanza <strong style="color:#fbbf24">10,000 de cualquier moneda</strong>. Jugar en serie solo llega a 100 COIN_B.</p>
    <button class="vault-btn" onclick="openVault()">Intentar Abrir Boveda</button>
  </div>

  <div class="card full-width">
    <h2>Respuesta API</h2>
    <pre id="output">// Los resultados apareceran aqui</pre>
    <div class="api-box">
      API: POST /swap (JSON) &middot; GET /balance &middot; GET /vault
    </div>
  </div>
</div>
<script>
const out = document.getElementById('output');
const show = d => { out.textContent = JSON.stringify(d,null,2); };

async function getBalance(){
  const r = await fetch('/balance');
  const d = await r.json();
  show(d);
  document.getElementById('coin-a').textContent = d.COIN_A ?? '-';
  document.getElementById('coin-b').textContent = d.COIN_B ?? '-';
}

async function doSwap(){
  const pair = document.getElementById('pair').value;
  const amount = parseInt(document.getElementById('amount').value);
  const from_coin = pair === 'A_to_B' ? 'COIN_A' : 'COIN_B';
  const to_coin   = pair === 'A_to_B' ? 'COIN_B' : 'COIN_A';
  const r = await fetch('/swap', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({from: from_coin, to: to_coin, amount})
  });
  const d = await r.json();
  show(d);
  getBalance();
}

async function openVault(){
  const r = await fetch('/vault');
  const d = await r.json();
  show(d);
}

getBalance();
</script>
</body>
</html>"""


@app.before_request
def _log_request():
    try:
        src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        if src_ip and "," in src_ip:
            src_ip = src_ip.split(",")[0].strip()
        body = request.get_data(cache=True, as_text=True)
        reqlog_http(src_ip=src_ip, method=request.method, path=request.path,
                    query=request.query_string.decode("utf-8", "replace"),
                    headers=dict(request.headers), body=body)
    except Exception:
        pass


@app.get("/")
def index():
    sid = _sid()
    _ensure_wallet(sid)
    return _with_cookie(
        Response(_INDEX_HTML, mimetype="text/html; charset=utf-8"), sid
    )


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.get("/balance")
def balance():
    sid = _sid()
    w = _ensure_wallet(sid)
    resp = jsonify({
        "COIN_A": w["COIN_A"],
        "COIN_B": w["COIN_B"],
        "vault_threshold": VAULT_THRESHOLD,
        "swap_rate": f"1:{SWAP_RATE}",
    })
    return _with_cookie(resp, sid)


@app.post("/swap")
def swap():
    """Intercambia coins. TOCTOU: check y write no son atomicos.

    La ventana de RACE_WINDOW segundos entre (1) check y (3) write
    permite que peticiones concurrentes lean el mismo saldo alto,
    pasen el check y acrediten COIN_B varias veces desde el mismo snapshot.
    """
    sid = _sid()
    w = _ensure_wallet(sid)
    src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if src_ip and "," in src_ip:
        src_ip = src_ip.split(",")[0].strip()

    data = request.get_json(silent=True) or {}
    from_coin = data.get("from", "COIN_A")
    to_coin   = data.get("to",   "COIN_B")
    amount    = data.get("amount", 0)

    if from_coin not in ("COIN_A", "COIN_B") or to_coin not in ("COIN_A", "COIN_B"):
        return _with_cookie(jsonify({"error": "Moneda invalida. Use COIN_A o COIN_B"}), sid), 400
    if from_coin == to_coin:
        return _with_cookie(jsonify({"error": "Las monedas deben ser diferentes"}), sid), 400

    try:
        amount = int(amount)
        if amount <= 0:
            raise ValueError
    except (ValueError, TypeError):
        return _with_cookie(jsonify({"error": "amount debe ser un entero positivo"}), sid), 400

    # (1) TIME-OF-CHECK: leer saldo desde el estado compartido (SIN lock)
    #     Todas las peticiones concurrentes leen el mismo snapshot aqui.
    from_balance_snapshot = w[from_coin]
    to_balance_snapshot   = w[to_coin]

    if from_balance_snapshot < amount:
        resp = jsonify({
            "error": "Saldo insuficiente",
            "have": from_balance_snapshot,
            "need": amount,
        })
        return _with_cookie(resp, sid), 402

    # (2) GAP: procesamiento de la transaccion (ventana real de carrera)
    #     Durante este sleep, otras peticiones concurrentes pueden leer el
    #     mismo snapshot de from_balance y pasar el check.
    time.sleep(RACE_WINDOW)

    # (3) TIME-OF-USE: escribir de vuelta al estado compartido (SIN lock).
    #     La resta de from_coin usa el snapshot (correcto: baja de verdad).
    #     La suma de to_coin usa += sobre el estado ACTUAL:
    #     cada hilo concurrente suma su propio amount al estado actual,
    #     pero todos partieron del mismo from_balance -> from_coin baja
    #     solo 1x mientras to_coin sube N*amount (double credit).
    w[from_coin] = from_balance_snapshot - amount  # escribe snapshot - amount
    w[to_coin]  += amount                           # += sobre estado actual -> acumulativo

    resp = jsonify({
        "swapped": True,
        "from": from_coin,
        "to": to_coin,
        "amount": amount,
        "new_balance": {
            "COIN_A": w["COIN_A"],
            "COIN_B": w["COIN_B"],
        },
    })
    return _with_cookie(resp, sid)


@app.get("/vault")
def vault():
    """Boveda de recompensas. Solo abre si alguna moneda >= VAULT_THRESHOLD."""
    sid = _sid()
    w = _ensure_wallet(sid)
    src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if src_ip and "," in src_ip:
        src_ip = src_ip.split(",")[0].strip()

    coin_a = w["COIN_A"]
    coin_b = w["COIN_B"]

    if coin_a >= VAULT_THRESHOLD or coin_b >= VAULT_THRESHOLD:
        emit("challenge_solved", "alert", src_ip=src_ip,
             detail={"vuln": "toctou-double-credit-swap",
                     "COIN_A": coin_a, "COIN_B": coin_b,
                     "threshold": VAULT_THRESHOLD})
        return _with_cookie(jsonify({
            "vault": "UNLOCKED",
            "COIN_A": coin_a,
            "COIN_B": coin_b,
            "note": "Saldo imposible en serie: race condition detectada",
            "flag": FLAG,
        }), sid)

    return _with_cookie(jsonify({
        "vault": "LOCKED",
        "COIN_A": coin_a,
        "COIN_B": coin_b,
        "vault_threshold": VAULT_THRESHOLD,
        "hint": f"Necesitas {VAULT_THRESHOLD}+ de cualquier moneda. Maximo en serie: 100.",
    }), sid), 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True)
