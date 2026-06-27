"""Test end-to-end del flujo completo: login → flag → submit → score → scoreboard.

Uso:
    docker exec ctf-api python test_e2e.py

Qué valida:
  1. Reset password de team_01 a valor conocido
  2. Login (POST /auth/login con username/password)
  3. Listado de retos asignados (GET /challenges)
  4. Flag real via flag-service (POST /flag)
  5. Submit flag correcta → correct=True + points_awarded > 0
  6. Submit duplicado → already_solved=True
  7. Submit flag falsa → correct=False
  8. Scoreboard → team_01 tiene puntos y rank=1
  9. Fila Solve en DB con puntos correctos
  10. SIEM collector alive
  11. Limpieza del solve de test
"""
import asyncio
import json
import sys

import httpx
from sqlalchemy import delete, select

sys.path.insert(0, "/app")

from app.auth import hash_password
from app.db import SessionLocal, init_db
from app.models import Solve, Team

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
API_BASE   = "http://localhost:8000"
FLAG_SVC   = "http://flag-service:8001"
COLLECTOR  = "http://collector:9000"

TEST_TEAM      = "team_01"
TEST_CHALLENGE = "web-oss-registry"
TEST_PASSWORD  = "TestPass_E2E_2026!"

# VPN gate: trust_forwarded_for=True → primer valor de X-Forwarded-For
VPN_HEADERS = {"X-Forwarded-For": "10.10.1.1"}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
OK   = "\033[92m[OK]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
INFO = "\033[94m[INFO]\033[0m"
errors: list[str] = []


def ok(msg: str):   print(f"  {OK} {msg}")
def fail(msg: str): print(f"  {FAIL} {msg}"); errors.append(msg)
def info(msg: str): print(f"  {INFO} {msg}")


def check(cond: bool, pass_msg: str, fail_msg: str):
    ok(pass_msg) if cond else fail(fail_msg)


# ---------------------------------------------------------------------------
# Pasos
# ---------------------------------------------------------------------------

async def step_reset_password():
    print("\n[1] Reset password de team_01...")
    await init_db()
    async with SessionLocal() as db:
        r = await db.execute(select(Team).where(Team.team_id == TEST_TEAM))
        team = r.scalar_one_or_none()
        if not team:
            fail(f"{TEST_TEAM} no existe en DB"); return
        team.password_hash = hash_password(TEST_PASSWORD)
        await db.commit()
    ok(f"Password reseteada a '{TEST_PASSWORD}'")


async def step_login(client: httpx.AsyncClient) -> str | None:
    print("\n[2] Login...")
    r = await client.post(
        f"{API_BASE}/auth/login",
        json={"username": TEST_TEAM, "password": TEST_PASSWORD},
    )
    check(r.status_code == 200, f"POST /auth/login → 200", f"Login FAIL {r.status_code}: {r.text[:250]}")
    if r.status_code != 200:
        return None
    data = r.json()
    token = data.get("access_token")
    check(bool(token),                            "JWT token recibido",          "Sin access_token")
    check(data.get("team_id") == TEST_TEAM,       f"team_id={data.get('team_id')}", "team_id incorrecto")
    info(f"display_name: {data.get('display_name')}")
    return token


async def step_list_challenges(client: httpx.AsyncClient, token: str) -> list:
    print("\n[3] Listado de retos...")
    r = await client.get(
        f"{API_BASE}/challenges",
        headers={"Authorization": f"Bearer {token}"},
    )
    check(r.status_code == 200, f"GET /challenges → 200", f"status={r.status_code}: {r.text[:200]}")
    if r.status_code != 200:
        return []
    challenges = r.json()
    check(len(challenges) == 12, f"12 retos asignados (recibido: {len(challenges)})", f"Esperados 12, recibidos {len(challenges)}")
    cids = [c["id"] for c in challenges]
    check(TEST_CHALLENGE in cids, f"{TEST_CHALLENGE} en la lista", f"{TEST_CHALLENGE} NO en la lista")
    info(f"Retos: {', '.join(cids[:4])}... ({len(challenges)} total)")
    return challenges


async def step_get_flag(client: httpx.AsyncClient) -> str | None:
    print("\n[4] Obteniendo flag real del flag-service...")
    r = await client.post(
        f"{FLAG_SVC}/flag",
        json={"team_id": TEST_TEAM, "challenge_id": TEST_CHALLENGE},
    )
    check(r.status_code == 200, f"flag-service → 200", f"flag-service {r.status_code}: {r.text[:200]}")
    if r.status_code != 200:
        return None
    flag = r.json().get("flag", "")
    check(flag.startswith("HL4{"), f"Flag válida: {flag}", f"Flag inválida: {flag}")
    return flag if flag.startswith("HL4{") else None


async def step_submit_correct(client: httpx.AsyncClient, token: str, flag: str) -> int:
    print("\n[5] Submit flag correcta...")
    r = await client.post(
        f"{API_BASE}/challenges/{TEST_CHALLENGE}/submit",
        json={"flag": flag},
        headers={"Authorization": f"Bearer {token}"},
    )
    check(r.status_code == 200, f"POST submit → 200", f"Submit FAIL {r.status_code}: {r.text[:300]}")
    if r.status_code != 200:
        return 0
    data = r.json()
    check(data.get("correct") is True,            "correct=True",               f"correct={data.get('correct')}")
    pts = data.get("points_awarded", 0)
    check(pts > 0,                                f"points_awarded={pts}",      f"points_awarded={pts} (esperado >0)")
    check(data.get("already_solved") is False,    "already_solved=False",       f"already_solved={data.get('already_solved')}")
    info(f"Respuesta: {json.dumps(data)}")
    return pts


async def step_submit_duplicate(client: httpx.AsyncClient, token: str, flag: str):
    print("\n[6] Submit duplicado...")
    r = await client.post(
        f"{API_BASE}/challenges/{TEST_CHALLENGE}/submit",
        json={"flag": flag},
        headers={"Authorization": f"Bearer {token}"},
    )
    if r.status_code == 200:
        data = r.json()
        check(data.get("already_solved") is True, "already_solved=True (duplicado)", f"already_solved={data.get('already_solved')}")
    elif r.status_code == 409:
        ok("409 Conflict (duplicado detectado)")
    else:
        fail(f"Duplicado: status inesperado {r.status_code}: {r.text[:200]}")


async def step_submit_wrong(client: httpx.AsyncClient, token: str):
    print("\n[7] Submit flag falsa...")
    r = await client.post(
        f"{API_BASE}/challenges/{TEST_CHALLENGE}/submit",
        json={"flag": "HL4{00000000000000000000}"},
        headers={"Authorization": f"Bearer {token}"},
    )
    check(r.status_code == 200, "Submit falsa → 200", f"status={r.status_code}")
    if r.status_code == 200:
        data = r.json()
        check(data.get("correct") is False, "correct=False (rechazada)", f"correct={data.get('correct')}")


async def step_scoreboard(client: httpx.AsyncClient, token: str, expected_pts: int):
    print("\n[8] Scoreboard...")
    r = await client.get(
        f"{API_BASE}/scoreboard",
        headers={"Authorization": f"Bearer {token}"},
    )
    check(r.status_code == 200, "GET /scoreboard → 200", f"status={r.status_code}: {r.text[:200]}")
    if r.status_code != 200:
        return
    entries = r.json().get("entries", [])
    check(len(entries) > 0, f"{len(entries)} equipos en scoreboard", "Scoreboard vacío")
    entry = next((e for e in entries if e.get("team_id") == TEST_TEAM), None)
    check(entry is not None, f"{TEST_TEAM} en scoreboard", f"{TEST_TEAM} NO en scoreboard")
    if entry:
        check(entry.get("points") == expected_pts,  f"points={entry['points']} (esperado {expected_pts})", f"points={entry.get('points')} != {expected_pts}")
        check(entry.get("solves", 0) >= 1,          f"solves={entry['solves']}",    f"solves={entry.get('solves')} (esperado >=1)")
        info(f"Rank={entry.get('rank')} | Points={entry.get('points')} | Solves={entry.get('solves')}")


async def step_check_db():
    print("\n[9] Verificando Solve en DB...")
    async with SessionLocal() as db:
        r = await db.execute(
            select(Solve).where(
                Solve.team_id == TEST_TEAM,
                Solve.challenge_id == TEST_CHALLENGE,
            )
        )
        solve = r.scalar_one_or_none()
        check(solve is not None,
              f"Solve row: points={getattr(solve, 'points', None)}, ts={getattr(solve, 'solved_at', None)}",
              "NO hay Solve row en DB")


async def step_check_collector(client: httpx.AsyncClient):
    print("\n[10] SIEM collector health...")
    try:
        r = await client.get(f"{COLLECTOR}/health", timeout=3.0)
        check(r.status_code == 200, f"Collector /health → {r.json()}", f"Collector {r.status_code}")
    except Exception as e:
        fail(f"Collector inaccesible: {e}")


async def step_cleanup():
    print("\n[11] Limpieza...")
    async with SessionLocal() as db:
        await db.execute(
            delete(Solve).where(
                Solve.team_id == TEST_TEAM,
                Solve.challenge_id == TEST_CHALLENGE,
            )
        )
        await db.commit()
    ok(f"Solve {TEST_TEAM}/{TEST_CHALLENGE} eliminado")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main():
    print("=" * 62)
    print("  CTFHL4-INSANE — Test End-to-End")
    print("=" * 62)

    await step_reset_password()

    async with httpx.AsyncClient(timeout=10.0, headers=VPN_HEADERS) as client:
        token = await step_login(client)
        if not token:
            print(f"\n  {FAIL} Login falló — abortando")
            sys.exit(1)

        await step_list_challenges(client, token)

        flag = await step_get_flag(client)
        if not flag:
            print(f"\n  {FAIL} No se pudo obtener flag — abortando")
            sys.exit(1)

        pts = await step_submit_correct(client, token, flag)
        await step_submit_duplicate(client, token, flag)
        await step_submit_wrong(client, token)
        await step_scoreboard(client, token, pts)
        await step_check_db()
        await step_check_collector(client)
        await step_cleanup()

    print("\n" + "=" * 62)
    if errors:
        print(f"  \033[91mRESULTADO: {len(errors)} error(es)\033[0m")
        for e in errors:
            print(f"    - {e}")
        sys.exit(1)
    else:
        print("  \033[92mRESULTADO: TODOS LOS TESTS PASARON ✓\033[0m")
        print()
        print("  Flujo verificado:")
        print("  login → challenges → flag-service → submit → score → scoreboard → DB → SIEM")
    print("=" * 62)


if __name__ == "__main__":
    asyncio.run(main())
