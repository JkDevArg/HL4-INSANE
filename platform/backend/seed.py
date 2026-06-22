"""Siembra 5 equipos + 20 retos unicos + asignaciones exclusivas por equipo.

Anti-trampa: cada equipo recibe un reto diferente por categoria.
Ningun equipo comparte retos con otro.

Uso:
    python seed.py              # siembra incremental
    python seed.py --reset      # borra TODO y resiembra desde cero
"""
import argparse
import asyncio
import secrets
import string

from sqlalchemy import delete, select

from app.auth import hash_password
from app.db import SessionLocal, init_db
from app.models import Challenge, ChallengeInstance, Solve, Team, TeamChallengeAssignment

# ---------------------------------------------------------------------------
# 20 RETOS UNICOS — 5 web + 5 api + 5 crypto + 5 reversing
# (challenge_id, category, name, points, description, connection_info_template)
#
# connection_info usa {N} = numero del equipo (se renderiza al listar retos).
# Los octetos por categoria:
#   web:       172.30.{N}.10
#   api:       172.30.{N}.20
#   crypto:    172.30.{N}.30 (TCP)
#   reversing: 172.30.{N}.40 (HTTP para descarga + validacion)
# ---------------------------------------------------------------------------
CHALLENGES = [
    # ── WEB (5 retos, uno por equipo) ────────────────────────────────────────
    (
        "web-creditview",
        "web",
        "CreditView",
        700,
        "Portal de análisis crediticio con procesamiento de documentos en formato binario propietario.",
        "http://172.30.{N}.10:8080",
    ),
    (
        "web-reportgen",
        "web",
        "ReportGen",
        650,
        "Generador de reportes con sistema de plantillas y capa de filtros de seguridad.",
        "http://172.30.{N}.10:8080",
    ),
    (
        "web-docmanager",
        "web",
        "DocManager",
        700,
        "Sistema de gestión documental con integración a servicios web externos.",
        "http://172.30.{N}.10:8080",
    ),
    (
        "web-coinswap",
        "web",
        "CoinSwap",
        600,
        "Exchange de criptomonedas con soporte para operaciones concurrentes.",
        "http://172.30.{N}.10:8080",
    ),
    (
        "web-taskflow",
        "web",
        "TaskFlow",
        750,
        "Gestor de proyectos con funcionalidad de backup y restauración de estado.",
        "http://172.30.{N}.10:8080",
    ),

    # ── API (5 retos) ─────────────────────────────────────────────────────────
    (
        "api-datahub",
        "api",
        "DataHub",
        700,
        "API de analítica con soporte GraphQL para consultas y filtros personalizados.",
        "http://172.30.{N}.20:5001",
    ),
    (
        "api-cloudconnect",
        "api",
        "CloudConnect",
        650,
        "Servicio de autenticación para acceso federado a recursos en la nube.",
        "http://172.30.{N}.20:5002",
    ),
    (
        "api-metricstream",
        "api",
        "MetricStream",
        700,
        "API de métricas con endpoints internos de diagnóstico y monitoreo.",
        "http://172.30.{N}.20:5003",
    ),
    (
        "api-securevault",
        "api",
        "SecureVault",
        650,
        "Gestor de secretos con autenticación basada en tokens firmados.",
        "http://172.30.{N}.20:5004",
    ),
    (
        "api-hrmpro",
        "api",
        "HRM-Pro",
        600,
        "Sistema de gestión de recursos humanos con perfiles y roles de usuario.",
        "http://172.30.{N}.20:5005",
    ),

    # ── CRYPTO (5 retos) ──────────────────────────────────────────────────────
    (
        "crypto-rsalsb",
        "crypto",
        "RSA-LSB Oracle",
        700,
        "Servicio TCP con operaciones criptográficas sobre cifrado asimétrico RSA.",
        "nc 172.30.{N}.30 9999",
    ),
    (
        "crypto-paddingoracle",
        "crypto",
        "Padding Oracle",
        650,
        "Servicio TCP con esquema de cifrado simétrico por bloques y validación de relleno.",
        "nc 172.30.{N}.30 9999",
    ),
    (
        "crypto-ecdsanonce",
        "crypto",
        "ECDSA Nonce",
        750,
        "API HTTP de firma digital basada en criptografía de curva elíptica.",
        "http://172.30.{N}.30:9999",
    ),
    (
        "crypto-lengthext",
        "crypto",
        "Length Extension",
        600,
        "Servicio HTTP de autenticación mediante token criptográfico basado en hash.",
        "http://172.30.{N}.30:9999",
    ),
    (
        "crypto-hastad",
        "crypto",
        "Hastad Broadcast",
        700,
        "Servicio HTTP con datos cifrados distribuidos entre múltiples receptores.",
        "http://172.30.{N}.30:9999",
    ),

    # ── REVERSING (5 retos) ───────────────────────────────────────────────────
    (
        "rev-customvm",
        "reversing",
        "CustomVM",
        700,
        "Binario ELF con máquina virtual embebida y conjunto de instrucciones propio.",
        "http://172.30.{N}.40:6001  (GET /binary, POST /submit)",
    ),
    (
        "rev-gobinary",
        "reversing",
        "GoBinary",
        650,
        "Binario Go con algoritmo de validación de entrada y protecciones de análisis.",
        "http://172.30.{N}.40:6002  (GET /binary, POST /submit)",
    ),
    (
        "rev-wasmcrack",
        "reversing",
        "WASMCrack",
        700,
        "Binario nativo con algoritmo de validación de clave de licencia.",
        "http://172.30.{N}.40:6003  (GET /binary, POST /submit)",
    ),
    (
        "rev-packeddelta",
        "reversing",
        "PackedDelta",
        750,
        "Binario ELF con sección de datos cifrada y mecanismo de protección anti-análisis.",
        "http://172.30.{N}.40:6004  (GET /binary, POST /submit)",
    ),
    (
        "rev-dotnetobf",
        "reversing",
        "DotNET Obfuscated",
        700,
        "Bytecode compilado con esquema de validación de clave y nombres ofuscados.",
        "http://172.30.{N}.40:6005  (GET /binary, POST /submit)",
    ),
]

# ---------------------------------------------------------------------------
# Asignaciones: equipo N recibe el reto N de cada categoria (1-indexed)
# team_01 → [0], team_02 → [1], ..., team_05 → [4]
# ---------------------------------------------------------------------------
# [category][team_index] = challenge_id
CATEGORY_ORDER = ["web", "api", "crypto", "reversing"]

ASSIGNMENTS: dict[str, list[str]] = {
    f"team_{n:02d}": []
    for n in range(1, 6)
}

for cat in CATEGORY_ORDER:
    cat_challenges = [cid for cid, c, *_ in CHALLENGES if c == cat]
    for idx, team_id in enumerate(sorted(ASSIGNMENTS.keys())):
        ASSIGNMENTS[team_id].append(cat_challenges[idx])


def _random_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    alphabet = alphabet.translate(str.maketrans("", "", "Il1O0"))
    return "".join(secrets.choice(alphabet) for _ in range(length))


async def seed(reset: bool) -> None:
    await init_db()

    async with SessionLocal() as db:
        if reset:
            await db.execute(delete(ChallengeInstance))
            await db.execute(delete(TeamChallengeAssignment))
            await db.execute(delete(Solve))
            await db.execute(delete(Challenge))
            await db.execute(delete(Team))
            await db.commit()
            print("[reset] Tablas limpiadas.")

        # --- Retos ---
        existing_cids = {c for (c,) in (await db.execute(
            select(Challenge.challenge_id)
        )).all()}

        for order, (cid, cat, name, pts, desc, conn) in enumerate(CHALLENGES):
            if cid in existing_cids:
                continue
            db.add(Challenge(
                challenge_id=cid, category=cat, name=name, difficulty="insane",
                points=pts, description=desc, connection_info=conn,
                visible=True, sort_order=order,
            ))
        await db.commit()
        print(f"[seed] {len(CHALLENGES)} retos sembrados (catalog completo).")

        # --- Equipos ---
        existing_teams = {t for (t,) in (await db.execute(
            select(Team.team_id)
        )).all()}

        credentials: list[tuple[str, str]] = []
        for n in range(1, 6):
            tid = f"team_{n:02d}"
            if tid in existing_teams:
                continue
            pw = _random_password()
            credentials.append((tid, pw))
            team_names = {1: "Bytreach", 2: "MoodySploiters", 3: "DARKHIVE", 4: "Threat Hunters", 5: "Capa 8"}
            db.add(Team(team_id=tid, display_name=team_names[n],
                        password_hash=hash_password(pw)))
        await db.commit()

        # --- Asignaciones (idempotente) ---
        existing_asgn = {
            (row[0], row[1])
            for row in (await db.execute(
                select(TeamChallengeAssignment.team_id, TeamChallengeAssignment.challenge_id)
            )).all()
        }

        for tid, cids in ASSIGNMENTS.items():
            for cid in cids:
                if (tid, cid) not in existing_asgn:
                    db.add(TeamChallengeAssignment(team_id=tid, challenge_id=cid))
        await db.commit()
        print("[seed] Asignaciones de retos por equipo guardadas.")

    # --- Credenciales ---
    if credentials:
        print("\n=== CREDENCIALES (guardar en lugar seguro) ===")
        print(f"{'EQUIPO':<12} CONTRASENA")
        print("-" * 32)
        lines = []
        for tid, pw in credentials:
            print(f"{tid:<12} {pw}")
            lines.append(f"{tid}\t{pw}")
            # Imprime asignacion
            assigned = ASSIGNMENTS.get(tid, [])
            for cid in assigned:
                cat = next(c for _id, c, *_ in CHALLENGES if _id == cid)
                print(f"  [{cat}] {cid}")
        with open("credentials.txt", "w", encoding="utf-8") as fh:
            fh.write("team_id\tpassword\n")
            fh.write("\n".join(lines) + "\n")
        print("\nGuardado en credentials.txt")
    else:
        print("Equipos ya existian.")

    print("\n[seed] Completado.")
    print("Asignaciones finales:")
    for tid, cids in sorted(ASSIGNMENTS.items()):
        print(f"  {tid}: {', '.join(cids)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args()
    asyncio.run(seed(args.reset))
