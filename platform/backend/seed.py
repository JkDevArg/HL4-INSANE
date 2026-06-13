"""Script de siembra de la base de datos.

Crea los 10 equipos (team_01..team_10) con contrasenas aleatorias e imprime
las credenciales, y siembra ~15 retos de ejemplo (web/api/crypto, insane).

Uso:
    python seed.py                # contrasenas aleatorias
    python seed.py --reset        # borra solves/teams/challenges y resiembra

Las credenciales se imprimen en stdout y se guardan en `credentials.txt`.
"""
import argparse
import asyncio
import secrets
import string

from sqlalchemy import delete, select

from app.auth import hash_password
from app.config import get_settings
from app.db import SessionLocal, init_db
from app.models import Challenge, Solve, Team

settings = get_settings()


# ----------------------------------------------------------------------------
# Catalogo de retos de ejemplo (placeholders). Ids segun convencion seccion 7.
# ----------------------------------------------------------------------------
# connection_info usa la plantilla {N} (numero de equipo) que el router renderiza
# por equipo. IP interna del esquema 172.30.N.<octeto> (ver infra/launch-team-challenges.sh
# y los docker-compose.yml de cada reto). Solo alcanzable desde la VPN del equipo.
CHALLENGES = [
    # --- WEB ---  (octetos .10-.15)
    ("web-supply-01", "web", "Poisoned Pipeline", 500,
     "Una cadena de CI/CD confia demasiado en un paquete interno. Encadena la "
     "contaminacion del pipeline hasta RCE.",
     "http://172.30.{N}.10:8080  ·  registry para publicar: http://172.30.{N}.11:8080"),
    ("web-ssrf-02", "web", "Metadata Mirage", 500,
     "Un proxy de imagenes mal filtrado expone el plano de control interno. "
     "SSRF ciego hacia el metadata endpoint.", "http://172.30.{N}.12:8080"),
    ("web-proto-03", "web", "Prototype of Doom", 550,
     "Prototype pollution en una API de templates que escala a ejecucion en SSR.",
     "http://172.30.{N}.16:8080"),  # .13 reservado al servicio metadata de web-ssrf-02
    ("web-jwt-04", "web", "Forged Crown", 450,
     "Confusion de algoritmos JWT (RS256/HS256) combinada con JWK injection.",
     "http://172.30.{N}.14:8080"),
    ("web-race-05", "web", "Double Spend", 600,
     "Condicion de carrera en el flujo de canje de cupones. TOCTOU al limite.",
     "http://172.30.{N}.15:8080"),

    # --- API ---  (octetos .20-.24)
    ("api-bola-01", "api", "Tenant Trespass", 500,
     "BOLA/IDOR multi-tenant: rompe el aislamiento entre organizaciones de la API.",
     "http://172.30.{N}.20:8080"),
    ("api-bola-02", "api", "Mass Assignment Heist", 500,
     "Mass assignment sobre un recurso de facturacion que escala privilegios.",
     "http://172.30.{N}.21:8080"),
    ("api-graphql-03", "api", "Introspection Abyss", 550,
     "GraphQL con introspeccion 'desactivada'. Encadena alias batching y "
     "field suggestions para filtrar datos.", "http://172.30.{N}.22:8080"),
    ("api-grpc-04", "api", "Silent Channel", 600,
     "Reflexion gRPC parcialmente expuesta. Reconstruye el .proto y abusa de un "
     "metodo administrativo.", "grpc://172.30.{N}.23:8080"),
    ("api-cache-05", "api", "Poisoned Edge", 550,
     "Web cache deception sobre una API REST detras de un CDN simulado.",
     "http://172.30.{N}.24:8080"),

    # --- CRYPTO ---  (octetos .30-.34, puerto TCP 9999)
    ("crypto-oracle-01", "crypto", "Padding Whisperer", 550,
     "Padding oracle sobre CBC con un detalle no estandar en el relleno. "
     "Servido por red.", "nc 172.30.{N}.30 9999"),
    ("crypto-lattice-02", "crypto", "Lattice Mirage", 700,
     "Firma ECDSA con nonces sesgados. Recupera la clave via reduccion de "
     "reticulos (LLL/HNP).", "nc 172.30.{N}.31 9999"),
    ("crypto-rsa-03", "crypto", "Shared Modulus", 600,
     "Multiples cifrados RSA comparten parametros de forma sutil. Factoriza "
     "sin fuerza bruta.", "nc 172.30.{N}.32 9999"),
    ("crypto-aesgcm-04", "crypto", "Nonce Reuse Roulette", 650,
     "Reuso de nonce en AES-GCM permite forjar tags. Recupera la clave de "
     "autenticacion.", "nc 172.30.{N}.33 9999"),
    ("crypto-prng-05", "crypto", "Predictable Fortune", 600,
     "Un PRNG 'seguro' filtra estado a traves de un token. Predice la salida "
     "y firma el reto.", "nc 172.30.{N}.34 9999"),
]


def _random_password(length: int = 16) -> str:
    """Contrasena legible (sin caracteres ambiguos) para reparto manual."""
    alphabet = string.ascii_letters + string.digits
    alphabet = alphabet.translate(str.maketrans("", "", "Il1O0"))
    return "".join(secrets.choice(alphabet) for _ in range(length))


async def seed(reset: bool) -> None:
    await init_db()

    async with SessionLocal() as db:
        if reset:
            # Orden por FKs: solves -> challenges/teams.
            await db.execute(delete(Solve))
            await db.execute(delete(Challenge))
            await db.execute(delete(Team))
            await db.commit()

        # --- Retos ---
        existing = {c for (c,) in (await db.execute(select(Challenge.challenge_id))).all()}
        for order, (cid, cat, name, pts, desc, conn) in enumerate(CHALLENGES):
            if cid in existing:
                continue
            db.add(
                Challenge(
                    challenge_id=cid,
                    category=cat,
                    name=name,
                    difficulty="insane",
                    points=pts,
                    description=desc,
                    connection_info=conn,
                    visible=True,
                    sort_order=order,
                )
            )

        # --- Equipos + credenciales ---
        credentials: list[tuple[str, str]] = []
        existing_teams = {t for (t,) in (await db.execute(select(Team.team_id))).all()}
        for n in range(1, settings.team_count + 1):
            team_id = f"team_{n:02d}"
            if team_id in existing_teams:
                continue
            password = _random_password()
            credentials.append((team_id, password))
            db.add(
                Team(
                    team_id=team_id,
                    display_name=f"Equipo {n:02d}",
                    password_hash=hash_password(password),
                )
            )

        await db.commit()

    # --- Reporte de credenciales ---
    if credentials:
        print("\n=== CREDENCIALES DE EQUIPOS (guardar en lugar seguro) ===")
        print(f"{'TEAM':<12} CONTRASENA")
        print("-" * 32)
        lines = []
        for team_id, password in credentials:
            print(f"{team_id:<12} {password}")
            lines.append(f"{team_id}\t{password}")
        with open("credentials.txt", "w", encoding="utf-8") as fh:
            fh.write("team_id\tpassword\n")
            fh.write("\n".join(lines) + "\n")
        print("\nGuardado en credentials.txt")
    else:
        print("Equipos ya existian; no se generaron credenciales nuevas.")

    print(f"\nRetos sembrados: {len(CHALLENGES)} (catalogo). Seed completo.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Siembra equipos y retos del CTF.")
    parser.add_argument("--reset", action="store_true", help="Borra y resiembra todo.")
    args = parser.parse_args()
    asyncio.run(seed(args.reset))
