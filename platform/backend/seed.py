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
        "CreditView — Deserialización Pickle Formato Propietario",
        700,
        (
            "Portal de historial crediticio. El endpoint de reportes acepta un "
            "formato binario propietario CRDV v2 (magic + version + len + CRC32 + payload). "
            "El payload es un objeto pickle serializado, con blacklist que bloquea "
            "os, subprocess, builtins, __import__. "
            "Construye un exploit con opcodes GLOBAL apuntando a clases internas. "
            "⚠ La especificación del formato está expuesta en /static/docs/api-spec.txt."
        ),
        "http://172.30.{N}.10:8080",
    ),
    (
        "web-reportgen",
        "web",
        "ReportGen — SSTI Jinja2 con WAF Bypass",
        650,
        (
            "Generador de reportes en Flask/Jinja2. El WAF bloquea strings como "
            "__class__, __globals__, popen, read vía regex sobre el template raw. "
            "Jinja2 procesa secuencias de escape \\xNN antes de que el WAF las evalúe. "
            "Usa hex escapes para construir los atributos bloqueados y ejecutar código. "
            "⚠ Los bypasses documentados con filtros Jinja2 están bloqueados aquí."
        ),
        "http://172.30.{N}.10:8080",
    ),
    (
        "web-docmanager",
        "web",
        "DocManager — XXE en Endpoint SOAP Oculto",
        700,
        (
            "Sistema de gestión documental con endpoint SOAP que procesa XML. "
            "El endpoint real no está en la ruta obvia — hay misdirection. "
            "Requiere firma HMAC-SHA256 en header X-Api-Signature (clave en el SDK). "
            "lxml está configurado con resolución de entidades externas habilitada. "
            "Usa XXE para leer /flag.txt — el valor se refleja en la respuesta. "
            "⚠ El WSDL en /static/wsdl/ revela la ruta del endpoint real."
        ),
        "http://172.30.{N}.10:8080",
    ),
    (
        "web-coinswap",
        "web",
        "CoinSwap — TOCTOU Race Condition en Swap",
        600,
        (
            "Exchange de criptomonedas en Flask. El endpoint /swap hace: "
            "lee snapshot de COIN_A → sleep(80ms) → descuenta snapshot pero acredita "
            "COIN_B sobre el estado actual. Con peticiones concurrentes en la ventana, "
            "COIN_B se acredita N veces mientras COIN_A baja solo 1×. "
            "Llega a 10,000 de cualquier moneda para abrir el vault y obtener la flag. "
            "⚠ El servidor detecta y banea patrones de fuerza bruta naive."
        ),
        "http://172.30.{N}.10:8080",
    ),
    (
        "web-taskflow",
        "web",
        "TaskFlow — Deserialización Pickle en Backup .tar.gz",
        750,
        (
            "Gestor de proyectos en Flask. El endpoint /upload acepta archivos .tar.gz. "
            "Si el archivo contiene __metadata__.pkl, el servidor lo deserializa. "
            "El código fuente expuesto en /source revela la clave ofuscada (hex XOR). "
            "La blacklist bloquea os, subprocess, builtins — construye un payload "
            "con GLOBAL apuntando a clases internas del proyecto. "
            "⚠ La clave de verificación del backup está ofuscada pero recuperable."
        ),
        "http://172.30.{N}.10:8080",
    ),

    # ── API (5 retos) ─────────────────────────────────────────────────────────
    (
        "api-datahub",
        "api",
        "DataHub — GraphQL SQLi via Directiva Interna",
        700,
        (
            "API de analítica con GraphQL. La introspección está 'desactivada' "
            "pero el schema es enumerable. El tipo Dataset expone un argumento "
            "'predicate' para filtrar por owner — se interpola directamente en SQL. "
            "Los errores SQL están suprimidos: respuesta vacía, sin mensaje. "
            "Exfiltra la flag de la tabla interna con UNION-based blind SQLi. "
            "⚠ El argumento vulnerable no se llama 'where' ni 'filter'."
        ),
        "http://172.30.{N}.20:5001",
    ),
    (
        "api-cloudconnect",
        "api",
        "CloudConnect — JWT Algorithm Confusion RS256→HS256",
        650,
        (
            "Servicio de autenticación JWT con RS256. Hay un endpoint que expone "
            "la clave pública del servidor. Descárgala, conviértela a PEM y úsala "
            "como secreto HMAC-SHA256 para forjar un token firmado con HS256. "
            "El servidor acepta ambos algoritmos sin validación explícita del 'alg'. "
            "⚠ El endpoint de clave pública no está en la documentación principal."
        ),
        "http://172.30.{N}.20:5002",
    ),
    (
        "api-metricstream",
        "api",
        "MetricStream — Header Injection Auth Bypass",
        700,
        (
            "API de métricas con autenticación por token. Hay un endpoint interno "
            "de especificaciones accesible solo desde 'localhost'. "
            "Inyecta 'X-Forwarded-For: 127.0.0.1' y 'X-Debug: 1' para forzar "
            "que el servidor te trate como tráfico interno, luego usa el header "
            "'X-Internal-Service: true' para saltarte la autenticación del admin. "
            "⚠ Los tres headers son necesarios — uno solo no es suficiente."
        ),
        "http://172.30.{N}.20:5003",
    ),
    (
        "api-securevault",
        "api",
        "SecureVault — JWT kid Path Traversal",
        650,
        (
            "Gestor de secretos con JWT firmado por HMAC. El claim 'kid' del header "
            "indica qué archivo de clave usar — se concatena directamente a la ruta "
            "base sin sanitizar. Usa path traversal para apuntar a /dev/null "
            "(secreto vacío) y forja un token de administrador con kid='../../dev/null'. "
            "⚠ El servidor bloquea '../' explícito — necesitas encoding alternativo."
        ),
        "http://172.30.{N}.20:5004",
    ),
    (
        "api-hrmpro",
        "api",
        "HRM-Pro — Mass Assignment Whitelist Bypass",
        600,
        (
            "Sistema de RRHH con endpoint PUT /api/v1/profile que filtra campos "
            "en whitelist. La whitelist solo valida strings — si envías un campo "
            "como dict con clave 'override', la validación lo ignora pero el ORM "
            "lo deserializa y lo aplica. Eleva tu rol a 'hr_admin' y accede al "
            "endpoint de nóminas protegido. "
            "⚠ El campo de rol tiene un nombre en camelCase no documentado."
        ),
        "http://172.30.{N}.20:5005",
    ),

    # ── CRYPTO (5 retos) ──────────────────────────────────────────────────────
    (
        "crypto-rsalsb",
        "crypto",
        "RSA-LSB Oracle — Paridad Binaria",
        700,
        (
            "Servicio TCP que expone un oráculo RSA-2048. Envía cualquier "
            "cifrado y responde '0' o '1' (bit menos significativo del descifrado). "
            "Usa binary search con multiplicación modular para descifrar la flag. "
            "⚠ El oráculo aplica un factor multiplicativo aleatorio por sesión — "
            "debes recuperarlo primero."
        ),
        "nc 172.30.{N}.30 9999",
    ),
    (
        "crypto-paddingoracle",
        "crypto",
        "Padding Oracle — AES-CBC con Ruido",
        650,
        (
            "Servicio TCP con AES-CBC y PKCS#7 modificado (relleno 0x00). "
            "5% de falsos negativos aleatorios — si el oráculo dice 'invalido' "
            "tres veces seguidas, confía en él. Descifra el ciphertext dado "
            "y extrae la flag incrustada. "
            "⚠ El bloque IV está concatenado al final, no al inicio."
        ),
        "nc 172.30.{N}.30 9999",
    ),
    (
        "crypto-ecdsanonce",
        "crypto",
        "ECDSA Nonce Reuse — Recuperación de Clave",
        750,
        (
            "API HTTP con ECDSA NIST P-256. Solicita N firmas de mensajes a tu elección. "
            "El PRNG está sembrado con timestamp % 997 — hay colisión de nonce "
            "tras ~30 firmas (birthday). Detecta el par con mismo nonce, "
            "recupera la clave privada y firma el mensaje de desafío para obtener la flag. "
            "⚠ La implementación ECDSA tiene una diferencia sutil vs openssl — léela."
        ),
        "http://172.30.{N}.30:9999",
    ),
    (
        "crypto-lengthext",
        "crypto",
        "Length Extension — MD5(secret||msg)",
        600,
        (
            "Servicio HTTP de autenticación: token = MD5(secret + ':' + user + ':role=user'). "
            "La longitud del secreto está filtrada en un endpoint de diagnóstico. "
            "Aplica length extension para forjar 'role=admin' y accede al panel. "
            "⚠ El relleno usa tamaño de bloque no estándar (56 bytes, no 64)."
        ),
        "http://172.30.{N}.30:9999",
    ),
    (
        "crypto-hastad",
        "crypto",
        "Håstad Broadcast — RSA e=3 × 5 receptores",
        700,
        (
            "La flag fue cifrada con RSA e=3 para 5 receptores distintos "
            "(N distintos, mismo e). Los 5 cifrados están disponibles. "
            "Aplica CRT + raíz cúbica exacta para recuperar el mensaje. "
            "⚠ Los cifrados están en base58 con checksum — valida antes de operar."
        ),
        "http://172.30.{N}.30:9999",
    ),

    # ── REVERSING (5 retos) ───────────────────────────────────────────────────
    (
        "rev-customvm",
        "reversing",
        "CustomVM — Reverse the Bytecode",
        700,
        (
            "ELF x86-64 que implementa una VM de pila con 12 opcodes propios. "
            "El bytecode del programa está embebido. Primero reversa el set de "
            "instrucciones de la VM, luego descompila el bytecode para encontrar "
            "la contraseña correcta. Envíala al servicio para obtener la flag. "
            "⚠ Dos opcodes tienen comportamiento condicional que depende del estado — "
            "no son obvios en el disassembler."
        ),
        "http://172.30.{N}.40:6001  (GET /binary, POST /submit)",
    ),
    (
        "rev-gobinary",
        "reversing",
        "GoBinary — Stripped + Anti-Debug",
        650,
        (
            "Binario Go 1.21 stripped (sin símbolos). Implementa FNV-1a modificado "
            "con una constante diferente a la estándar. El binario detecta ptrace "
            "y termina. Identifica el algoritmo de hash, encuentra el input que "
            "produce el hash objetivo y envíalo al servicio. "
            "⚠ La constante FNV está ofuscada con XOR en tiempo de inicialización."
        ),
        "http://172.30.{N}.40:6002  (GET /binary, POST /submit)",
    ),
    (
        "rev-wasmcrack",
        "reversing",
        "WASMCrack — License Key WebAssembly",
        700,
        (
            "Binario Rust (stripped, opt3) con algoritmo de hash custom. "
            "Valida una clave de 12 caracteres con transformaciones por byte. "
            "Descarga el binario, analízalo (Ghidra/radare2) y reconstruye "
            "el algoritmo de validación para encontrar la clave correcta. "
            "⚠ El nombre 'WASM' es un señuelo — es un ELF real."
        ),
        "http://172.30.{N}.40:6003  (GET /binary, POST /submit)",
    ),
    (
        "rev-packeddelta",
        "reversing",
        "PackedDelta — XOR Packed ELF",
        750,
        (
            "ELF cuya contraseña objetivo está XOR-encriptada en .rodata. "
            "Clave: 4 bytes rotando. Un mecanismo de anti-tamper falso sirve "
            "de distracción. Localiza el array cifrado y la clave en el binario, "
            "aplica XOR para recuperar la contraseña correcta. "
            "⚠ El anti-tamper parece modificar la clave pero es idempotente."
        ),
        "http://172.30.{N}.40:6004  (GET /binary, POST /submit)",
    ),
    (
        "rev-dotnetobf",
        "reversing",
        "DotNET Obfuscated — Python Bytecode",
        700,
        (
            "Archivo .pyc (Python 3.11 compilado) con nombres ofuscados. "
            "La clave está almacenada como tupla de enteros ASCII en co_consts. "
            "Decompila con uncompyle6/pycdc o analiza co_consts con dis/marshal "
            "para reconstruir la clave y enviarla al servicio. "
            "⚠ El comando 'strings' solo muestra basura — es bytecode compilado."
        ),
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
            db.add(Team(team_id=tid, display_name=f"Equipo {n:02d}",
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
