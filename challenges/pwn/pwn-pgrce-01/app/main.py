"""MoneyPipe API — pwn-pgrce-01 (PWN INSANE · "MoneyPipe").

VULN central: SQL INJECTION en un endpoint de reportes financieros que se
ESCALA a RCE EN EL SERVIDOR DE BASE DE DATOS via `COPY ... TO/FROM PROGRAM`
de PostgreSQL. Tecnica real de pos-explotacion: cuando la app conecta a
Postgres como SUPERUSER (mala configuracion habitual en pipelines ETL de
fintech), una SQLi deja de ser solo lectura de datos y se convierte en
ejecucion de comandos del SO en el contenedor de la base de datos.

Topologia:
  jugador --> api (FastAPI, .40:8080) --> db (postgres:16, superuser) [.140]

La FLAG NO esta en la base de datos ni en la API: vive como ARCHIVO
(`/flag.txt`) dentro del contenedor de POSTGRES. Solo se alcanza ejecutando
un comando del SO en ese contenedor. Esto obliga a la cadena completa.

Cadena de explotacion (INSANE):

  1) SQL INJECTION en GET /api/v1/reports?filter=...
     El parametro `filter` se CONCATENA crudo dentro de la clausula WHERE de
     la query de reportes. No hay parametrizacion. Permite UNION-based y
     ejecucion de sentencias apiladas (psycopg2 .execute permite multi-stmt
     cuando no devuelve filas; lo usamos para los COPY).

  2) ESCALADA A RCE via COPY ... FROM PROGRAM (Postgres superuser):
     - El usuario de la DB de la app es SUPERUSER (como en despliegues ETL
       reales mal configurados). COPY ... TO/FROM PROGRAM solo lo permite un
       superuser o miembro de pg_execute_server_program.
     - El atacante crea una tabla puente y ejecuta:
         COPY exfil(line) FROM PROGRAM 'cat /flag.txt';
       Esto ejecuta `cat /flag.txt` como el usuario `postgres` del SO DENTRO
       del contenedor db, y vuelca su salida en la tabla `exfil`.

  3) RECUPERAR LA SALIDA via UNION-based SQLi:
     - El atacante vuelve a /api/v1/reports con un filtro UNION que lee la
       tabla `exfil` -> la flag aparece en la respuesta JSON del reporte.

La FLAG se inyecta por equipo via env FLAG y el entrypoint del contenedor db
la escribe en /flag.txt. NO hardcodeada.
"""
import os

import psycopg2
import psycopg2.extras
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from siem import emit
from reqlog import reqlog_http

app = FastAPI(title="MoneyPipe API", docs_url=None, redoc_url=None, openapi_url=None)

FLAG = os.environ.get("FLAG", "flag{EJEMPLO_LOCAL}")

DB_HOST = os.environ.get("DB_HOST", "db")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))
DB_NAME = os.environ.get("DB_NAME", "moneypipe")
# OJO: el usuario de la app es SUPERUSER (mala practica real). Eso es lo que
# convierte la SQLi en RCE via COPY ... TO/FROM PROGRAM.
DB_USER = os.environ.get("DB_USER", "moneypipe_etl")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "etl_pipe_2024")


def _connect():
    """Conexion nueva por peticion. autocommit=True para que las sentencias
    apiladas (incluido COPY ... FROM PROGRAM) surtan efecto inmediato y para
    no dejar transacciones abortadas tras una SQLi."""
    conn = psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
        user=DB_USER, password=DB_PASSWORD, connect_timeout=4,
    )
    conn.autocommit = True
    return conn


# --------------------------------------------------------------------------
# Middleware ASGI PURO: loguea CADA peticion COMPLETA para el SIEM del stream
# (linea CTFREQ via reqlog). Implementado como middleware ASGI puro (NO
# @app.middleware("http")) para no romper el listener de desconexion de
# Starlette. Copiado del patron corregido de api-cache-05.
# --------------------------------------------------------------------------
class ReqLogMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Buffer del body completo (los handlers lo vuelven a leer reinyectado).
        chunks: list[bytes] = []
        more = True
        while more:
            message = await receive()
            if message["type"] == "http.request":
                chunks.append(message.get("body", b"") or b"")
                more = message.get("more_body", False)
            elif message["type"] == "http.disconnect":
                more = False
        raw = b"".join(chunks)

        try:
            headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in scope.get("headers", [])}
            src_ip = headers.get("x-forwarded-for")
            if src_ip and "," in src_ip:
                src_ip = src_ip.split(",")[0].strip()
            if not src_ip:
                client = scope.get("client")
                src_ip = client[0] if client else "?"
            query = (scope.get("query_string") or b"").decode("latin-1")
            reqlog_http(
                src_ip=src_ip,
                method=scope.get("method", "?"),
                path=scope.get("path", "/"),
                query=query,
                headers=headers,
                body=raw,
            )
        except Exception:
            pass

        # Reinyecta el body bufferizado para los handlers aguas abajo.
        _sent = False

        async def _receive():
            nonlocal _sent
            if not _sent:
                _sent = True
                return {"type": "http.request", "body": raw, "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, _receive, send)


app.add_middleware(ReqLogMiddleware)


# --------------------------------------------------------------------------
# Endpoints publicos / portada
# --------------------------------------------------------------------------
@app.get("/health")
def health():
    try:
        conn = _connect()
        conn.close()
        return {"status": "ok", "db": "up"}
    except Exception:
        return JSONResponse({"status": "degraded", "db": "down"}, status_code=503)


@app.get("/")
def root():
    return {
        "app": "MoneyPipe",
        "desc": "Pipeline de reportes financieros (ETL fintech)",
        "endpoints": [
            "GET /api/v1/transactions          -> ultimas transacciones (demo)",
            "GET /api/v1/reports?filter=...     -> reporte filtrado por estado/region/moneda",
        ],
        "hint": "El filtro de reportes alimenta directamente el motor de consultas del data warehouse.",
    }


@app.get("/api/v1/transactions")
def transactions():
    """Listado de demo (consulta parametrizada, NO vulnerable). Sirve para que
    el jugador conozca el esquema `transactions` antes de atacar /reports."""
    try:
        conn = _connect()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT id, account, region, currency, amount, status "
                "FROM transactions ORDER BY id LIMIT 10"
            )
            rows = cur.fetchall()
        conn.close()
        return {"transactions": rows}
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"db error: {exc}")


# --------------------------------------------------------------------------
# VULN — SQL INJECTION
#
# El parametro `filter` se CONCATENA crudo en la clausula WHERE. Sin
# parametrizacion. Permite UNION-based y, como la conexion es de un SUPERUSER,
# escalar a RCE con COPY ... TO/FROM PROGRAM (sentencias apiladas separadas
# por ';' que psycopg2 ejecuta en un mismo .execute()).
# --------------------------------------------------------------------------
@app.get("/api/v1/reports")
def reports(request: Request, filter: str = Query(default="1=1")):
    src_ip = request.client.host if request.client else None

    # Senal de SQLi/COPY para el SIEM (heuristica simple sobre el filtro).
    lowered = filter.lower()
    if any(tok in lowered for tok in ("union", "copy", "program", "--", ";", "select")):
        emit(
            "scan_detected", "alert",
            src_ip=src_ip,
            detail={"vuln": "sqli-reports", "filter": filter[:200]},
        )

    # VULN: concatenacion directa del filtro del usuario en el WHERE.
    query = (
        "SELECT id, account, region, currency, amount, status "
        "FROM transactions WHERE " + filter
    )

    try:
        conn = _connect()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(query)
            # COPY ... FROM PROGRAM no devuelve filas: protegerse de fetch.
            if cur.description is not None:
                rows = cur.fetchall()
            else:
                rows = []
        conn.close()
        return {"filter": filter, "rows": rows}
    except Exception as exc:  # noqa: BLE001
        # El error de SQL se devuelve al jugador (SQLi basada en errores util
        # para el recon del esquema). Realista en backends ETL verbosos.
        raise HTTPException(status_code=500, detail=f"query error: {exc}")
