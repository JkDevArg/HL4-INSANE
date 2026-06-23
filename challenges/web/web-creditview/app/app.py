"""CreditView API — web-creditview (Web INSANE) · "Deuda de Legado".

Vulnerabilidad central: INSECURE DESERIALIZATION via formato binario propietario.

El endpoint /api/report acepta un cuerpo binario con Content-Type:
application/x-creditview-filter. El formato "CRDV v2" tiene:

  Offset  Size  Desc
  0       4     Magic: 0x43 0x52 0x44 0x56 ("CRDV")
  4       1     Version: 0x02
  5       2     Payload length (big-endian uint16)
  7       4     CRC32 of payload (big-endian uint32)
  11      N     Payload (pickle data)

El servidor parsea el formato, verifica el CRC32 y deserializa el payload
como pickle. Tiene una lista negra rudimentaria que bloquea los strings
b'os', b'subprocess', b'builtins', b'__import__', b'eval', b'exec'.

Bypass: usar el módulo 'importlib' que NO está en la lista negra.
La clase ReportFilter tiene un campo report_type. Si el resultado de la
deserialización es una instancia de ReportFilter con report_type='CONFIDENTIAL',
el servidor retorna la flag.

El truco: la lista negra bloquea b'__reduce__' directamente en el pickle.
Pero se puede usar pickle opcodes manuales para construir el objeto sin
usar la reducción habitual, o usar el módulo copyreg para registrar
una función de reducción alternativa.

Solución real: construir manualmente los opcodes pickle para llamar a
la clase ReportFilter directamente usando el opcode GLOBAL + REDUCE,
sin que aparezca b'__reduce__' en el payload binario (eso es interno
al protocolo pickle, no aparece como string literal).

La lista negra es una comprobación superficial de strings de texto en el
payload binario:
  - Bloquea: b'os', b'subprocess', b'builtins', b'__import__', b'eval', b'exec'
  - NO bloquea: b'importlib', b'copyreg', b'__reduce__' (opcode interno)

Para bypasear: los jugadores deben:
1. Leer el código fuente expuesto en /static/docs/api-spec.txt (hint de la UI)
2. Entender que el payload es pickle
3. Crear un pickle que construya ReportFilter con report_type='CONFIDENTIAL'
   sin triggear la lista negra

La clase ReportFilter está definida en el servidor y también debe estar en
el módulo del pickle (módulo __main__ del servidor, no del cliente).
Por eso la forma correcta es usar pickle opcodes para llamar directamente
a __main__.ReportFilter o usar GLOBAL opcode con el módulo correcto.

La solución elegante: pickle protocol 2, opcode GLOBAL para referenciar
'__main__ ReportFilter' (donde __main__ es el módulo del servidor al
ejecutar app.py directamente), luego MARK, string 'CONFIDENTIAL', TUPLE1,
REDUCE. El módulo '__main__' y el nombre 'ReportFilter' NO están en el
blacklist, así que el payload pasa la comprobación superficial.

La flag se retorna como JSON si report_type == 'CONFIDENTIAL'.
"""
import binascii
import io
import os
import pickle
import struct

from flask import Flask, jsonify, request

from siem import emit
from reqlog import reqlog_http

app = Flask(__name__)

FLAG = os.environ.get("FLAG", "HL4{EJEMPLO_LOCAL}")

# ---------------------------------------------------------------------------
# Clase target de deserialización
# ---------------------------------------------------------------------------

class ReportFilter:
    """Filtro de reportes crediticios. Contiene los criterios de búsqueda."""

    def __init__(self, report_type: str = "STANDARD", filters: dict | None = None):
        self.report_type = report_type
        self.filters = filters or {}

    def __repr__(self) -> str:
        return f"ReportFilter(report_type={self.report_type!r}, filters={self.filters!r})"


# ---------------------------------------------------------------------------
# Parser del formato binario propietario CRDV v2
# ---------------------------------------------------------------------------

MAGIC = b"CRDV"
VERSION = 0x02

# Lista negra superficial: comprobación de strings en el payload pickle
_BLACKLIST = [b"os", b"subprocess", b"builtins", b"__import__", b"eval", b"exec"]

_MAX_PAYLOAD = 4096  # máximo tamaño del payload pickle


class CRDVError(Exception):
    pass


def _parse_crdv(raw: bytes) -> bytes:
    """Parsea el formato CRDV y devuelve el payload pickle si es válido."""
    if len(raw) < 11:
        raise CRDVError("Cabecera incompleta (mínimo 11 bytes)")

    magic = raw[:4]
    if magic != MAGIC:
        raise CRDVError(f"Magic incorrecto: {magic!r} (esperado: {MAGIC!r})")

    version = raw[4]
    if version != VERSION:
        raise CRDVError(f"Versión no soportada: {version} (soportada: {VERSION})")

    payload_len = struct.unpack(">H", raw[5:7])[0]
    crc32_expected = struct.unpack(">I", raw[7:11])[0]

    if len(raw) < 11 + payload_len:
        raise CRDVError(f"Payload truncado: esperados {payload_len} bytes, hay {len(raw) - 11}")

    payload = raw[11:11 + payload_len]

    if payload_len > _MAX_PAYLOAD:
        raise CRDVError(f"Payload demasiado grande: {payload_len} > {_MAX_PAYLOAD}")

    crc32_actual = binascii.crc32(payload) & 0xFFFFFFFF
    if crc32_actual != crc32_expected:
        raise CRDVError(
            f"CRC32 inválido: calculado {crc32_actual:#010x}, esperado {crc32_expected:#010x}"
        )

    return payload


def _check_blacklist(payload: bytes) -> None:
    """Comprobación superficial de strings prohibidos en el payload."""
    for term in _BLACKLIST:
        if term in payload:
            raise CRDVError(f"Payload bloqueado: contiene término prohibido {term!r}")


def _deserialize(payload: bytes) -> object:
    """Deserializa el payload pickle. Solo acepta instancias de ReportFilter."""
    _check_blacklist(payload)
    try:
        obj = pickle.loads(payload)  # noqa: S301 — vulnerabilidad intencional
    except Exception as exc:
        raise CRDVError(f"Error de deserialización pickle: {exc}") from exc

    return obj


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

INDEX_HTML = """<!doctype html>
<html lang="es">
<head><meta charset="utf-8">
<title>CreditView API</title>
<style>
body{font-family:monospace;background:#0d1117;color:#c9d1d9;max-width:900px;margin:2rem auto;padding:1rem}
h1{color:#58a6ff}h2{color:#3fb950}pre{background:#161b22;padding:1rem;overflow-x:auto}
a{color:#58a6ff}.warn{color:#f0883e}.info{color:#79c0ff}code{background:#161b22;padding:2px 4px}
</style>
</head>
<body>
<h1>CreditView API v2.1</h1>
<p>Portal de acceso a reportes crediticios. Autenticados vía filtros CRDV.</p>

<h2>Endpoint principal</h2>
<pre>POST /api/report
Content-Type: application/x-creditview-filter
Body: &lt;CRDV binary filter&gt;</pre>

<h2>Formato CRDV v2 (propietario)</h2>
<p>Documentación técnica: <a href="/static/docs/api-spec.txt">/static/docs/api-spec.txt</a></p>

<h2>Tipos de reporte disponibles</h2>
<ul>
  <li><code>STANDARD</code> — Reporte estándar (datos públicos)</li>
  <li><code>PREMIUM</code> — Reporte premium (historial completo)</li>
  <li><span class="warn"><code>CONFIDENTIAL</code> — Datos restringidos (solo auditores internos)</span></li>
</ul>

<h2>Ejemplo (STANDARD)</h2>
<pre class="info">python3 -c "
import pickle, struct, binascii, io

class ReportFilter:
    def __init__(self, report_type='STANDARD', filters=None):
        self.report_type = report_type
        self.filters = filters or {}

rf = ReportFilter('STANDARD')
payload = pickle.dumps(rf, protocol=2)

magic = b'CRDV'
version = b'\\x02'
plen = struct.pack('>H', len(payload))
crc = struct.pack('>I', binascii.crc32(payload) & 0xFFFFFFFF)
packet = magic + version + plen + crc + payload
open('/tmp/filter.bin', 'wb').write(packet)
print(f'Escrito {len(packet)} bytes')
"

curl -X POST http://localhost:8080/api/report \\
     -H 'Content-Type: application/x-creditview-filter' \\
     --data-binary @/tmp/filter.bin
</pre>

<p class="warn">&#9888; El sistema audita todos los accesos a reportes CONFIDENTIAL.</p>
<p><a href="/health">Estado del servicio</a></p>
</body>
</html>"""

API_SPEC = """CreditView Filter Format — CRDV v2
====================================
Especificación técnica del formato de filtros del protocolo CreditView.

ESTRUCTURA DEL PAQUETE
----------------------
Offset  Size  Tipo          Descripción
------  ----  ----          -----------
0       4     bytes         Magic: 0x43 0x52 0x44 0x56 (ASCII: "CRDV")
4       1     uint8         Version: 0x02
5       2     uint16 (BE)   Payload length (N bytes)
7       4     uint32 (BE)   CRC32 del payload (binascii.crc32)
11      N     bytes         Payload (formato interno: serialización de ReportFilter)

SERIALIZACIÓN INTERNA
---------------------
El payload es un objeto ReportFilter serializado. El motor interno utiliza
pickle protocol 2 para máxima compatibilidad con clientes legacy.

La clase ReportFilter (módulo __main__) tiene los campos:
  - report_type: str  (STANDARD | PREMIUM | CONFIDENTIAL)
  - filters: dict     (criterios de búsqueda opcionales)

VALIDACIONES DEL SERVIDOR
--------------------------
1. Magic check: los primeros 4 bytes deben ser "CRDV"
2. Version check: byte 4 debe ser 0x02
3. Length check: el payload_len indicado debe coincidir con los bytes disponibles
4. CRC32 check: CRC32(payload) debe coincidir con los bytes 7-10
5. Blacklist check: el payload no debe contener términos prohibidos
6. Type check: el objeto deserializado debe ser una instancia de ReportFilter

NOTAS DE IMPLEMENTACIÓN
-----------------------
- El CRC32 se calcula con binascii.crc32(payload) & 0xFFFFFFFF
- Big-endian para todos los enteros multi-byte
- Máximo payload: 4096 bytes
- La lista negra verifica la presencia de bytes literales en el payload pickle

SEGURIDAD
---------
El deserializador implementa una lista negra de módulos peligrosos.
Los filtros CONFIDENTIAL solo están disponibles para auditores internos.
"""


@app.get("/")
def index():
    return INDEX_HTML, 200, {"Content-Type": "text/html; charset=utf-8"}


@app.get("/health")
def health():
    return jsonify({"status": "ok", "version": "2.1", "protocol": "CRDV/2"})


@app.get("/static/docs/api-spec.txt")
def api_spec():
    return API_SPEC, 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.post("/api/report")
def api_report():
    src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if src_ip and "," in src_ip:
        src_ip = src_ip.split(",")[0].strip()

    ct = request.content_type or ""
    if "application/x-creditview-filter" not in ct:
        emit("invalid_content_type", "warn", src_ip=src_ip,
             detail={"content_type": ct, "path": "/api/report"})
        return jsonify({
            "error": "Content-Type incorrecto",
            "expected": "application/x-creditview-filter",
            "received": ct,
        }), 415

    raw = request.get_data()
    if not raw:
        return jsonify({"error": "Body vacío"}), 400

    # Parsear el formato CRDV
    try:
        payload = _parse_crdv(raw)
    except CRDVError as e:
        emit("crdv_parse_error", "info", src_ip=src_ip,
             detail={"error": str(e), "raw_len": len(raw)})
        return jsonify({"error": f"Formato CRDV inválido: {e}"}), 400

    # Deserializar
    try:
        obj = _deserialize(payload)
    except CRDVError as e:
        emit("deserialize_error", "warn", src_ip=src_ip,
             detail={"error": str(e)})
        return jsonify({"error": f"Error de deserialización: {e}"}), 400

    # Validar tipo
    if not isinstance(obj, ReportFilter):
        emit("invalid_filter_type", "warn", src_ip=src_ip,
             detail={"received_type": type(obj).__name__})
        return jsonify({
            "error": "El objeto deserializado no es un ReportFilter válido",
            "received_type": type(obj).__name__,
        }), 400

    report_type = getattr(obj, "report_type", "UNKNOWN")
    filters = getattr(obj, "filters", {})

    # Acceso a datos CONFIDENTIAL → retorna la flag
    if report_type == "CONFIDENTIAL":
        emit("challenge_solved", "alert", src_ip=src_ip,
             detail={"vuln": "insecure-deserialization-crdv", "report_type": report_type})
        return jsonify({
            "status": "ok",
            "report_type": report_type,
            "access": "GRANTED",
            "data": {
                "classification": "TOP SECRET",
                "note": "Acceso a datos confidenciales concedido",
                "flag": FLAG,
            },
        })

    if report_type == "PREMIUM":
        return jsonify({
            "status": "ok",
            "report_type": report_type,
            "access": "GRANTED",
            "data": {
                "credit_score": 742,
                "history_months": 84,
                "filters_applied": filters,
                "hint": "Existen tipos de reporte más restringidos...",
            },
        })

    # STANDARD
    return jsonify({
        "status": "ok",
        "report_type": report_type,
        "access": "GRANTED",
        "data": {
            "credit_score": 650,
            "history_months": 12,
            "filters_applied": filters,
        },
    })


@app.before_request
def _log_request():
    try:
        src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        if src_ip and "," in src_ip:
            src_ip = src_ip.split(",")[0].strip()
        body_raw = request.get_data(cache=True)
        body_repr = repr(body_raw[:64]) if body_raw else ""
        reqlog_http(
            src_ip=src_ip,
            method=request.method,
            path=request.path,
            query=request.query_string.decode("utf-8", "replace"),
            headers=dict(request.headers),
            body=body_repr,
        )
    except Exception:
        pass


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True)
