"""TaskFlow — web-taskflow (Web INSANE) · "Deserialización en Backup".

Vulnerabilidad: Deserialización insegura de pickle en un archivo __metadata__.pkl
dentro de un backup .tar.gz importado por el usuario.

Flujo de importación (/upload):
  1. Recibe el .tar.gz vía multipart/form-data
  2. Extrae a un directorio temporal
  3. Busca __metadata__.pkl dentro del archivo
  4. Comprueba lista negra (b'os', b'subprocess', b'builtins')
  5. Deserializa el pickle
  6. Si el resultado es TaskMetadata con import_key == SERVER_IMPORT_KEY → flag

La clave SERVER_IMPORT_KEY está ofuscada en el código fuente (XOR con 0x5A).
El código fuente está expuesto en /source (para que los jugadores puedan leerlo).

Bypass de la lista negra:
- b'os', b'subprocess', b'builtins' están bloqueados
- b'importlib', b'__main__', b'TaskMetadata', b'copyreg' NO están bloqueados
- Se puede usar pickle opcode GLOBAL con '__main__\nTaskMetadata'
  para crear la instancia, luego BUILD con el dict de estado
  (incluyendo import_key = SERVER_IMPORT_KEY derivada del código)
"""
import io
import os
import pickle
import struct
import tarfile

from flask import Flask, Response, jsonify, request

from siem import emit
from reqlog import reqlog_http

app = Flask(__name__)

FLAG = os.environ.get("FLAG", "HL4{EJEMPLO_LOCAL}")

# Escribir flag a disco
try:
    with open("/flag.txt", "w") as _fh:
        _fh.write(FLAG)
except OSError:
    pass

# ---------------------------------------------------------------------------
# Clave de importación ofuscada (XOR 0x5A). Los jugadores deben:
# 1. Leer /source para encontrar _KEY_OBFUSCATED y _XOR_CONST
# 2. Desofuscar: SERVER_IMPORT_KEY = bytes(b^0x5A for b in bytes.fromhex(hex_str)).decode()
# ---------------------------------------------------------------------------
_XOR_CONST = 0x5A
_KEY_OBFUSCATED = bytes.fromhex("0e1c77186e39312f2a7709693928692e")
SERVER_IMPORT_KEY: str = bytes(b ^ _XOR_CONST for b in _KEY_OBFUSCATED).decode()

# ---------------------------------------------------------------------------
# Clase target de deserialización
# ---------------------------------------------------------------------------

class TaskMetadata:
    """Metadatos de un backup de TaskFlow."""

    def __init__(self, project_name: str = "", version: str = "1.0",
                 import_key: str = "", task_count: int = 0):
        self.project_name = project_name
        self.version = version
        self.import_key = import_key
        self.task_count = task_count

    def __repr__(self) -> str:
        return (f"TaskMetadata(project={self.project_name!r}, "
                f"version={self.version!r}, tasks={self.task_count})")


# ---------------------------------------------------------------------------
# Lista negra del deserializador
# ---------------------------------------------------------------------------
_BLACKLIST = [b"os", b"subprocess", b"builtins", b"__import__", b"eval", b"exec", b"system"]

_MAX_PICKLE_SIZE = 8192  # 8 KB


def _check_blacklist(data: bytes) -> bytes | None:
    """Retorna el término bloqueado o None si el payload es aceptable."""
    for term in _BLACKLIST:
        if term in data:
            return term
    return None


def _safe_deserialize(pkl_data: bytes) -> object:
    """Deserializa el pickle tras comprobar la lista negra."""
    if len(pkl_data) > _MAX_PICKLE_SIZE:
        raise ValueError(f"Pickle demasiado grande: {len(pkl_data)} > {_MAX_PICKLE_SIZE}")

    blocked = _check_blacklist(pkl_data)
    if blocked is not None:
        raise ValueError(f"Payload bloqueado: contiene módulo prohibido {blocked!r}")

    return pickle.loads(pkl_data)  # noqa: S301 — vulnerabilidad intencional


def _extract_metadata(archive_bytes: bytes) -> tuple[object | None, str]:
    """Extrae y deserializa __metadata__.pkl del tar.gz.

    Retorna (objeto, error_str). Si error_str != '' hubo un error.
    """
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tf:
            names = tf.getnames()

            # Buscar __metadata__.pkl (puede estar en raíz o en subdirectorio)
            meta_name = None
            for n in names:
                if n.endswith("__metadata__.pkl"):
                    meta_name = n
                    break

            if meta_name is None:
                return None, f"No se encontró __metadata__.pkl en el archivo. Contenido: {names[:10]}"

            member = tf.getmember(meta_name)
            if member.size > _MAX_PICKLE_SIZE:
                return None, f"__metadata__.pkl demasiado grande: {member.size} bytes"

            f = tf.extractfile(member)
            if f is None:
                return None, "__metadata__.pkl no es un archivo regular"

            pkl_data = f.read()

    except tarfile.TarError as e:
        return None, f"Error al extraer tar.gz: {e}"

    try:
        obj = _safe_deserialize(pkl_data)
    except ValueError as e:
        return None, str(e)
    except Exception as e:
        return None, f"Error de deserialización: {e}"

    return obj, ""


def _build_sample_backup() -> bytes:
    """Construye un backup de ejemplo válido (sin exploit) para download."""
    meta = TaskMetadata(
        project_name="Mi Proyecto",
        version="1.0",
        import_key="sample-key",
        task_count=3,
    )
    pkl = pickle.dumps(meta, protocol=2)

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        # Añadir metadatos
        meta_bytes = pkl
        info = tarfile.TarInfo(name="mi-proyecto/__metadata__.pkl")
        info.size = len(meta_bytes)
        tf.addfile(info, io.BytesIO(meta_bytes))

        # Añadir archivo de tareas de ejemplo
        tasks_data = b"task1: Implementar feature\ntask2: Revisar PR\ntask3: Deploy\n"
        info2 = tarfile.TarInfo(name="mi-proyecto/tasks.txt")
        info2.size = len(tasks_data)
        tf.addfile(info2, io.BytesIO(tasks_data))

    return buf.getvalue()


# ---------------------------------------------------------------------------
# HTML principal
# ---------------------------------------------------------------------------
_INDEX_HTML = """<!doctype html>
<html lang="es">
<head><meta charset="utf-8"><title>TaskFlow</title>
<style>
body{font-family:'Segoe UI',sans-serif;background:#f0f2f5;margin:0}
.nav{background:#1e3a5f;color:white;padding:1rem 2rem;display:flex;align-items:center;gap:1rem}
.nav h1{margin:0;font-size:1.5rem}
.nav a{color:#90caf9;text-decoration:none;font-size:.9rem}
.nav a:hover{color:white}
.container{max-width:960px;margin:2rem auto;padding:0 1rem}
.card{background:white;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.1);padding:1.5rem;margin-bottom:1.5rem}
h2{color:#1e3a5f;margin-top:0}
.btn{display:inline-block;background:#1565c0;color:white;padding:.7rem 1.4rem;border:none;border-radius:5px;cursor:pointer;text-decoration:none;font-size:.95rem}
.btn:hover{background:#1976d2}
.btn-secondary{background:#546e7a}
.btn-secondary:hover{background:#607d8b}
input[type=file]{display:block;margin:.5rem 0;padding:.5rem;border:2px dashed #90a4ae;border-radius:4px;width:100%;box-sizing:border-box}
pre{background:#263238;color:#cfd8dc;padding:1rem;border-radius:4px;overflow-x:auto;font-size:.85rem}
.result{margin-top:1rem}
.ok{color:#2e7d32;font-weight:bold}
.err{color:#c62828;font-weight:bold}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
.feature{background:#e3f2fd;padding:1rem;border-radius:6px;border-left:4px solid #1565c0}
.warn{background:#fff3e0;border-left:4px solid #f57c00;padding:.8rem;border-radius:4px;margin:.5rem 0}
</style>
</head>
<body>
<div class="nav">
  <h1>TaskFlow v2.3</h1>
  <a href="/">Inicio</a>
  <a href="/export">Exportar ejemplo</a>
  <a href="/source">Ver código fuente</a>
  <span style="margin-left:auto;color:#90caf9">Gestor de proyectos empresarial</span>
</div>
<div class="container">
  <div class="card">
    <h2>Importar Proyecto</h2>
    <p>Importa un backup de proyecto desde un archivo <code>.tar.gz</code>. El archivo debe contener un <code>__metadata__.pkl</code> con los datos del proyecto.</p>
    <form method="POST" action="/upload" enctype="multipart/form-data">
      <input type="file" name="backup" accept=".tar.gz,.tgz">
      <br>
      <button type="submit" class="btn">Importar Backup</button>
      <a href="/export" class="btn btn-secondary" style="margin-left:.5rem">Descargar Ejemplo</a>
    </form>
    <div class="warn">&#9888; El sistema valida la clave de importación en los metadatos para garantizar backups auténticos.</div>
  </div>

  <div class="card">
    <h2>Formato del Backup</h2>
    <p>Estructura esperada del <code>.tar.gz</code>:</p>
    <pre>mi-proyecto/
&#9500;&#9472;&#9472; __metadata__.pkl    &#8592; metadatos serializados (requerido)
&#9500;&#9472;&#9472; tasks.txt
&#9492;&#9472;&#9472; config.json</pre>
    <p>El archivo <code>__metadata__.pkl</code> debe ser un objeto <code>TaskMetadata</code> serializado con pickle protocol 2.</p>
    <p>La clave <code>import_key</code> en los metadatos debe coincidir con la clave del servidor.</p>
  </div>

  <div class="card">
    <div class="grid">
      <div class="feature">
        <strong>Exportar Proyectos</strong><br>Descarga tus proyectos como backups portables
      </div>
      <div class="feature">
        <strong>Importar Backups</strong><br>Restaura proyectos desde archivos de backup
      </div>
    </div>
  </div>
</div>
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
                    headers=dict(request.headers), body=body[:200])
    except Exception:
        pass


@app.get("/")
def index():
    return _INDEX_HTML, 200, {"Content-Type": "text/html; charset=utf-8"}


@app.get("/health")
def health():
    return jsonify({"status": "ok", "version": "2.3"})


@app.get("/export")
def export_backup():
    """Descarga un backup de ejemplo para que los jugadores entiendan el formato."""
    backup_data = _build_sample_backup()
    return Response(
        backup_data,
        mimetype="application/gzip",
        headers={"Content-Disposition": "attachment; filename=taskflow-backup-sample.tar.gz"}
    )


@app.get("/source")
def view_source():
    """Expone el código fuente del servidor (intencional — parte del puzzle)."""
    try:
        with open(__file__, "r", encoding="utf-8") as f:
            src = f.read()
    except OSError:
        src = "# No disponible"
    return src, 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.post("/upload")
def upload():
    """Importa un backup .tar.gz. Extrae y deserializa __metadata__.pkl."""
    src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if src_ip and "," in src_ip:
        src_ip = src_ip.split(",")[0].strip()

    if "backup" not in request.files:
        return jsonify({"error": "Campo 'backup' requerido (multipart/form-data)"}), 400

    file = request.files["backup"]
    if not file.filename:
        return jsonify({"error": "Archivo vacío"}), 400

    fname = file.filename.lower()
    if not (fname.endswith(".tar.gz") or fname.endswith(".tgz")):
        return jsonify({"error": "Solo se aceptan archivos .tar.gz"}), 400

    archive_bytes = file.read()
    if len(archive_bytes) > 10 * 1024 * 1024:  # 10 MB
        return jsonify({"error": "Archivo demasiado grande (máx 10 MB)"}), 413

    obj, err = _extract_metadata(archive_bytes)

    if err:
        emit("import_error", "info", src_ip=src_ip, detail={"error": err, "filename": file.filename})
        return jsonify({"error": f"Error al importar: {err}"}), 400

    # Validar tipo
    if not isinstance(obj, TaskMetadata):
        emit("invalid_metadata_type", "warn", src_ip=src_ip,
             detail={"type": type(obj).__name__, "filename": file.filename})
        return jsonify({
            "error": "Los metadatos no son una instancia válida de TaskMetadata",
            "received_type": type(obj).__name__,
            "hint": "El archivo __metadata__.pkl debe serializar un objeto TaskMetadata",
        }), 400

    # Validar clave de importación
    provided_key = getattr(obj, "import_key", "")
    if provided_key != SERVER_IMPORT_KEY:
        emit("invalid_import_key", "warn", src_ip=src_ip,
             detail={"provided": provided_key[:16], "filename": file.filename})
        return jsonify({
            "error": "Clave de importación inválida",
            "detail": "import_key no coincide con la clave del servidor",
            "hint": "La clave está derivable del código fuente (/source)",
        }), 403

    # Importación exitosa con clave correcta
    emit("challenge_solved", "alert", src_ip=src_ip,
         detail={"vuln": "pickle-deserialization-tar-bypass",
                 "project": getattr(obj, "project_name", "")[:50]})

    return jsonify({
        "status": "ok",
        "imported": True,
        "project": {
            "name": getattr(obj, "project_name", ""),
            "version": getattr(obj, "version", ""),
            "task_count": getattr(obj, "task_count", 0),
        },
        "message": "Proyecto importado correctamente. Acceso a datos confidenciales concedido.",
        "flag": FLAG,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True)
