"""DocManager SOAP API — web-docmanager (Web INSANE) · "XXE en SOAP".

Vulnerabilidad: XXE (XML External Entity Injection) en endpoint SOAP.

El parser lxml tiene DTD processing habilitado. Inyectando una DOCTYPE
con una entidad externa que apunta a file:///flag.txt, el valor de la
entidad se resuelve y se inyecta en el campo filename del documento.

El endpoint real está en /ws/document/v2/upload (no en la ruta "obvia").
Requiere cabecera X-Api-Signature: HMAC-SHA256(body, SIGNING_KEY).
La clave de firma está expuesta en /static/sdk/docmanager-client.py.

Payload XXE:
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag.txt">]>
  <soapenv:Envelope ...>
    <soapenv:Body>
      <doc:UploadDocument>
        <doc:filename>&xxe;</doc:filename>
        ...
      </doc:UploadDocument>
    </soapenv:Body>
  </soapenv:Envelope>
"""
import hashlib
import hmac
import os

from flask import Flask, jsonify, request
from lxml import etree

from siem import emit
from reqlog import reqlog_http

app = Flask(__name__)

FLAG = os.environ.get("FLAG", "flag{EJEMPLO_LOCAL}")

# Escribir flag a disco
try:
    with open("/flag.txt", "w") as _fh:
        _fh.write(FLAG)
except OSError:
    pass

# Clave de firma — expuesta en /static/sdk/docmanager-client.py
# Los jugadores deben leerla del SDK público y derivar la firma HMAC
SIGNING_KEY = b"DocMgr-2024-K3y-Pr0d"

# Namespaces SOAP
NS_SOAPENV = "http://schemas.xmlsoap.org/soap/envelope/"
NS_DOC = "http://docmanager.internal/v2"


def _compute_sig(body: bytes) -> str:
    return hmac.new(SIGNING_KEY, body, hashlib.sha256).hexdigest()


def _parse_soap_upload(xml_body: bytes) -> dict:
    """Parsea el XML SOAP con lxml (DTD processing habilitado — XXE intencional)."""
    parser = etree.XMLParser(
        load_dtd=True,          # Carga DTDs — permite !DOCTYPE
        no_network=False,       # Permite entidades de red y de archivo
        resolve_entities=True,  # Resuelve entidades externas — XXE habilitado
        huge_tree=True,
    )
    try:
        root = etree.fromstring(xml_body, parser=parser)
    except etree.XMLSyntaxError as e:
        raise ValueError(f"XML inválido: {e}") from e

    # Extraer datos del body SOAP
    body_el = root.find(f"{{{NS_SOAPENV}}}Body")
    if body_el is None:
        raise ValueError("Falta soapenv:Body")

    upload_el = body_el.find(f"{{{NS_DOC}}}UploadDocument")
    if upload_el is None:
        raise ValueError("Falta doc:UploadDocument en el Body")

    def _text(el, tag):
        child = el.find(f"{{{NS_DOC}}}{tag}")
        return child.text if child is not None and child.text else ""

    metadata_el = upload_el.find(f"{{{NS_DOC}}}metadata")
    author = ""
    department = ""
    if metadata_el is not None:
        author = _text(metadata_el, "author")
        department = _text(metadata_el, "department")

    return {
        "filename": _text(upload_el, "filename"),
        "content_type": _text(upload_el, "content_type"),
        "author": author,
        "department": department,
    }


# ---------------------------------------------------------------------------
# HTML de la UI principal
# ---------------------------------------------------------------------------
_INDEX_HTML = """<!doctype html>
<html lang="es">
<head><meta charset="utf-8"><title>DocManager v2.4</title>
<style>
body{font-family:Arial,sans-serif;margin:0;background:#f5f5f5}
.top{background:#2c3e50;color:white;padding:1rem 2rem}
.top h1{margin:0;font-size:1.5rem}
.container{max-width:960px;margin:2rem auto;padding:0 1rem}
.card{background:white;border-radius:6px;box-shadow:0 1px 4px rgba(0,0,0,.15);padding:1.5rem;margin-bottom:1.5rem}
h2{color:#2c3e50;margin-top:0}
code{background:#f0f0f0;padding:2px 5px;border-radius:3px;font-size:.9rem}
a{color:#2980b9}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
.feature{background:#ecf0f1;padding:1rem;border-radius:4px}
.badge{display:inline-block;background:#e74c3c;color:white;padding:.2rem .6rem;border-radius:3px;font-size:.75rem}
</style>
</head>
<body>
<div class="top"><h1>DocManager v2.4 <span class="badge">ENTERPRISE</span></h1></div>
<div class="container">
  <div class="card">
    <h2>Bienvenido al Sistema de Gestión Documental</h2>
    <p>DocManager procesa, indexa y almacena documentos corporativos de forma segura.</p>
    <div class="grid">
      <div class="feature"><strong>API SOAP v2</strong><br>Integración con sistemas legacy via protocolo SOAP/XML</div>
      <div class="feature"><strong>Soporte Multi-formato</strong><br>PDF, DOCX, XML, TXT y más de 40 formatos</div>
      <div class="feature"><strong>Auditoría Completa</strong><br>Log de todos los accesos y operaciones</div>
      <div class="feature"><strong>SDK Cliente</strong><br>Biblioteca Python para integración rápida</div>
    </div>
  </div>
  <div class="card">
    <h2>Recursos para Desarrolladores</h2>
    <ul>
      <li><a href="/api/docs">Documentación de la API REST</a></li>
      <li><a href="/static/sdk/docmanager-client.py">SDK Python (docmanager-client.py)</a></li>
      <li><a href="/static/wsdl/docmanager.wsdl">WSDL del servicio SOAP</a></li>
    </ul>
  </div>
  <div class="card">
    <h2>Estado del Sistema</h2>
    <p>Servicio: <strong style="color:#27ae60">Operativo</strong></p>
    <p>Versión API: <code>2.4.1</code></p>
    <p><a href="/health">Health check</a></p>
  </div>
</div>
</body>
</html>"""

_API_DOCS = """{
  "api_version": "2.4",
  "endpoints": {
    "POST /soap/upload": {
      "description": "DEPRECATED — Endpoint SOAP legacy (solo para compatibilidad v1)",
      "status": "deprecated",
      "note": "Usar /ws/document/v2/upload para nuevas integraciones"
    },
    "GET /api/documents": {
      "description": "Lista documentos indexados",
      "auth": "Bearer token"
    },
    "GET /health": {
      "description": "Health check del servicio"
    }
  },
  "soap_service": {
    "wsdl": "/static/wsdl/docmanager.wsdl",
    "note": "Ver WSDL para endpoint y operaciones actualizadas"
  }
}"""

_SDK_PY = '''#!/usr/bin/env python3
"""DocManager Client SDK v2.4 — Python.

Ejemplo de integración con la API SOAP de DocManager.

Uso:
    client = DocManagerClient("http://docmanager.internal")
    client.upload_document("report.pdf", "application/pdf",
                           author="John Doe", department="Finance")
"""
import hashlib
import hmac

import urllib.request
import urllib.error


# Clave de firma para el entorno de producción.
# ⚠ Esta clave es específica del entorno — no compartir fuera de la organización.
_SIGNING_KEY = b"DocMgr-2024-K3y-Pr0d"

# Endpoint del servicio SOAP v2
SOAP_ENDPOINT = "/ws/document/v2/upload"

# Namespace del servicio
SOAP_NAMESPACE = "http://docmanager.internal/v2"


def _sign_request(body: bytes) -> str:
    """Calcula la firma HMAC-SHA256 del body del request."""
    return hmac.new(_SIGNING_KEY, body, hashlib.sha256).hexdigest()


def _build_soap_envelope(filename: str, content_type: str,
                          author: str = "", department: str = "") -> bytes:
    """Construye el envelope SOAP para subir un documento."""
    body = f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope
    xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:doc="{SOAP_NAMESPACE}">
  <soapenv:Header>
    <doc:Auth>
      <doc:ApiVersion>2.4</doc:ApiVersion>
    </doc:Auth>
  </soapenv:Header>
  <soapenv:Body>
    <doc:UploadDocument>
      <doc:filename>{filename}</doc:filename>
      <doc:content_type>{content_type}</doc:content_type>
      <doc:metadata>
        <doc:author>{author}</doc:author>
        <doc:department>{department}</doc:department>
      </doc:metadata>
    </doc:UploadDocument>
  </soapenv:Body>
</soapenv:Envelope>""".encode("utf-8")
    return body


class DocManagerClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def upload_document(self, filename: str, content_type: str,
                        author: str = "", department: str = "") -> dict:
        body = _build_soap_envelope(filename, content_type, author, department)
        sig = _sign_request(body)
        req = urllib.request.Request(
            f"{self.base_url}{SOAP_ENDPOINT}",
            data=body,
            headers={
                "Content-Type": "text/xml; charset=utf-8",
                "SOAPAction": "UploadDocument",
                "X-Api-Signature": sig,
            },
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            import json
            return json.loads(resp.read())


if __name__ == "__main__":
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
    client = DocManagerClient(host)
    result = client.upload_document("test.pdf", "application/pdf",
                                    author="Test User", department="IT")
    print(result)
'''

_WSDL = """<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
             xmlns:tns="http://docmanager.internal/v2"
             xmlns:xsd="http://www.w3.org/2001/XMLSchema"
             name="DocManagerService"
             targetNamespace="http://docmanager.internal/v2">

  <types>
    <xsd:schema targetNamespace="http://docmanager.internal/v2">
      <xsd:element name="UploadDocument">
        <xsd:complexType>
          <xsd:sequence>
            <xsd:element name="filename" type="xsd:string"/>
            <xsd:element name="content_type" type="xsd:string"/>
            <xsd:element name="metadata" type="tns:MetadataType"/>
          </xsd:sequence>
        </xsd:complexType>
      </xsd:element>
      <xsd:complexType name="MetadataType">
        <xsd:sequence>
          <xsd:element name="author" type="xsd:string"/>
          <xsd:element name="department" type="xsd:string"/>
        </xsd:sequence>
      </xsd:complexType>
    </xsd:schema>
  </types>

  <message name="UploadDocumentRequest">
    <part name="parameters" element="tns:UploadDocument"/>
  </message>

  <portType name="DocManagerPortType">
    <operation name="UploadDocument">
      <input message="tns:UploadDocumentRequest"/>
    </operation>
  </portType>

  <binding name="DocManagerSOAPBinding" type="tns:DocManagerPortType">
    <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
    <operation name="UploadDocument">
      <soap:operation soapAction="UploadDocument"/>
      <input><soap:body use="literal"/></input>
    </operation>
  </binding>

  <service name="DocManagerService">
    <port name="DocManagerSOAPPort" binding="tns:DocManagerSOAPBinding">
      <soap:address location="/ws/document/v2/upload"/>
    </port>
  </service>
</definitions>"""


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
    return _INDEX_HTML, 200, {"Content-Type": "text/html; charset=utf-8"}


@app.get("/health")
def health():
    return jsonify({"status": "ok", "version": "2.4.1", "soap_api": "active"})


@app.get("/api/docs")
def api_docs():
    return _API_DOCS, 200, {"Content-Type": "application/json"}


@app.get("/static/sdk/docmanager-client.py")
def sdk():
    return _SDK_PY, 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.get("/static/wsdl/docmanager.wsdl")
def wsdl():
    return _WSDL, 200, {"Content-Type": "text/xml; charset=utf-8"}


@app.post("/soap/upload")
def soap_upload_legacy():
    """Endpoint SOAP legacy — responde con error de deprecación."""
    return jsonify({
        "error": "DEPRECATED",
        "message": "Este endpoint está deprecado desde v2.0",
        "migration": "Usar POST /ws/document/v2/upload con SOAP v2",
    }), 410


@app.post("/ws/document/v2/upload")
def soap_upload_v2():
    """Endpoint SOAP v2 — vulnerable a XXE (DTD processing habilitado)."""
    src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if src_ip and "," in src_ip:
        src_ip = src_ip.split(",")[0].strip()

    # Validar Content-Type
    ct = request.content_type or ""
    if "xml" not in ct.lower():
        return jsonify({"error": "Content-Type debe ser text/xml o application/xml"}), 415

    # Validar firma HMAC
    sig_header = request.headers.get("X-Api-Signature", "")
    body_raw = request.get_data()
    expected_sig = _compute_sig(body_raw)

    if not sig_header:
        emit("missing_signature", "info", src_ip=src_ip,
             detail={"path": "/ws/document/v2/upload"})
        return jsonify({
            "error": "Firma requerida",
            "detail": "Cabecera X-Api-Signature ausente",
            "hint": "Ver /static/sdk/docmanager-client.py para calcular la firma",
        }), 401

    if not hmac.compare_digest(sig_header.lower(), expected_sig.lower()):
        emit("invalid_signature", "warn", src_ip=src_ip,
             detail={"provided": sig_header[:16] + "...", "expected": expected_sig[:16] + "..."})
        return jsonify({"error": "Firma inválida"}), 401

    # Parsear SOAP (XXE habilitado)
    try:
        doc_info = _parse_soap_upload(body_raw)
    except ValueError as e:
        emit("xml_parse_error", "info", src_ip=src_ip, detail={"error": str(e)})
        return jsonify({"error": f"Error XML: {e}"}), 400

    filename = doc_info.get("filename", "")

    # Detectar si el filename contiene la flag (XXE exitoso)
    if FLAG in filename and FLAG != "flag{EJEMPLO_LOCAL}":
        emit("challenge_solved", "alert", src_ip=src_ip,
             detail={"vuln": "xxe-soap-file-read", "filename": filename[:100]})

    # Detectar intentos XXE (para SIEM)
    if "flag" in filename.lower() or "etc/passwd" in filename.lower() or "\n" in filename:
        emit("xxe_attempt", "warn", src_ip=src_ip,
             detail={"filename": filename[:200]})

    import hashlib as _hl
    import time
    doc_id = _hl.md5(f"{filename}{time.time()}".encode()).hexdigest()[:12]

    return jsonify({
        "status": "ok",
        "document_id": doc_id,
        "indexed": True,
        "metadata": {
            "filename": filename,
            "content_type": doc_info.get("content_type", ""),
            "author": doc_info.get("author", ""),
            "department": doc_info.get("department", ""),
        },
        "message": f"Documento '{filename}' indexado correctamente",
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True)
