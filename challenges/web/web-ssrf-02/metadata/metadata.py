"""Metadata interno simulado — web-ssrf-02.

Emula el endpoint de metadata de un proveedor cloud (estilo
http://169.254.169.254/latest/meta-data/). NO está publicado al host: vive solo
en la red del equipo (172.30.N.13). Solo es alcanzable vía el SSRF de PixelForge.

Árbol servido:
  GET /                                                  -> banner
  GET /latest/meta-data/                                 -> índice de claves
  GET /latest/meta-data/instance-id                      -> id de la instancia
  GET /latest/meta-data/iam/                             -> índice iam
  GET /latest/meta-data/iam/security-credentials/        -> nombre del rol
  GET /latest/meta-data/iam/security-credentials/<rol>   -> credenciales (FLAG en "Token")

La credencial sensible (con la FLAG) SOLO se entrega a peticiones "internas":
las que llegan con el User-Agent del fetcher de PixelForge (PixelForge-Fetcher).
Un navegador normal recibe 403 — refuerza que hay que pasar POR el SSRF.

La FLAG se inyecta por equipo vía env FLAG. NO hardcodeada.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FLAG = os.environ.get("FLAG", "HL4{EJEMPLO_LOCAL}")
PORT = int(os.environ.get("PORT", "8080"))
ROLE = "pixelforge-node-role"
INTERNAL_UA_MARK = "PixelForge-Fetcher"

BASE = "/latest/meta-data/"


class Handler(BaseHTTPRequestHandler):
    server_version = "EC2ws"  # se hace pasar por metadata service
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # silencioso
        pass

    def _send(self, code: int, body: str, ctype: str = "text/plain"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Server", self.server_version)
        self.end_headers()
        self.wfile.write(data)

    def _is_internal(self) -> bool:
        return INTERNAL_UA_MARK in self.headers.get("User-Agent", "")

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path in ("/", ""):
            return self._send(200, "metadata service\nver: latest\n")

        if path == BASE or path == BASE.rstrip("/"):
            return self._send(200, "instance-id\niam/\nlocal-ipv4\nplacement/\n")

        if path == BASE + "instance-id":
            return self._send(200, "i-0pixelforge0node00")

        if path == BASE + "local-ipv4":
            return self._send(200, "172.30.99.13")

        if path in (BASE + "iam/", BASE + "iam"):
            return self._send(200, "security-credentials/\n")

        if path in (BASE + "iam/security-credentials/", BASE + "iam/security-credentials"):
            # Devuelve el NOMBRE del rol. Esto sí es enumerable por cualquiera.
            return self._send(200, ROLE + "\n")

        if path == BASE + "iam/security-credentials/" + ROLE:
            # La joya. Solo para peticiones internas (las del fetcher).
            if not self._is_internal():
                return self._send(403, "Forbidden: credentials are node-internal only\n")
            creds = {
                "Code": "Success",
                "Type": "AWS-HMAC",
                "AccessKeyId": "ASIAPIXELFORGE0NODE",
                "SecretAccessKey": "do-not-log-this",
                "Token": FLAG,
                "Expiration": "2030-01-01T00:00:00Z",
            }
            return self._send(200, json.dumps(creds, indent=2), "application/json")

        self._send(404, "Not Found\n")


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[*] metadata service en 0.0.0.0:{PORT}", flush=True)
    srv.serve_forever()
