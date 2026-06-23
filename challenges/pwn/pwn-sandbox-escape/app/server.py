#!/usr/bin/env python3
"""
pwn-sandbox-escape — Python eval() sandbox

El sandbox:
  - globals: {'__builtins__': None} + whitelist de nombres seguros
  - Filtra expresiones que contengan '__' literalmente
  - Bloquea: import, open, os, sys, exec, eval, compile, breakpoint

Escape: usar chr(95)+chr(95) para construir '__' en tiempo de ejecución,
luego recorrer la cadena de subclases de object para encontrar clases útiles
como _io.FileIO, subprocess.Popen, etc.

Ejemplo de escape:
  getattr(
    [c for c in ().__class__.mro()[1].__subclasses__() if 'FileIO' in str(c)][0],
    'read'
  )  ← no funciona directo por el filtro de __

  Pero con chr():
  getattr(
    getattr((), chr(95)*2+'class'+chr(95)*2)
      .mro()[1]
      .__subclasses__()[X],   ← aún tiene __ → usar getattr dinámico
    'read'
  )
"""
import os
import sys
import socket
import socketserver
import signal

FLAG = os.environ.get('FLAG', 'HL4{EJEMPLO_LOCAL}')

# Lista negra de palabras prohibidas en la expresión del usuario
BLOCKED_STRINGS = [
    '__',          # dunder directo
    'import',      # import statement
    'open(',       # open()
    ' os',         # módulo os
    ' sys',        # módulo sys
    'exec(',       # exec()
    'eval(',       # eval()
    'compile(',    # compile()
    'breakpoint',  # breakpoint()
    'flag',        # no directamente
    '/etc',        # no acceso al sistema
    '/root',       # no acceso a root
]

# Globals permitidos en el sandbox: solo tipos básicos y chr/ord/len/range
SAFE_GLOBALS = {
    '__builtins__': None,
    'True': True,
    'False': False,
    'None': None,
    'chr': chr,
    'ord': ord,
    'len': len,
    'range': range,
    'str': str,
    'int': int,
    'list': list,
    'tuple': tuple,
    'dict': dict,
    'set': set,
    'bytes': bytes,
    'bytearray': bytearray,
    'getattr': getattr,
    'hasattr': hasattr,
    'type': type,
    'isinstance': isinstance,
    'issubclass': issubclass,
    'print': print,
    'repr': repr,
    'id': id,
    'dir': dir,
}

BANNER = b"""
===========================================================
  Python Eval Sandbox v1.0 — "Totally Secure" Edition
===========================================================
Rules:
  - No '__' in your expression
  - No: import, open, os, sys, exec, eval, compile
  - Builtins are restricted to a safe subset
  - You have chr(), ord(), len(), range(), getattr()...
  - ...and the full Python object model (if you can reach it)

Goal: read /home/ctf/flag.txt
===========================================================
"""

MAX_ATTEMPTS = 30
TIMEOUT_SECS = 120


class SandboxHandler(socketserver.StreamRequestHandler):

    def _send(self, msg: str):
        self.wfile.write((msg + '\n').encode())

    def _blocked(self, expr: str) -> bool:
        for word in BLOCKED_STRINGS:
            if word in expr:
                return True
        return False

    def handle(self):
        signal.alarm(TIMEOUT_SECS)
        self.wfile.write(BANNER)

        for attempt in range(MAX_ATTEMPTS):
            self.wfile.write(f'[{attempt+1}/{MAX_ATTEMPTS}] >>> '.encode())
            try:
                line = self.rfile.readline()
            except Exception:
                return
            if not line:
                return

            expr = line.strip().decode(errors='replace')
            if not expr:
                continue

            # Comprobación del filtro
            if self._blocked(expr):
                self._send('BLOCKED: forbidden pattern detected')
                continue

            # Evaluar en sandbox
            try:
                result = eval(expr, SAFE_GLOBALS.copy(), {})  # noqa: S307
                self._send(f'=> {repr(result)}')
            except Exception as exc:
                self._send(f'Error: {exc}')

        self._send('Max attempts reached. Goodbye.')


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True
    timeout = 1


def main():
    # Escribir flag en el sistema de archivos (para que el escape la lea)
    os.makedirs('/home/ctf', exist_ok=True)
    with open('/home/ctf/flag.txt', 'w') as fh:
        fh.write(FLAG + '\n')
    os.chmod('/home/ctf/flag.txt', 0o444)

    signal.signal(signal.SIGALRM, lambda *_: sys.exit(0))

    with ReusableTCPServer(('0.0.0.0', 9998), SandboxHandler) as srv:
        print('[*] Sandbox listening on :9998', flush=True)
        srv.serve_forever()


if __name__ == '__main__':
    main()
